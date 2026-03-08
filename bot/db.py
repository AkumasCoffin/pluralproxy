"""
Shared module — encrypted PostgreSQL storage + JWT helpers.

Provides AES-256-GCM encryption at rest inside a PostgreSQL database.
Every CGI script imports from here instead of duplicating logic.

**All user-submitted content is encrypted at rest** — per-column AES-256-GCM.
Alters are stored as normalised rows (one per alter) with individually encrypted
field values.  Relationships are still stored as encrypted JSON blobs.

Schema overview (3NF-normalized, encrypted at rest)
────────────────────────────────────────────────────
  users                        — one row per Clerk user (display name encrypted)
  user_discord_settings        — 1:1 Discord link + proxy settings (split from users)
  user_profiles                — wide table: one row per user, one column-pair per field (encrypted)
  alters                       — wide table: one row per alter, one column-pair per field (encrypted)
  user_data                    — encrypted JSON blobs (relationships only)
  user_data_backups            — automatic version history (last N per user+type)
  shares                       — view-only share links (label encrypted)
  share_alters                 — which alter UUIDs are in each share
  share_alter_hidden_groups    — per-alter hidden groups
  discord_proxies              — alter proxy triggers (prefix/suffix encrypted)
  fronting                     — currently fronting alters per user
  share_claims                 — who claimed which share
  link_codes                   — legacy table (kept for compat)
  friend_requests              — pending/resolved friend requests (message encrypted)
  friendships                  — bidirectional friend pairs
  friend_shares                — which alters are shared with a friend
  friend_share_hidden_groups   — per-alter hidden groups for friend shares
  fronting_shares              — share fronting status with a friend
  fronting_share_hidden_groups — hidden groups for fronting shares
  journal_entries              — per-alter encrypted journal (title+body encrypted)
  journal_tags                 — per-user encrypted tag names
  journal_entry_tags           — junction: entries ↔ tags

Discord linking: uses Clerk's Discord SSO connection.  The backend calls
  the Clerk Backend API (CLERK_SECRET_KEY in .env) to verify the user's
  Discord external account, then stores the Discord ID in user_discord_settings.
  Falls back to frontend-provided ID if the secret key isn't configured.

Encryption key: DATA_ENCRYPTION_KEY in .env (base64-encoded 32 bytes).
"""

import base64
import json
import os
import secrets
import uuid as _uuid_mod
import psycopg
from psycopg.rows import dict_row
import string
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
#  Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent          # bot/
PROJECT_DIR = SCRIPT_DIR.parent                        # /var/www/plural-proxy/
DATA_DIR = PROJECT_DIR / "data"
ENV_FILE = PROJECT_DIR / ".env"
CLERK_PK_FALLBACK = "pk_live_Y2xlcmsucGx1cmFscHJveHkuZm9yY2VxdWl0Lnh5eiQ"

MAX_BACKUPS_PER_USER = 3   # per (user_id, data_type)
SHARE_CODE_LENGTH = 12     # URL-safe share codes
LINK_CODE_LENGTH = 6       # short alphanumeric code for Discord linking
LINK_CODE_TTL_MINUTES = 10 # link codes expire after this

# ---------------------------------------------------------------------------
#  Load .env
# ---------------------------------------------------------------------------

def load_dotenv(path=None):
    path = path or ENV_FILE
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_dotenv()

# PostgreSQL connection parameters (now loaded from .env)
PG_HOST = os.environ.get("PG_HOST", "localhost")
PG_PORT = os.environ.get("PG_PORT", "5432")
PG_DATABASE = os.environ.get("PG_DATABASE", "did_tracker")
PG_USER = os.environ.get("PG_USER", "postgres")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "")

# ---------------------------------------------------------------------------
#  Encryption  (AES-256-GCM via cryptography library)
# ---------------------------------------------------------------------------

def _get_encryption_key() -> bytes:
    """Return the 32-byte AES-256 key from the environment."""
    raw = os.environ.get("DATA_ENCRYPTION_KEY", "")
    if not raw:
        raise RuntimeError(
            "DATA_ENCRYPTION_KEY not set in .env — "
            "run  sudo bash install.sh  or add it manually"
        )
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError(
            f"DATA_ENCRYPTION_KEY must be 32 bytes (got {len(key)})"
        )
    return key


def encrypt(plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM.
    Returns (nonce, ciphertext_with_tag).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _get_encryption_key()
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ct


def decrypt(nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    """Decrypt AES-256-GCM *ciphertext_with_tag* using *nonce*."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


# ── Per-field encryption helpers ──────────────────────────────────────

def _encrypt_field(value: str) -> tuple[bytes | None, bytes | None]:
    """Encrypt a single text field. Returns (nonce, cipher) or (None, None)."""
    if not value:
        return None, None
    return encrypt(value.encode("utf-8"))


def _decrypt_field(nonce: bytes | None, cipher: bytes | None) -> str:
    """Decrypt a single text field. Returns plaintext string or ''."""
    if not nonce or not cipher:
        return ""
    try:
        return decrypt(nonce, cipher).decode("utf-8")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
#  Field mappings — JSON ↔ column names for wide tables
# ---------------------------------------------------------------------------

# Each tuple: (group_name, json_field_name, column_prefix, group_order, field_order)
_ALTER_FIELD_MAP: list[tuple[str, str, str, int, int]] = [
    # ── Basic Info ──
    ("Basic Info", "Name", "name", 0, 0),
    ("Basic Info", "Nicknames/Aliases", "nicknames", 0, 1),
    ("Basic Info", "Age", "age", 0, 2),
    ("Basic Info", "Gender", "gender", 0, 3),
    ("Basic Info", "Sexuality", "sexuality", 0, 4),
    ("Basic Info", "Presentation", "presentation", 0, 5),
    ("Basic Info", "Dominant emotion", "dominant_emotion", 0, 6),
    # ── System Info ──
    ("System Info", "Role", "role", 1, 0),
    ("System Info", "Subsystem/Group", "subsystem", 1, 1),
    # ── Fronting & Switching ──
    ("Fronting & Switching", "Fronting frequency", "fronting_frequency", 2, 0),
    ("Fronting & Switching", "Fronting signs", "fronting_signs", 2, 1),
    ("Fronting & Switching", "Dissociation level", "dissociation_level", 2, 2),
    ("Fronting & Switching", "Handoffs", "handoffs", 2, 3),
    # ── Personality & Traits ──
    ("Personality & Traits", "Personality description", "personality_desc", 3, 0),
    ("Personality & Traits", "Strengths", "strengths", 3, 1),
    ("Personality & Traits", "Struggles", "struggles", 3, 2),
    ("Personality & Traits", "Fears", "fears", 3, 3),
    ("Personality & Traits", "Values", "f_values", 3, 4),
    ("Personality & Traits", "Humor style", "humor_style", 3, 5),
    ("Personality & Traits", "Love language / comfort style", "love_language", 3, 6),
    ("Personality & Traits", "Energy level", "energy_level", 3, 7),
    # ── Boundaries & Consent ──
    ("Boundaries & Consent", "Hard boundaries", "hard_boundaries", 4, 0),
    ("Boundaries & Consent", "Soft boundaries", "soft_boundaries", 4, 1),
    ("Boundaries & Consent", "Consent reminders", "consent_reminders", 4, 2),
    # ── Triggers & Warnings ──
    ("Triggers & Warnings", "Known triggers", "known_triggers", 5, 0),
    ("Triggers & Warnings", "Alter Triggers", "alter_triggers", 5, 1),
    ("Triggers & Warnings", "Common sensitivities", "common_sensitivities", 5, 2),
    ("Triggers & Warnings", "Early warning signs", "early_warning_signs", 5, 3),
    # ── Mental Health ──
    ("Mental Health", "Diagnosis/known conditions", "diagnosis", 6, 0),
    ("Mental Health", "Coping strategies", "coping_strategies", 6, 1),
    ("Mental Health", "Crisis plan", "crisis_plan", 6, 2),
    ("Mental Health", "Therapist notes", "therapist_notes", 6, 3),
    # ── Skills, Interests & Habits ──
    ("Skills, Interests & Habits", "Skills", "skills", 7, 0),
    ("Skills, Interests & Habits", "Special interests", "special_interests", 7, 1),
    ("Skills, Interests & Habits", "Likes", "likes", 7, 2),
    ("Skills, Interests & Habits", "Dislikes", "dislikes", 7, 3),
    ("Skills, Interests & Habits", "Comfort items", "comfort_items", 7, 4),
    ("Skills, Interests & Habits", "Food/drink preferences", "food_drink_prefs", 7, 5),
    ("Skills, Interests & Habits", "Music/aesthetic", "music_aesthetic", 7, 6),
    ("Skills, Interests & Habits", "Shows/games they like", "shows_games", 7, 7),
    # ── Relationships ──
    ("Relationships", "Closest alters", "closest_alters", 8, 0),
    ("Relationships", "Tension/conflict", "tension_conflict", 8, 1),
    ("Relationships", "Caretakers", "caretakers", 8, 2),
    ("Relationships", "External relationships", "external_rels", 8, 3),
    # ── Communication ──
    ("Communication", "Internal Communication", "internal_comm", 9, 0),
    ("Communication", "Communication Method", "comm_method", 9, 1),
    ("Communication", "Tone Use", "tone_use", 9, 2),
    # ── Notes ──
    ("Notes", "General notes", "general_notes", 10, 0),
    ("Notes", "Session notes", "session_notes", 10, 1),
    ("Notes", "Goals", "goals", 10, 2),
    ("Notes", "To-do / follow-up", "todo_followup", 10, 3),
    # ── Quick Summary ──
    ("Quick Summary", "1\u20133 sentence summary", "summary", 11, 0),
]

# Derived look-ups
_ALTER_JSON_TO_COL: dict[tuple[str, str], str] = {
    (g, f): col for g, f, col, _, _ in _ALTER_FIELD_MAP
}
_ALTER_COL_TO_JSON: dict[str, tuple[str, str, int, int]] = {
    col: (g, f, go, fo) for g, f, col, go, fo in _ALTER_FIELD_MAP
}
_ALTER_COL_PREFIXES: list[str] = [col for _, _, col, _, _ in _ALTER_FIELD_MAP]

# Profile fields: (json_key, column_prefix)
_PROFILE_FIELD_MAP: list[tuple[str, str]] = [
    ("Age", "age"),
    ("Pronouns", "pronouns"),
    ("Gender", "gender"),
    ("Sexuality", "sexuality"),
    ("Communication", "communication"),
    ("Personality", "personality"),
    ("Boundaries", "boundaries"),
    ("Triggers", "triggers"),
    ("Bio", "bio"),
]
_PROFILE_JSON_TO_COL: dict[str, str] = {j: c for j, c in _PROFILE_FIELD_MAP}
_PROFILE_COL_TO_JSON: dict[str, str] = {c: j for j, c in _PROFILE_FIELD_MAP}


# ---------------------------------------------------------------------------
#  Database  — 3NF-normalized schema + connection (encrypted at rest)
# ---------------------------------------------------------------------------

_SCHEMA_TABLES = """
-- ── Core ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,                -- Clerk user ID
    name_nonce   BYTEA,                            -- encrypted display name
    name_cipher  BYTEA,
    avatar_url   TEXT    DEFAULT '',               -- Clerk / uploaded avatar
    friend_code  TEXT,                             -- unique friend code
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);

-- Discord settings split out (3NF: only exist when discord is linked)
CREATE TABLE IF NOT EXISTS user_discord_settings (
    user_id           TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    discord_id        TEXT UNIQUE,                  -- linked Discord snowflake
    proxy_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    autoproxy_enabled BOOLEAN NOT NULL DEFAULT FALSE
);

-- User profile fields (one row per user, values encrypted at rest)
CREATE TABLE IF NOT EXISTS user_profiles (
    user_id          TEXT PRIMARY KEY
                          REFERENCES users(user_id) ON DELETE CASCADE,
    age_nonce        BYTEA, age_cipher        BYTEA,
    pronouns_nonce   BYTEA, pronouns_cipher   BYTEA,
    gender_nonce     BYTEA, gender_cipher     BYTEA,
    sexuality_nonce  BYTEA, sexuality_cipher  BYTEA,
    communication_nonce BYTEA, communication_cipher BYTEA,
    personality_nonce BYTEA, personality_cipher BYTEA,
    boundaries_nonce BYTEA, boundaries_cipher BYTEA,
    triggers_nonce   BYTEA, triggers_cipher   BYTEA,
    bio_nonce        BYTEA, bio_cipher        BYTEA
);

-- ── Alters (one row per alter, field values encrypted) ────────────────

CREATE TABLE IF NOT EXISTS alters (
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    uuid        TEXT NOT NULL,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    image       TEXT DEFAULT '',
    card_color  TEXT DEFAULT '',
    avatar_icon TEXT DEFAULT '',
    -- Basic Info (encrypted)
    name_nonce BYTEA, name_cipher BYTEA,
    nicknames_nonce BYTEA, nicknames_cipher BYTEA,
    age_nonce BYTEA, age_cipher BYTEA,
    gender_nonce BYTEA, gender_cipher BYTEA,
    sexuality_nonce BYTEA, sexuality_cipher BYTEA,
    presentation_nonce BYTEA, presentation_cipher BYTEA,
    dominant_emotion_nonce BYTEA, dominant_emotion_cipher BYTEA,
    -- System Info
    role_nonce BYTEA, role_cipher BYTEA,
    subsystem_nonce BYTEA, subsystem_cipher BYTEA,
    -- Fronting & Switching
    fronting_frequency_nonce BYTEA, fronting_frequency_cipher BYTEA,
    fronting_signs_nonce BYTEA, fronting_signs_cipher BYTEA,
    dissociation_level_nonce BYTEA, dissociation_level_cipher BYTEA,
    handoffs_nonce BYTEA, handoffs_cipher BYTEA,
    -- Personality & Traits
    personality_desc_nonce BYTEA, personality_desc_cipher BYTEA,
    strengths_nonce BYTEA, strengths_cipher BYTEA,
    struggles_nonce BYTEA, struggles_cipher BYTEA,
    fears_nonce BYTEA, fears_cipher BYTEA,
    f_values_nonce BYTEA, f_values_cipher BYTEA,
    humor_style_nonce BYTEA, humor_style_cipher BYTEA,
    love_language_nonce BYTEA, love_language_cipher BYTEA,
    energy_level_nonce BYTEA, energy_level_cipher BYTEA,
    -- Boundaries & Consent
    hard_boundaries_nonce BYTEA, hard_boundaries_cipher BYTEA,
    soft_boundaries_nonce BYTEA, soft_boundaries_cipher BYTEA,
    consent_reminders_nonce BYTEA, consent_reminders_cipher BYTEA,
    -- Triggers & Warnings
    known_triggers_nonce BYTEA, known_triggers_cipher BYTEA,
    alter_triggers_nonce BYTEA, alter_triggers_cipher BYTEA,
    common_sensitivities_nonce BYTEA, common_sensitivities_cipher BYTEA,
    early_warning_signs_nonce BYTEA, early_warning_signs_cipher BYTEA,
    -- Mental Health
    diagnosis_nonce BYTEA, diagnosis_cipher BYTEA,
    coping_strategies_nonce BYTEA, coping_strategies_cipher BYTEA,
    crisis_plan_nonce BYTEA, crisis_plan_cipher BYTEA,
    therapist_notes_nonce BYTEA, therapist_notes_cipher BYTEA,
    -- Skills, Interests & Habits
    skills_nonce BYTEA, skills_cipher BYTEA,
    special_interests_nonce BYTEA, special_interests_cipher BYTEA,
    likes_nonce BYTEA, likes_cipher BYTEA,
    dislikes_nonce BYTEA, dislikes_cipher BYTEA,
    comfort_items_nonce BYTEA, comfort_items_cipher BYTEA,
    food_drink_prefs_nonce BYTEA, food_drink_prefs_cipher BYTEA,
    music_aesthetic_nonce BYTEA, music_aesthetic_cipher BYTEA,
    shows_games_nonce BYTEA, shows_games_cipher BYTEA,
    -- Relationships
    closest_alters_nonce BYTEA, closest_alters_cipher BYTEA,
    tension_conflict_nonce BYTEA, tension_conflict_cipher BYTEA,
    caretakers_nonce BYTEA, caretakers_cipher BYTEA,
    external_rels_nonce BYTEA, external_rels_cipher BYTEA,
    -- Communication
    internal_comm_nonce BYTEA, internal_comm_cipher BYTEA,
    comm_method_nonce BYTEA, comm_method_cipher BYTEA,
    tone_use_nonce BYTEA, tone_use_cipher BYTEA,
    -- Notes
    general_notes_nonce BYTEA, general_notes_cipher BYTEA,
    session_notes_nonce BYTEA, session_notes_cipher BYTEA,
    goals_nonce BYTEA, goals_cipher BYTEA,
    todo_followup_nonce BYTEA, todo_followup_cipher BYTEA,
    -- Quick Summary
    summary_nonce BYTEA, summary_cipher BYTEA,
    -- Timestamps
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, uuid)
);

-- Encrypted blobs (relationships only — alters use columns above)
CREATE TABLE IF NOT EXISTS user_data (
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    data_type  TEXT NOT NULL CHECK(data_type IN ('relationships')),
    nonce      BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, data_type)
);

CREATE TABLE IF NOT EXISTS user_data_backups (
    id         SERIAL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    data_type  TEXT    NOT NULL,
    nonce      BYTEA   NOT NULL,
    ciphertext BYTEA   NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- ── Sharing (view-only links) ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS shares (
    share_code   TEXT PRIMARY KEY,                 -- random URL-safe token
    owner_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    label_nonce  BYTEA,                             -- encrypted label
    label_cipher BYTEA,
    share_scope  TEXT NOT NULL DEFAULT 'selected'
                      CHECK(share_scope IN ('all','selected')),
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ,                       -- NULL = never expires
    is_active    BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS share_alters (
    share_code TEXT NOT NULL REFERENCES shares(share_code) ON DELETE CASCADE,
    alter_uuid TEXT NOT NULL,
    PRIMARY KEY (share_code, alter_uuid)
);

-- Per-alter hidden groups for shares
CREATE TABLE IF NOT EXISTS share_alter_hidden_groups (
    share_code TEXT NOT NULL,
    alter_uuid TEXT NOT NULL,
    group_name TEXT NOT NULL,
    PRIMARY KEY (share_code, alter_uuid, group_name),
    FOREIGN KEY (share_code, alter_uuid)
        REFERENCES share_alters(share_code, alter_uuid) ON DELETE CASCADE
);

-- ── Discord Bot ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS discord_proxies (
    id            SERIAL PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    alter_uuid    TEXT NOT NULL,
    prefix_nonce  BYTEA,                            -- encrypted prefix trigger
    prefix_cipher BYTEA,
    suffix_nonce  BYTEA,                            -- encrypted suffix trigger
    suffix_cipher BYTEA,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(user_id, alter_uuid)
);

-- ── Fronting ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS fronting (
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    alter_uuid TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'secondary'
                    CHECK(role IN ('primary','secondary')),
    set_at     TIMESTAMPTZ NOT NULL,
    set_via    TEXT NOT NULL DEFAULT 'site',
    PRIMARY KEY (user_id, alter_uuid)
);

-- ── Share claims (person-to-person sharing) ──────────────────────────

CREATE TABLE IF NOT EXISTS share_claims (
    share_code TEXT NOT NULL REFERENCES shares(share_code) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    claimed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (share_code, user_id)
);

-- ── Account linking codes ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS link_codes (
    code       TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- ── Friends ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS friend_requests (
    id          SERIAL PRIMARY KEY,
    from_user   TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    to_user     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    msg_nonce   BYTEA,                              -- encrypted message
    msg_cipher  BYTEA,
    status      TEXT NOT NULL DEFAULT 'pending'
                     CHECK(status IN ('pending','accepted','declined','cancelled')),
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    UNIQUE(from_user, to_user)
);

CREATE TABLE IF NOT EXISTS friendships (
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    friend_id   TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, friend_id)
);

CREATE TABLE IF NOT EXISTS friend_shares (
    user_id       TEXT NOT NULL,
    friend_id     TEXT NOT NULL,
    alter_uuid    TEXT NOT NULL,
    PRIMARY KEY (user_id, friend_id, alter_uuid),
    FOREIGN KEY (user_id, friend_id)
        REFERENCES friendships(user_id, friend_id) ON DELETE CASCADE
);

-- Per-alter hidden groups for friend shares
CREATE TABLE IF NOT EXISTS friend_share_hidden_groups (
    user_id    TEXT NOT NULL,
    friend_id  TEXT NOT NULL,
    alter_uuid TEXT NOT NULL,
    group_name TEXT NOT NULL,
    PRIMARY KEY (user_id, friend_id, alter_uuid, group_name),
    FOREIGN KEY (user_id, friend_id, alter_uuid)
        REFERENCES friend_shares(user_id, friend_id, alter_uuid) ON DELETE CASCADE
);

-- ── Fronting sharing ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS fronting_shares (
    user_id       TEXT NOT NULL,
    friend_id     TEXT NOT NULL,
    PRIMARY KEY (user_id, friend_id),
    FOREIGN KEY (user_id, friend_id)
        REFERENCES friendships(user_id, friend_id) ON DELETE CASCADE
);

-- Hidden groups for fronting shares
CREATE TABLE IF NOT EXISTS fronting_share_hidden_groups (
    user_id    TEXT NOT NULL,
    friend_id  TEXT NOT NULL,
    group_name TEXT NOT NULL,
    PRIMARY KEY (user_id, friend_id, group_name),
    FOREIGN KEY (user_id, friend_id)
        REFERENCES fronting_shares(user_id, friend_id) ON DELETE CASCADE
);

-- ── Journal ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS journal_entries (
    id           SERIAL PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    alter_uuid   TEXT    NOT NULL DEFAULT '',
    title_nonce  BYTEA,                             -- encrypted title
    title_cipher BYTEA,
    body_nonce   BYTEA,                             -- encrypted body
    body_cipher  BYTEA,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    via          TEXT    NOT NULL DEFAULT 'site'
);

-- Per-user encrypted tags (no plaintext tag names at rest)
CREATE TABLE IF NOT EXISTS journal_tags (
    id          SERIAL PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name_nonce  BYTEA NOT NULL,
    name_cipher BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS journal_entry_tags (
    entry_id INTEGER NOT NULL REFERENCES journal_entries(id) ON DELETE CASCADE,
    tag_id   INTEGER NOT NULL REFERENCES journal_tags(id) ON DELETE CASCADE,
    PRIMARY KEY (entry_id, tag_id)
);
"""

# Indexes are created AFTER migrations so that columns added by ALTER TABLE exist.
_SCHEMA_INDEXES = [
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_friend_code ON users(friend_code) WHERE friend_code IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_alters_user ON alters(user_id, sort_order)",
    "CREATE INDEX IF NOT EXISTS idx_backups_user ON user_data_backups(user_id, data_type, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_shares_owner ON shares(owner_id)",
    "CREATE INDEX IF NOT EXISTS idx_proxies_user ON discord_proxies(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_share_claims_user ON share_claims(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_link_codes_expiry ON link_codes(expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests(to_user, status)",
    "CREATE INDEX IF NOT EXISTS idx_friend_requests_from ON friend_requests(from_user, status)",
    "CREATE INDEX IF NOT EXISTS idx_friend_shares_friend ON friend_shares(friend_id)",
    "CREATE INDEX IF NOT EXISTS idx_journal_user ON journal_entries(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_journal_alter ON journal_entries(user_id, alter_uuid)",
    "CREATE INDEX IF NOT EXISTS idx_journal_tags_user ON journal_tags(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_journal_entry_tags_tag ON journal_entry_tags(tag_id)",
]


_schema_initialized = False


def _get_db() -> psycopg.Connection:
    """Open (and initialise if needed) the PostgreSQL database.

    Order of operations:
      1. Acquire advisory lock (prevents concurrent migration races)
      2. Create tables (IF NOT EXISTS — no-op for existing tables)
      3. Run migrations (add columns via ALTER TABLE, move/encrypt data)
      4. Create indexes (safe now — all columns exist after migrations)
      5. Release advisory lock

    Schema init only runs once per process (flagged by _schema_initialized).
    """
    global _schema_initialized
    conn = psycopg.connect(
        host=PG_HOST,
        port=int(PG_PORT),
        dbname=PG_DATABASE,
        user=PG_USER,
        password=PG_PASSWORD,
        row_factory=dict_row,
        connect_timeout=10,
    )
    if not _schema_initialized:
        try:
            # Advisory lock prevents multiple CGI processes from running
            # migrations concurrently (e.g. DROP TABLE + CREATE TABLE race).
            conn.execute("SELECT pg_advisory_lock(42)")
            _execute_schema(conn, _SCHEMA_TABLES)  # 1. tables only (no indexes)
            _upgrade_schema(conn)                   # 2. data migrations
            _ensure_indexes(conn)                   # 3. indexes (columns now exist)
            _schema_initialized = True
        except Exception as exc:
            conn.rollback()
            print(f"[db.py] Schema init error: {exc}", file=sys.stderr)
            # Still mark as initialized — the flag-based migrations are
            # idempotent and will retry on the next process.  Crashing
            # every request is worse than a partially-applied migration.
            _schema_initialized = True
        finally:
            try:
                conn.execute("SELECT pg_advisory_unlock(42)")
                conn.commit()
            except Exception:
                pass
    return conn


def _execute_schema(conn: psycopg.Connection, sql_script: str) -> None:
    """Execute a multi-statement DDL script by splitting on semicolons."""
    for stmt in sql_script.split(';'):
        # Remove comment-only lines and whitespace
        lines = []
        for line in stmt.split('\n'):
            stripped = line.strip()
            if stripped and not stripped.startswith('--'):
                lines.append(line)
        clean = '\n'.join(lines).strip()
        if clean:
            conn.execute(clean)
    conn.commit()


def _ensure_indexes(conn: psycopg.Connection) -> None:
    """Create all indexes.  Runs after migrations so every column exists."""
    for stmt in _SCHEMA_INDEXES:
        try:
            conn.execute(stmt)
            conn.commit()
        except Exception:
            conn.rollback()  # required in PG after error in transaction
    conn.commit()


def _get_columns(conn: psycopg.Connection, table_name: str) -> set[str]:
    """Return the set of column names for a table (PostgreSQL)."""
    rows = conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = %s AND table_schema = 'public'",
        (table_name,),
    ).fetchall()
    return {r["column_name"] for r in rows}


def _table_exists(conn: psycopg.Connection, table_name: str) -> bool:
    """Check if a table exists in the public schema."""
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_name = %s AND table_schema = 'public'",
        (table_name,),
    ).fetchone()
    return row is not None


def _upgrade_schema(conn: psycopg.Connection) -> None:
    """
    Migrate data from older schemas to the current encrypted-at-rest,
    3NF-normalized schema.

    Safe to run many times — uses ON CONFLICT DO NOTHING and column-existence
    checks so it's fully idempotent.
    """

    # ── Ensure migration flags table exists ────────────────────────────
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _migration_flags "
        "(name TEXT PRIMARY KEY, migrated_at TEXT)"
    )
    conn.commit()

    # ── 3NF structural migration (old JSON columns → normalized tables) ──
    _upgrade_3nf(conn)

    # ── Encryption-at-rest migration (plaintext → encrypted columns) ──
    _upgrade_encrypt_at_rest(conn)

    # ── Cleanup: drop legacy plaintext columns that block normal inserts ──
    _cleanup_legacy_columns(conn)

    # ── Upgrade to proper PostgreSQL types (TEXT→TIMESTAMPTZ, INTEGER→BOOLEAN) ──
    _upgrade_pg_types(conn)

    # ── Repair any boolean columns that pg_types_v1 silently skipped ──
    _repair_boolean_columns(conn)

    # ── Migrate alter blobs to normalised alters table (wide columns) ──
    _migrate_alters_to_table(conn)

    # ── Migrate EAV tables to wide-column tables ──
    _migrate_to_wide_v1(conn)

    # ── Recover avatarIcon from backup blobs (missed in initial migration) ──
    _recover_avatar_icons(conn)


def _upgrade_3nf(conn: psycopg.Connection) -> None:
    """Migrate from pre-3NF schema to normalized tables."""

    already = conn.execute(
        "SELECT 1 FROM _migration_flags WHERE name = '3nf_v1'"
    ).fetchone()
    if already:
        return

    user_cols = _get_columns(conn, "users")

    # Ensure columns that may be missing from very old schemas
    if "friend_code" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN friend_code TEXT")
        conn.commit()
    if "avatar_url" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT DEFAULT ''")
        conn.commit()

    # Ensure fronting has 'role' column
    fcols = _get_columns(conn, "fronting")
    if "role" not in fcols:
        conn.execute(
            "ALTER TABLE fronting ADD COLUMN role TEXT NOT NULL DEFAULT 'secondary'"
        )
        conn.commit()

    # 1. Migrate discord settings from users → user_discord_settings
    if "discord_id" in user_cols:
        conn.execute("""
            INSERT INTO user_discord_settings
                (user_id, discord_id, proxy_enabled, autoproxy_enabled)
            SELECT user_id, discord_id,
                   COALESCE(proxy_enabled, 0),
                   COALESCE(autoproxy_enabled, 0)
            FROM users
            WHERE discord_id IS NOT NULL
            ON CONFLICT DO NOTHING
        """)
        conn.commit()

    # 2. Migrate profile_json → user_profiles (EAV)
    if "profile_json" in user_cols:
        up_cols = _get_columns(conn, "user_profiles")
        rows = conn.execute(
            "SELECT user_id, profile_json FROM users "
            "WHERE profile_json IS NOT NULL AND profile_json != '{}' "
            "AND profile_json != ''"
        ).fetchall()
        for row in rows:
            try:
                profile = json.loads(row["profile_json"] or "{}")
                for key, value in profile.items():
                    if value and key != "display_name":
                        if "field_value" in up_cols:
                            # Old intermediate schema (has plaintext column)
                            conn.execute(
                                "INSERT INTO user_profiles "
                                "(user_id, field_name, field_value) "
                                "VALUES (%s, %s, %s) "
                                "ON CONFLICT DO NOTHING",
                                (row["user_id"], key, str(value)),
                            )
                        else:
                            # New schema — encrypt directly
                            vn, vc = _encrypt_field(str(value))
                            conn.execute(
                                "INSERT INTO user_profiles "
                                "(user_id, field_name, value_nonce, value_cipher) "
                                "VALUES (%s, %s, %s, %s) "
                                "ON CONFLICT DO NOTHING",
                                (row["user_id"], key, vn, vc),
                            )
            except (json.JSONDecodeError, TypeError):
                pass
        conn.commit()

    # 3. Migrate share_alters.hidden_fields → share_alter_hidden_groups
    sa_cols = _get_columns(conn, "share_alters")
    if "hidden_fields" in sa_cols:
        rows = conn.execute(
            "SELECT share_code, alter_uuid, hidden_fields FROM share_alters "
            "WHERE hidden_fields IS NOT NULL AND hidden_fields != '[]'"
        ).fetchall()
        for row in rows:
            try:
                groups = json.loads(row["hidden_fields"] or "[]")
                for g in groups:
                    if g:
                        conn.execute(
                            "INSERT INTO share_alter_hidden_groups "
                            "(share_code, alter_uuid, group_name) VALUES (%s, %s, %s) "
                            "ON CONFLICT DO NOTHING",
                            (row["share_code"], row["alter_uuid"], g),
                        )
            except (json.JSONDecodeError, TypeError):
                pass
        conn.commit()

    # 4. Migrate friend_shares.hidden_fields → friend_share_hidden_groups
    fs_cols = _get_columns(conn, "friend_shares")
    if "hidden_fields" in fs_cols:
        rows = conn.execute(
            "SELECT user_id, friend_id, alter_uuid, hidden_fields FROM friend_shares "
            "WHERE hidden_fields IS NOT NULL AND hidden_fields != '[]'"
        ).fetchall()
        for row in rows:
            try:
                groups = json.loads(row["hidden_fields"] or "[]")
                for g in groups:
                    if g:
                        conn.execute(
                            "INSERT INTO friend_share_hidden_groups "
                            "(user_id, friend_id, alter_uuid, group_name) "
                            "VALUES (%s, %s, %s, %s) "
                            "ON CONFLICT DO NOTHING",
                            (row["user_id"], row["friend_id"],
                             row["alter_uuid"], g),
                        )
            except (json.JSONDecodeError, TypeError):
                pass
        conn.commit()

    # 5. Migrate fronting_shares.hidden_fields → fronting_share_hidden_groups
    fts_cols = _get_columns(conn, "fronting_shares")
    if "hidden_fields" in fts_cols:
        rows = conn.execute(
            "SELECT user_id, friend_id, hidden_fields FROM fronting_shares "
            "WHERE hidden_fields IS NOT NULL AND hidden_fields != '[]'"
        ).fetchall()
        for row in rows:
            try:
                groups = json.loads(row["hidden_fields"] or "[]")
                for g in groups:
                    if g:
                        conn.execute(
                            "INSERT INTO fronting_share_hidden_groups "
                            "(user_id, friend_id, group_name) VALUES (%s, %s, %s) "
                            "ON CONFLICT DO NOTHING",
                            (row["user_id"], row["friend_id"], g),
                        )
            except (json.JSONDecodeError, TypeError):
                pass
        conn.commit()

    # 6. Migrate journal_entries.tags → journal_tags + journal_entry_tags
    je_cols = _get_columns(conn, "journal_entries")
    if "tags" in je_cols:
        jt_cols = _get_columns(conn, "journal_tags")

        if "name" in jt_cols:
            # Old intermediate schema — insert plaintext tag names
            rows = conn.execute(
                "SELECT id, tags FROM journal_entries "
                "WHERE tags IS NOT NULL AND tags != '[]'"
            ).fetchall()
            for row in rows:
                try:
                    tags = json.loads(row["tags"] or "[]")
                    for tag_name in tags:
                        if not tag_name:
                            continue
                        conn.execute(
                            "INSERT INTO journal_tags (name) "
                            "VALUES (%s) "
                            "ON CONFLICT DO NOTHING",
                            (tag_name,),
                        )
                        tag_row = conn.execute(
                            "SELECT id FROM journal_tags WHERE name = %s",
                            (tag_name,),
                        ).fetchone()
                        if tag_row:
                            conn.execute(
                                "INSERT INTO journal_entry_tags "
                                "(entry_id, tag_id) VALUES (%s, %s) "
                                "ON CONFLICT DO NOTHING",
                                (row["id"], tag_row["id"]),
                            )
                except (json.JSONDecodeError, TypeError):
                    pass
        else:
            # New schema — encrypt tag names directly, grouped by user
            rows = conn.execute(
                "SELECT id, user_id, tags FROM journal_entries "
                "WHERE tags IS NOT NULL AND tags != '[]'"
            ).fetchall()
            for row in rows:
                try:
                    tags = json.loads(row["tags"] or "[]")
                    tag_ids = _ensure_tags(conn, row["user_id"], tags)
                    for tid in tag_ids:
                        conn.execute(
                            "INSERT INTO journal_entry_tags "
                            "(entry_id, tag_id) VALUES (%s, %s) "
                            "ON CONFLICT DO NOTHING",
                            (row["id"], tid),
                        )
                except (json.JSONDecodeError, TypeError):
                    pass
        conn.commit()

    conn.execute(
        "INSERT INTO _migration_flags (name, migrated_at) "
        "VALUES ('3nf_v1', %s) "
        "ON CONFLICT DO NOTHING",
        (_now(),),
    )
    conn.commit()


def _upgrade_encrypt_at_rest(conn: psycopg.Connection) -> None:
    """Migrate plaintext user-submitted data to encrypted columns."""

    already = conn.execute(
        "SELECT 1 FROM _migration_flags WHERE name = 'encrypt_at_rest_v1'"
    ).fetchone()
    if already:
        return

    # ── 1. users: display_name → name_nonce / name_cipher ──────────────
    user_cols = _get_columns(conn, "users")
    if "display_name" in user_cols:
        if "name_nonce" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN name_nonce BYTEA")
            conn.execute("ALTER TABLE users ADD COLUMN name_cipher BYTEA")
            conn.commit()
        for row in conn.execute(
            "SELECT user_id, display_name FROM users "
            "WHERE display_name IS NOT NULL AND display_name != ''"
        ).fetchall():
            nn, nc = _encrypt_field(row["display_name"])
            conn.execute(
                "UPDATE users SET name_nonce = %s, name_cipher = %s WHERE user_id = %s",
                (nn, nc, row["user_id"]),
            )
        conn.commit()

    # ── 2. user_profiles: field_value → value_nonce / value_cipher ─────
    up_cols = _get_columns(conn, "user_profiles")
    if "field_value" in up_cols:
        if "value_nonce" not in up_cols:
            conn.execute("ALTER TABLE user_profiles ADD COLUMN value_nonce BYTEA")
            conn.execute("ALTER TABLE user_profiles ADD COLUMN value_cipher BYTEA")
            conn.commit()
        for row in conn.execute(
            "SELECT user_id, field_name, field_value FROM user_profiles "
            "WHERE field_value IS NOT NULL AND field_value != ''"
        ).fetchall():
            vn, vc = _encrypt_field(row["field_value"])
            conn.execute(
                "UPDATE user_profiles SET value_nonce = %s, value_cipher = %s "
                "WHERE user_id = %s AND field_name = %s",
                (vn, vc, row["user_id"], row["field_name"]),
            )
        conn.commit()

    # ── 3. journal_entries: title → title_nonce / title_cipher ─────────
    je_cols = _get_columns(conn, "journal_entries")
    if "title" in je_cols:
        if "title_nonce" not in je_cols:
            conn.execute("ALTER TABLE journal_entries ADD COLUMN title_nonce BYTEA")
            conn.execute("ALTER TABLE journal_entries ADD COLUMN title_cipher BYTEA")
            conn.commit()
        for row in conn.execute(
            "SELECT id, title FROM journal_entries "
            "WHERE title IS NOT NULL AND title != ''"
        ).fetchall():
            tn, tc = _encrypt_field(row["title"])
            conn.execute(
                "UPDATE journal_entries SET title_nonce = %s, title_cipher = %s "
                "WHERE id = %s",
                (tn, tc, row["id"]),
            )
        conn.commit()

    # ── 4. friend_requests: message → msg_nonce / msg_cipher ──────────
    fr_cols = _get_columns(conn, "friend_requests")
    if "message" in fr_cols:
        if "msg_nonce" not in fr_cols:
            conn.execute("ALTER TABLE friend_requests ADD COLUMN msg_nonce BYTEA")
            conn.execute("ALTER TABLE friend_requests ADD COLUMN msg_cipher BYTEA")
            conn.commit()
        for row in conn.execute(
            "SELECT id, message FROM friend_requests "
            "WHERE message IS NOT NULL AND message != ''"
        ).fetchall():
            mn, mc = _encrypt_field(row["message"])
            conn.execute(
                "UPDATE friend_requests SET msg_nonce = %s, msg_cipher = %s "
                "WHERE id = %s",
                (mn, mc, row["id"]),
            )
        conn.commit()

    # ── 5. shares: label → label_nonce / label_cipher ─────────────────
    sh_cols = _get_columns(conn, "shares")
    if "label" in sh_cols:
        if "label_nonce" not in sh_cols:
            conn.execute("ALTER TABLE shares ADD COLUMN label_nonce BYTEA")
            conn.execute("ALTER TABLE shares ADD COLUMN label_cipher BYTEA")
            conn.commit()
        for row in conn.execute(
            "SELECT share_code, label FROM shares "
            "WHERE label IS NOT NULL AND label != ''"
        ).fetchall():
            ln, lc = _encrypt_field(row["label"])
            conn.execute(
                "UPDATE shares SET label_nonce = %s, label_cipher = %s "
                "WHERE share_code = %s",
                (ln, lc, row["share_code"]),
            )
        conn.commit()

    # ── 6. discord_proxies: prefix/suffix → encrypted ─────────────────
    dp_cols = _get_columns(conn, "discord_proxies")
    if "prefix" in dp_cols:
        if "prefix_nonce" not in dp_cols:
            conn.execute("ALTER TABLE discord_proxies ADD COLUMN prefix_nonce BYTEA")
            conn.execute("ALTER TABLE discord_proxies ADD COLUMN prefix_cipher BYTEA")
            conn.execute("ALTER TABLE discord_proxies ADD COLUMN suffix_nonce BYTEA")
            conn.execute("ALTER TABLE discord_proxies ADD COLUMN suffix_cipher BYTEA")
            conn.commit()
        for row in conn.execute("SELECT id, prefix, suffix FROM discord_proxies").fetchall():
            if row["prefix"]:
                pn, pc = _encrypt_field(row["prefix"])
                conn.execute(
                    "UPDATE discord_proxies SET prefix_nonce = %s, prefix_cipher = %s "
                    "WHERE id = %s",
                    (pn, pc, row["id"]),
                )
            if row["suffix"]:
                sn, sc = _encrypt_field(row["suffix"])
                conn.execute(
                    "UPDATE discord_proxies SET suffix_nonce = %s, suffix_cipher = %s "
                    "WHERE id = %s",
                    (sn, sc, row["id"]),
                )
        conn.commit()

    # ── 7. journal_tags: make per-user and encrypt names ──────────────
    jt_cols = _get_columns(conn, "journal_tags")
    if "name" in jt_cols and "name_nonce" not in jt_cols:
        # Old schema has global plaintext tags — migrate to per-user encrypted
        conn.execute("ALTER TABLE journal_tags ADD COLUMN user_id TEXT")
        conn.execute("ALTER TABLE journal_tags ADD COLUMN name_nonce BYTEA")
        conn.execute("ALTER TABLE journal_tags ADD COLUMN name_cipher BYTEA")
        conn.commit()

    if "name" in jt_cols:
        # Find all (user, old_tag) pairs via the junction table
        old_usage = conn.execute(
            "SELECT DISTINCT t.id AS tag_id, t.name, e.user_id "
            "FROM journal_tags t "
            "JOIN journal_entry_tags et ON t.id = et.tag_id "
            "JOIN journal_entries e ON et.entry_id = e.id "
            "WHERE t.name IS NOT NULL AND t.name != '' "
            "AND t.name_nonce IS NULL"
        ).fetchall()

        # Create per-user encrypted tags and remap journal_entry_tags.
        # The old table has  name TEXT NOT NULL UNIQUE  so we must supply
        # a unique placeholder for the legacy column on every INSERT.
        remap: dict[tuple[str, int], int] = {}  # (user_id, old_tag_id) → new_tag_id
        for row in old_usage:
            key = (row["user_id"], row["tag_id"])
            if key in remap:
                continue
            nn, nc = _encrypt_field(row["name"])
            placeholder = f"_enc_{row['user_id']}_{row['tag_id']}"
            cur = conn.execute(
                "INSERT INTO journal_tags "
                "(user_id, name_nonce, name_cipher, name) "
                "VALUES (%s, %s, %s, %s) RETURNING id",
                (row["user_id"], nn, nc, placeholder),
            )
            remap[key] = cur.fetchone()["id"]

        for (uid, old_tid), new_tid in remap.items():
            conn.execute(
                "UPDATE journal_entry_tags SET tag_id = %s "
                "WHERE tag_id = %s AND entry_id IN ("
                "  SELECT id FROM journal_entries WHERE user_id = %s"
                ")",
                (new_tid, old_tid, uid),
            )

        # Remove old plaintext tag rows that are no longer referenced
        conn.execute(
            "DELETE FROM journal_tags WHERE name_nonce IS NULL "
            "AND id NOT IN (SELECT tag_id FROM journal_entry_tags)"
        )
        conn.commit()

    # ── Mark migration complete ────────────────────────────────────────
    conn.execute(
        "INSERT INTO _migration_flags (name, migrated_at) "
        "VALUES ('encrypt_at_rest_v1', %s) "
        "ON CONFLICT DO NOTHING",
        (_now(),),
    )
    conn.commit()


def _cleanup_legacy_columns(conn: psycopg.Connection) -> None:
    """
    Remove legacy plaintext columns left over from pre-encryption schemas.

    The most critical one is journal_tags.name (TEXT NOT NULL UNIQUE) which
    blocks new inserts.  We rebuild the table without it.  Also strips other
    leftover plaintext columns from tables that have been migrated to
    encrypted _nonce/_cipher pairs.

    Safe to run many times — checks a migration flag first.
    """
    already = conn.execute(
        "SELECT 1 FROM _migration_flags WHERE name = 'cleanup_legacy_v1'"
    ).fetchone()
    if already:
        return

    # ── journal_tags: drop legacy 'name' column ────────────────────────
    jt_cols = _get_columns(conn, "journal_tags")
    if "name" in jt_cols:
        # PostgreSQL supports DROP COLUMN directly
        # First delete rows without encrypted data
        conn.execute(
            "DELETE FROM journal_tags "
            "WHERE user_id IS NULL OR name_nonce IS NULL OR name_cipher IS NULL"
        )
        # Make columns NOT NULL before dropping the legacy column
        conn.execute("ALTER TABLE journal_tags ALTER COLUMN user_id SET NOT NULL")
        conn.execute("ALTER TABLE journal_tags ALTER COLUMN name_nonce SET NOT NULL")
        conn.execute("ALTER TABLE journal_tags ALTER COLUMN name_cipher SET NOT NULL")
        conn.execute("ALTER TABLE journal_tags DROP COLUMN name")
        conn.commit()

    conn.execute(
        "INSERT INTO _migration_flags (name, migrated_at) "
        "VALUES ('cleanup_legacy_v1', %s) "
        "ON CONFLICT DO NOTHING",
        (_now(),),
    )
    conn.commit()


def _upgrade_pg_types(conn: psycopg.Connection) -> None:
    """
    Upgrade legacy TEXT timestamp columns to TIMESTAMPTZ and INTEGER
    boolean columns to BOOLEAN.  Idempotent — checks a migration flag
    first and skips columns that are already the correct type.
    """
    already = conn.execute(
        "SELECT 1 FROM _migration_flags WHERE name = 'pg_types_v1'"
    ).fetchone()
    if already:
        return

    # ── Timestamp columns: TEXT → TIMESTAMPTZ ──────────────────────────
    ts_upgrades = [
        ("users",            "created_at"),
        ("users",            "updated_at"),
        ("user_data",        "updated_at"),
        ("user_data_backups","created_at"),
        ("shares",           "created_at"),
        ("shares",           "expires_at"),
        ("fronting",         "set_at"),
        ("share_claims",     "claimed_at"),
        ("link_codes",       "created_at"),
        ("link_codes",       "expires_at"),
        ("friend_requests",  "created_at"),
        ("friend_requests",  "updated_at"),
        ("friendships",      "created_at"),
        ("journal_entries",  "created_at"),
        ("journal_entries",  "updated_at"),
    ]
    for table, col in ts_upgrades:
        try:
            # Check current type — skip if already timestamptz
            cur_type = conn.execute(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = %s "
                "AND column_name = %s",
                (table, col),
            ).fetchone()
            if cur_type and cur_type["data_type"] == "timestamp with time zone":
                continue
            if cur_type is None:
                continue  # column doesn't exist yet
            conn.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" '
                f'TYPE TIMESTAMPTZ USING "{col}"::timestamptz'
            )
            conn.commit()
        except Exception:
            conn.rollback()

    # ── Boolean columns: INTEGER → BOOLEAN ─────────────────────────────
    bool_upgrades = [
        ("user_discord_settings", "proxy_enabled",     "FALSE"),
        ("user_discord_settings", "autoproxy_enabled",  "FALSE"),
        ("shares",                "is_active",          "TRUE"),
        ("discord_proxies",       "is_active",          "TRUE"),
    ]
    for table, col, default in bool_upgrades:
        try:
            cur_type = conn.execute(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = %s "
                "AND column_name = %s",
                (table, col),
            ).fetchone()
            if cur_type and cur_type["data_type"] == "boolean":
                continue
            if cur_type is None:
                continue
            # Drop integer default first — PG refuses ALTER TYPE when
            # the existing default is incompatible with the target type.
            conn.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" DROP DEFAULT'
            )
            conn.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" '
                f'TYPE BOOLEAN USING ("{col}" != 0)'
            )
            conn.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" '
                f'SET DEFAULT {default}'
            )
            conn.commit()
        except Exception:
            conn.rollback()

    conn.execute(
        "INSERT INTO _migration_flags (name, migrated_at) "
        "VALUES ('pg_types_v1', %s) "
        "ON CONFLICT DO NOTHING",
        (_now(),),
    )
    conn.commit()


def _repair_boolean_columns(conn: psycopg.Connection) -> None:
    """
    Force INTEGER→BOOLEAN conversion for columns that ``_upgrade_pg_types``
    may have silently skipped.

    The original migration failed because PostgreSQL cannot implicitly cast
    an existing INTEGER default (e.g. ``1``) to BOOLEAN during ALTER TYPE.
    Fix: DROP DEFAULT → ALTER TYPE → SET DEFAULT.

    Runs every schema init but only does ALTER TABLE if the column is
    actually the wrong type.
    """
    bool_columns = [
        ("discord_proxies",       "is_active",          "TRUE"),
        ("shares",                "is_active",          "TRUE"),
        ("user_discord_settings", "proxy_enabled",      "FALSE"),
        ("user_discord_settings", "autoproxy_enabled",  "FALSE"),
    ]
    for table, col, default in bool_columns:
        try:
            cur_type = conn.execute(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = %s "
                "AND column_name = %s",
                (table, col),
            ).fetchone()
            if not cur_type or cur_type["data_type"] == "boolean":
                continue  # already correct (or column doesn't exist)
            # Must drop the integer default FIRST — PG refuses ALTER TYPE
            # when the existing default is incompatible with the new type.
            conn.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" DROP DEFAULT'
            )
            conn.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" '
                f'TYPE BOOLEAN USING ("{col}" != 0)'
            )
            conn.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" '
                f'SET DEFAULT {default}'
            )
            conn.commit()
            print(f"[repair-bool] {table}.{col} converted to BOOLEAN",
                  file=sys.stderr)
        except Exception as exc:
            conn.rollback()
            print(f"[repair-bool] {table}.{col} failed: {exc}",
                  file=sys.stderr)


def _alter_json_to_col_values(alter: dict) -> dict[str, tuple]:
    """Map a single alter JSON dict to {column_prefix: (nonce, cipher)}."""
    col_values: dict[str, tuple] = {}
    for key, value in alter.items():
        if key in ("UUID", "image", "cardColor", "avatarIcon", "sort_id"):
            continue
        if isinstance(value, list):
            for field_dict in value:
                if isinstance(field_dict, dict):
                    for fname, fval in field_dict.items():
                        col = _ALTER_JSON_TO_COL.get((key, fname))
                        if col:
                            vn, vc = _encrypt_field(
                                str(fval) if fval is not None else ""
                            )
                            col_values[col] = (vn, vc)
    return col_values


def _migrate_alters_to_table(conn: psycopg.Connection) -> None:
    """
    One-time migration: move alter data from encrypted JSON blobs
    (user_data rows with data_type='alters') into the wide ``alters``
    table (one row per alter, one column-pair per field).

    Each alter gets its own UUID (generated if missing).
    Field *values* are individually encrypted; group/field names are
    kept as plaintext column names.
    """
    already = conn.execute(
        "SELECT 1 FROM _migration_flags WHERE name = 'alters_table_v1'"
    ).fetchone()
    if already:
        return

    # Ensure the wide columns exist (for installs created before this schema)
    _ensure_wide_alter_columns(conn)

    now = _now()

    rows = conn.execute(
        "SELECT user_id, nonce, ciphertext FROM user_data "
        "WHERE data_type = 'alters'"
    ).fetchall()

    for row in rows:
        try:
            plaintext = decrypt(row["nonce"], row["ciphertext"])
            alters_list = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            print(f"[migrate-alters] SKIP user={row['user_id']}: {exc}",
                  file=sys.stderr)
            continue

        if not isinstance(alters_list, list):
            continue

        for sort_order, alter in enumerate(alters_list):
            if not isinstance(alter, dict):
                continue

            alter_uuid = alter.get("UUID") or str(_uuid_mod.uuid4())
            image = alter.get("image", "") or ""
            card_color = alter.get("cardColor", "") or ""
            avatar_icon = alter.get("avatarIcon", "") or ""

            # Build column lists
            col_values = _alter_json_to_col_values(alter)
            cols = ["user_id", "uuid", "sort_order", "image", "card_color",
                    "avatar_icon", "created_at", "updated_at"]
            vals: list = [row["user_id"], alter_uuid, sort_order, image,
                          card_color, avatar_icon, now, now]
            for cp, (vn, vc) in col_values.items():
                cols.extend([f"{cp}_nonce", f"{cp}_cipher"])
                vals.extend([vn, vc])

            ph = ", ".join(["%s"] * len(vals))
            conn.execute(
                f"INSERT INTO alters ({', '.join(cols)}) VALUES ({ph}) "
                "ON CONFLICT DO NOTHING",
                vals,
            )

        # Keep blob as a backup, then remove the active row
        conn.execute(
            "INSERT INTO user_data_backups "
            "(user_id, data_type, nonce, ciphertext, created_at) "
            "VALUES (%s, 'alters', %s, %s, %s)",
            (row["user_id"], row["nonce"], row["ciphertext"], now),
        )
        conn.execute(
            "DELETE FROM user_data WHERE user_id = %s AND data_type = 'alters'",
            (row["user_id"],),
        )
        conn.commit()
        print(f"[migrate-alters] user={row['user_id']} OK", file=sys.stderr)

    conn.execute(
        "INSERT INTO _migration_flags (name, migrated_at) "
        "VALUES ('alters_table_v1', %s) "
        "ON CONFLICT DO NOTHING",
        (now,),
    )
    conn.commit()


# ── helpers for wide-column migrations ─────────────────────────────────

def _ensure_wide_alter_columns(conn: psycopg.Connection) -> None:
    """Add wide-column pairs to ``alters`` if they're missing (existing installs)."""
    existing = _get_columns(conn, "alters")

    # Ensure the avatar_icon plain-text column exists
    if "avatar_icon" not in existing:
        try:
            conn.execute("ALTER TABLE alters ADD COLUMN avatar_icon TEXT DEFAULT ''")
            conn.commit()
        except Exception:
            conn.rollback()

    for cp in _ALTER_COL_PREFIXES:
        for suffix in ("_nonce", "_cipher"):
            col = f"{cp}{suffix}"
            if col not in existing:
                try:
                    conn.execute(f'ALTER TABLE alters ADD COLUMN "{col}" BYTEA')
                    conn.commit()
                except Exception:
                    conn.rollback()


def _ensure_wide_profile_table(conn: psycopg.Connection) -> None:
    """
    If ``user_profiles`` still uses the old EAV schema (has ``field_name``
    column), read the data, drop the table, and re-create it as a
    wide single-row-per-user table.  Returns the migrated data dict
    keyed by user_id, or None if no migration was needed.
    """
    if not _table_exists(conn, "user_profiles"):
        return None

    up_cols = _get_columns(conn, "user_profiles")
    if "field_name" not in up_cols:
        return None  # already wide (or new install)

    # Determine which value columns are available in the old table
    has_encrypted = "value_nonce" in up_cols and "value_cipher" in up_cols
    has_plaintext = "field_value" in up_cols

    if not has_encrypted and not has_plaintext:
        # No value columns at all — can't migrate, just drop and recreate empty
        conn.execute("DROP TABLE user_profiles CASCADE")
        conn.commit()
        _create_wide_profile_table(conn)
        return {}

    # 1. Read all EAV rows
    data_by_user: dict[str, dict[str, tuple]] = {}
    if has_encrypted:
        for row in conn.execute(
            "SELECT user_id, field_name, value_nonce, value_cipher "
            "FROM user_profiles"
        ).fetchall():
            uid = row["user_id"]
            if uid not in data_by_user:
                data_by_user[uid] = {}
            col = _PROFILE_JSON_TO_COL.get(row["field_name"])
            if col:
                data_by_user[uid][col] = (row["value_nonce"], row["value_cipher"])
    else:
        # Plaintext only — encrypt on the fly
        for row in conn.execute(
            "SELECT user_id, field_name, field_value FROM user_profiles "
            "WHERE field_value IS NOT NULL AND field_value != ''"
        ).fetchall():
            uid = row["user_id"]
            if uid not in data_by_user:
                data_by_user[uid] = {}
            col = _PROFILE_JSON_TO_COL.get(row["field_name"])
            if col:
                vn, vc = _encrypt_field(str(row["field_value"]))
                data_by_user[uid][col] = (vn, vc)

    # 2. Drop old table
    conn.execute("DROP TABLE user_profiles CASCADE")
    conn.commit()

    # 3. Create wide table
    _create_wide_profile_table(conn)

    # 4. Insert migrated data
    for uid, fields in data_by_user.items():
        cols = ["user_id"]
        vals: list = [uid]
        for cp, (vn, vc) in fields.items():
            cols.extend([f"{cp}_nonce", f"{cp}_cipher"])
            vals.extend([vn, vc])
        ph = ", ".join(["%s"] * len(vals))
        conn.execute(
            f"INSERT INTO user_profiles ({', '.join(cols)}) VALUES ({ph}) "
            "ON CONFLICT DO NOTHING",
            vals,
        )
    conn.commit()
    return data_by_user


def _create_wide_profile_table(conn: psycopg.Connection) -> None:
    """Create the wide ``user_profiles`` table."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id          TEXT PRIMARY KEY
                                  REFERENCES users(user_id) ON DELETE CASCADE,
            age_nonce        BYTEA, age_cipher        BYTEA,
            pronouns_nonce   BYTEA, pronouns_cipher   BYTEA,
            gender_nonce     BYTEA, gender_cipher     BYTEA,
            sexuality_nonce  BYTEA, sexuality_cipher  BYTEA,
            communication_nonce BYTEA, communication_cipher BYTEA,
            personality_nonce BYTEA, personality_cipher BYTEA,
            boundaries_nonce BYTEA, boundaries_cipher BYTEA,
            triggers_nonce   BYTEA, triggers_cipher   BYTEA,
            bio_nonce        BYTEA, bio_cipher        BYTEA
        )
    """)
    conn.commit()


def _migrate_to_wide_v1(conn: psycopg.Connection) -> None:
    """
    One-time migration: convert EAV tables to wide-column tables.

    1. ``alter_fields`` → columns on ``alters``  (then DROP alter_fields)
    2. ``user_profiles`` EAV → wide single-row-per-user table
    """
    already = conn.execute(
        "SELECT 1 FROM _migration_flags WHERE name = 'wide_tables_v1'"
    ).fetchone()
    if already:
        return

    # ── 1. alter_fields → wide columns on alters ──────────────────────

    if _table_exists(conn, "alter_fields"):
        try:
            _ensure_wide_alter_columns(conn)

            af_cols = _get_columns(conn, "alter_fields")
            needed = {"user_id", "alter_uuid", "group_name", "field_name",
                       "value_nonce", "value_cipher"}
            if needed.issubset(af_cols):
                rows = conn.execute(
                    "SELECT user_id, alter_uuid, group_name, field_name, "
                    "       value_nonce, value_cipher "
                    "FROM alter_fields"
                ).fetchall()

                # Batch updates: group by (user_id, alter_uuid)
                updates: dict[tuple[str, str], dict[str, tuple]] = {}
                for r in rows:
                    key = (r["user_id"], r["alter_uuid"])
                    col = _ALTER_JSON_TO_COL.get(
                        (r["group_name"], r["field_name"])
                    )
                    if col:
                        updates.setdefault(key, {})[col] = (
                            r["value_nonce"], r["value_cipher"]
                        )

                for (uid, auuid), cols in updates.items():
                    sets = []
                    vals: list = []
                    for cp, (vn, vc) in cols.items():
                        sets.append(
                            f'"{cp}_nonce" = %s, "{cp}_cipher" = %s'
                        )
                        vals.extend([vn, vc])
                    if sets:
                        vals.extend([uid, auuid])
                        conn.execute(
                            f"UPDATE alters SET {', '.join(sets)} "
                            "WHERE user_id = %s AND uuid = %s",
                            vals,
                        )

            conn.execute("DROP TABLE alter_fields CASCADE")
            conn.commit()
            print("[migrate-wide] alter_fields → alters columns OK",
                  file=sys.stderr)
        except Exception as exc:
            conn.rollback()
            print(f"[migrate-wide] alter_fields migration error: {exc}",
                  file=sys.stderr)

    # ── 2. user_profiles EAV → wide table ─────────────────────────────

    try:
        result = _ensure_wide_profile_table(conn)
        if result is not None:
            print("[migrate-wide] user_profiles EAV → wide OK",
                  file=sys.stderr)
    except Exception as exc:
        conn.rollback()
        # Attempt to recreate the table if it was dropped but CREATE failed
        if not _table_exists(conn, "user_profiles"):
            _create_wide_profile_table(conn)
        print(f"[migrate-wide] user_profiles migration error: {exc}",
              file=sys.stderr)

    # ── Mark complete ─────────────────────────────────────────────────

    conn.execute(
        "INSERT INTO _migration_flags (name, migrated_at) "
        "VALUES ('wide_tables_v1', %s) "
        "ON CONFLICT DO NOTHING",
        (_now(),),
    )
    conn.commit()


def _recover_avatar_icons(conn: psycopg.Connection) -> None:
    """
    One-time migration: recover ``avatarIcon`` values that were lost when
    ``_migrate_alters_to_table`` moved alter data from JSON blobs to the
    wide ``alters`` table but didn't include the ``avatarIcon`` field.

    Reads the most recent backup blob for each user from
    ``user_data_backups`` and patches the ``avatar_icon`` column.
    """
    already = conn.execute(
        "SELECT 1 FROM _migration_flags WHERE name = 'recover_avatar_icons_v1'"
    ).fetchone()
    if already:
        return

    # Ensure the column exists first
    _ensure_wide_alter_columns(conn)

    # Get the most recent backup per user (the one _migrate_alters_to_table created)
    rows = conn.execute(
        "SELECT DISTINCT ON (user_id) user_id, nonce, ciphertext "
        "FROM user_data_backups "
        "WHERE data_type = 'alters' "
        "ORDER BY user_id, created_at DESC"
    ).fetchall()

    recovered = 0
    for row in rows:
        try:
            plaintext = decrypt(row["nonce"], row["ciphertext"])
            alters_list = json.loads(plaintext.decode("utf-8"))
        except Exception:
            continue

        if not isinstance(alters_list, list):
            continue

        for alter in alters_list:
            if not isinstance(alter, dict):
                continue
            avatar_icon = alter.get("avatarIcon", "")
            alter_uuid = alter.get("UUID", "")
            if avatar_icon and alter_uuid:
                conn.execute(
                    "UPDATE alters SET avatar_icon = %s "
                    "WHERE user_id = %s AND uuid = %s AND "
                    "(avatar_icon IS NULL OR avatar_icon = '')",
                    (avatar_icon, row["user_id"], alter_uuid),
                )
                recovered += 1

    conn.execute(
        "INSERT INTO _migration_flags (name, migrated_at) "
        "VALUES ('recover_avatar_icons_v1', %s) "
        "ON CONFLICT DO NOTHING",
        (_now(),),
    )
    conn.commit()
    if recovered:
        print(f"[recover-icons] Restored {recovered} avatarIcon values",
              file=sys.stderr)


def _now() -> str:
    """UTC timestamp as ISO-8601 string (accepted by TIMESTAMPTZ columns)."""
    return datetime.now(timezone.utc).isoformat()


def _to_json_safe(obj):
    """Recursively convert datetime/date objects to ISO-8601 strings for JSON."""
    if isinstance(obj, dict):
        return {k: _to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_json_safe(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


# ---------------------------------------------------------------------------
#  Internal helpers
# ---------------------------------------------------------------------------

def _get_profile_dict(conn: psycopg.Connection, user_id: str) -> dict:
    """Fetch a user's profile fields as a plain dict (values decrypted).
    Handles both the wide table and the legacy EAV table transparently."""
    up_cols = _get_columns(conn, "user_profiles")

    # ── Wide table (current schema) ───────────────────────────────────
    if "field_name" not in up_cols:
        row = conn.execute(
            "SELECT * FROM user_profiles WHERE user_id = %s",
            (user_id,),
        ).fetchone()
        if not row:
            return {}
        result = {}
        for col_prefix, json_key in _PROFILE_COL_TO_JSON.items():
            val = _decrypt_field(
                row.get(f"{col_prefix}_nonce"),
                row.get(f"{col_prefix}_cipher"),
            )
            if val:
                result[json_key] = val
        return result

    # ── Legacy EAV table (pre-migration fallback) ─────────────────────
    rows = conn.execute(
        "SELECT * FROM user_profiles WHERE user_id = %s",
        (user_id,),
    ).fetchall()
    result = {}
    for r in rows:
        key = r.get("field_name", "")
        if "value_nonce" in r and r["value_nonce"]:
            val = _decrypt_field(r["value_nonce"], r["value_cipher"])
        elif "field_value" in r and r["field_value"]:
            val = str(r["field_value"])
        else:
            val = ""
        if val:
            result[key] = val
    return result


def _ensure_tags(conn: psycopg.Connection,
                 user_id: str, tags: list[str]) -> list[int]:
    """Ensure per-user encrypted tags exist and return their IDs.
    Deduplication is done by decrypting existing tags and comparing."""
    # Check if the legacy 'name' column still exists (NOT NULL UNIQUE).
    # If so, every INSERT must include a placeholder to avoid constraint errors.
    jt_cols = _get_columns(conn, "journal_tags")
    has_legacy_name = "name" in jt_cols

    # Load existing tags for this user (decrypt to compare)
    existing = conn.execute(
        "SELECT id, name_nonce, name_cipher FROM journal_tags WHERE user_id = %s",
        (user_id,),
    ).fetchall()
    existing_map: dict[str, int] = {}  # lowered name → id
    for row in existing:
        name = _decrypt_field(row["name_nonce"], row["name_cipher"])
        if name:
            existing_map[name.lower()] = row["id"]

    tag_ids: list[int] = []
    for tag in tags:
        if not tag:
            continue
        key = tag.strip().lower()
        if key in existing_map:
            tag_ids.append(existing_map[key])
        else:
            nn, nc = _encrypt_field(tag.strip())
            if has_legacy_name:
                placeholder = f"_enc_{user_id}_{secrets.token_hex(4)}"
                cur = conn.execute(
                    "INSERT INTO journal_tags "
                    "(user_id, name_nonce, name_cipher, name) "
                    "VALUES (%s, %s, %s, %s) RETURNING id",
                    (user_id, nn, nc, placeholder),
                )
            else:
                cur = conn.execute(
                    "INSERT INTO journal_tags "
                    "(user_id, name_nonce, name_cipher) "
                    "VALUES (%s, %s, %s) RETURNING id",
                    (user_id, nn, nc),
                )
            tid = cur.fetchone()["id"]
            tag_ids.append(tid)
            existing_map[key] = tid
    return tag_ids


def _set_entry_tags(conn: psycopg.Connection,
                    entry_id: int, tag_ids: list[int]) -> None:
    """Replace all tags for a journal entry."""
    conn.execute(
        "DELETE FROM journal_entry_tags WHERE entry_id = %s", (entry_id,)
    )
    for tag_id in tag_ids:
        conn.execute(
            "INSERT INTO journal_entry_tags (entry_id, tag_id) "
            "VALUES (%s, %s)",
            (entry_id, tag_id),
        )


def _get_entry_tags(conn: psycopg.Connection, entry_id: int) -> list[str]:
    """Return decrypted tag names for a journal entry."""
    rows = conn.execute(
        "SELECT t.name_nonce, t.name_cipher FROM journal_entry_tags et "
        "JOIN journal_tags t ON et.tag_id = t.id "
        "WHERE et.entry_id = %s",
        (entry_id,),
    ).fetchall()
    return [_decrypt_field(r["name_nonce"], r["name_cipher"]) for r in rows]


# ---------------------------------------------------------------------------
#  Users  — auto-created on first data write
# ---------------------------------------------------------------------------

def ensure_user(conn: psycopg.Connection, user_id: str) -> None:
    """Insert a user row if one doesn't exist yet."""
    now = _now()
    conn.execute(
        "INSERT INTO users (user_id, created_at, updated_at) "
        "VALUES (%s, %s, %s) "
        "ON CONFLICT (user_id) DO NOTHING",
        (user_id, now, now),
    )


def get_user(user_id: str) -> dict | None:
    """Return the user row as a dict (with discord settings merged), or None.
    Display name is decrypted from encrypted storage."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT u.user_id, u.name_nonce, u.name_cipher, "
            "       u.avatar_url, u.friend_code, "
            "       u.created_at, u.updated_at, "
            "       d.discord_id, d.proxy_enabled, d.autoproxy_enabled "
            "FROM users u "
            "LEFT JOIN user_discord_settings d ON u.user_id = d.user_id "
            "WHERE u.user_id = %s",
            (user_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["display_name"] = _decrypt_field(
            d.pop("name_nonce", None), d.pop("name_cipher", None)
        )
        return _to_json_safe(d)
    finally:
        conn.close()


def link_discord(user_id: str, discord_id: str) -> None:
    """Associate a Discord account with a Clerk user."""
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        conn.execute(
            "INSERT INTO user_discord_settings (user_id, discord_id) "
            "VALUES (%s, %s) "
            "ON CONFLICT(user_id) DO UPDATE SET discord_id = excluded.discord_id",
            (user_id, discord_id),
        )
        conn.execute(
            "UPDATE users SET updated_at = %s WHERE user_id = %s",
            (_now(), user_id),
        )
        conn.commit()
    finally:
        conn.close()


def unlink_discord(user_id: str) -> None:
    """Remove the Discord link for a user."""
    conn = _get_db()
    try:
        conn.execute(
            "DELETE FROM user_discord_settings WHERE user_id = %s",
            (user_id,),
        )
        # Deactivate all proxies
        conn.execute(
            "UPDATE discord_proxies SET is_active = FALSE WHERE user_id = %s",
            (user_id,),
        )
        conn.execute(
            "UPDATE users SET updated_at = %s WHERE user_id = %s",
            (_now(), user_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_user_by_discord(discord_id: str) -> dict | None:
    """Look up a Clerk user by their linked Discord ID.
    Display name is decrypted from encrypted storage."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT u.user_id, u.name_nonce, u.name_cipher, "
            "       u.avatar_url, u.friend_code, "
            "       u.created_at, u.updated_at, "
            "       d.discord_id, d.proxy_enabled, d.autoproxy_enabled "
            "FROM user_discord_settings d "
            "JOIN users u ON d.user_id = u.user_id "
            "WHERE d.discord_id = %s",
            (discord_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["display_name"] = _decrypt_field(
            d.pop("name_nonce", None), d.pop("name_cipher", None)
        )
        return _to_json_safe(d)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Clerk Backend API — fetch Discord ID from Clerk SSO
# ---------------------------------------------------------------------------

def get_discord_id_from_clerk(user_id: str) -> str | None:
    """
    Call the Clerk Backend API to find the user's linked Discord account.
    Returns the Discord user-ID (snowflake string) or None.

    Requires CLERK_SECRET_KEY in .env.
    """
    secret = os.environ.get("CLERK_SECRET_KEY", "")
    if not secret:
        print("[db.py] CLERK_SECRET_KEY not set — cannot verify Discord SSO",
              file=sys.stderr)
        return None

    url = f"https://api.clerk.com/v1/users/{user_id}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {secret}",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for acct in data.get("external_accounts", []):
                if "discord" in (acct.get("provider") or "").lower():
                    pid = acct.get("provider_user_id")
                    if pid:
                        return str(pid)
    except urllib.error.HTTPError as e:
        print(f"[db.py] Clerk API HTTP {e.code}: {e.read().decode()!r}",
              file=sys.stderr)
    except Exception as e:
        print(f"[db.py] Clerk API error: {e}", file=sys.stderr)
    return None


def auto_link_discord(user_id: str, frontend_discord_id: str | None = None) -> str | None:
    """
    Automatically link a user's Discord account via Clerk SSO.

    1. Tries the Clerk Backend API (most secure — verifies the SSO connection).
    2. Falls back to *frontend_discord_id* if provided (for when
       CLERK_SECRET_KEY isn't configured).

    Returns the Discord ID on success, or None on failure.
    """
    discord_id = get_discord_id_from_clerk(user_id)
    if not discord_id and frontend_discord_id:
        discord_id = str(frontend_discord_id).strip()
    if not discord_id:
        return None

    # Check if this Discord ID is already linked to another account
    existing = get_user_by_discord(discord_id)
    if existing and existing["user_id"] != user_id:
        # Already taken by a different user
        return None

    link_discord(user_id, discord_id)
    return discord_id


def set_proxy_enabled(user_id: str, enabled: bool) -> None:
    """Toggle trigger-based proxy mode on or off."""
    conn = _get_db()
    try:
        conn.execute(
            "UPDATE user_discord_settings SET proxy_enabled = %s "
            "WHERE user_id = %s",
            (enabled, user_id),
        )
        conn.execute(
            "UPDATE users SET updated_at = %s WHERE user_id = %s",
            (_now(), user_id),
        )
        conn.commit()
    finally:
        conn.close()


def set_autoproxy_enabled(user_id: str, enabled: bool) -> None:
    """Toggle auto-proxy mode on or off.

    When auto-proxy is on AND no trigger matches, messages are proxied
    as the highest-priority (primary) fronting alter automatically.
    """
    conn = _get_db()
    try:
        conn.execute(
            "UPDATE user_discord_settings SET autoproxy_enabled = %s "
            "WHERE user_id = %s",
            (enabled, user_id),
        )
        conn.execute(
            "UPDATE users SET updated_at = %s WHERE user_id = %s",
            (_now(), user_id),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Alters — normalised table storage (encrypted field values)
# ---------------------------------------------------------------------------

def _reconstruct_alter_from_row(row) -> dict:
    """Rebuild a single alter JSON dict from a wide ``alters`` row."""
    d: dict = {"UUID": row["uuid"]}
    if row.get("image"):
        d["image"] = row["image"]
    if row.get("card_color"):
        d["cardColor"] = row["card_color"]
    if row.get("avatar_icon"):
        d["avatarIcon"] = row["avatar_icon"]

    # Group fields by group_order → (group_name, [(field_order, field_name, value)])
    groups: dict[int, tuple[str, list]] = {}
    for col_prefix, (group_name, field_name, group_order, field_order) in _ALTER_COL_TO_JSON.items():
        nonce = row.get(f"{col_prefix}_nonce")
        cipher = row.get(f"{col_prefix}_cipher")
        val = _decrypt_field(nonce, cipher)
        if group_order not in groups:
            groups[group_order] = (group_name, [])
        groups[group_order][1].append((field_order, field_name, val))

    for _go, (gn, flist) in sorted(groups.items()):
        d[gn] = [{fn: val} for _, fn, val in sorted(flist)]

    return d


def _reconstruct_alter(conn: psycopg.Connection,
                       user_id: str, alter_uuid: str) -> dict | None:
    """Rebuild a single alter dict from a wide ``alters`` row."""
    row = conn.execute(
        "SELECT * FROM alters WHERE user_id = %s AND uuid = %s",
        (user_id, alter_uuid),
    ).fetchone()
    if not row:
        return None
    return _reconstruct_alter_from_row(row)


def _reconstruct_all_alters(conn: psycopg.Connection,
                            user_id: str) -> list[dict]:
    """Rebuild every alter for *user_id* in display order."""
    rows = conn.execute(
        "SELECT * FROM alters WHERE user_id = %s ORDER BY sort_order",
        (user_id,),
    ).fetchall()
    return [_reconstruct_alter_from_row(r) for r in rows]


def _backup_current_alters(conn: psycopg.Connection,
                           user_id: str, now: str) -> None:
    """Snapshot the current alters as an encrypted JSON blob for backup."""
    alters = _reconstruct_all_alters(conn, user_id)

    if not alters:
        # Fallback: if a leftover blob still sits in user_data (failed migration),
        # use it as the backup source and clean it up so it doesn't linger.
        leftover = conn.execute(
            "SELECT nonce, ciphertext FROM user_data "
            "WHERE user_id = %s AND data_type = 'alters'",
            (user_id,),
        ).fetchone()
        if leftover:
            conn.execute(
                "INSERT INTO user_data_backups "
                "(user_id, data_type, nonce, ciphertext, created_at) "
                "VALUES (%s, 'alters', %s, %s, %s)",
                (user_id, leftover["nonce"], leftover["ciphertext"], now),
            )
            conn.execute(
                "DELETE FROM user_data "
                "WHERE user_id = %s AND data_type = 'alters'",
                (user_id,),
            )
        return

    nonce, ct = encrypt(json.dumps(alters).encode("utf-8"))
    conn.execute(
        "INSERT INTO user_data_backups "
        "(user_id, data_type, nonce, ciphertext, created_at) "
        "VALUES (%s, 'alters', %s, %s, %s)",
        (user_id, nonce, ct, now),
    )
    conn.execute(
        "DELETE FROM user_data_backups WHERE id IN ("
        "  SELECT id FROM user_data_backups "
        "  WHERE user_id = %s AND data_type = 'alters' "
        "  ORDER BY created_at DESC "
        "  OFFSET %s"
        ")",
        (user_id, MAX_BACKUPS_PER_USER),
    )


def _write_alters_to_table(user_id: str, json_bytes: bytes) -> None:
    """Parse a JSON array and persist each alter as wide rows.

    * Missing UUIDs are auto-generated (uuid4).
    * Field values are individually AES-256-GCM encrypted.
    * A backup of the previous state is created automatically.
    """
    alters = json.loads(json_bytes)
    conn = _get_db()
    try:
        now = _now()
        ensure_user(conn, user_id)

        # Backup before overwriting
        _backup_current_alters(conn, user_id, now)

        # Wipe existing rows
        conn.execute("DELETE FROM alters WHERE user_id = %s", (user_id,))

        for sort_order, alter in enumerate(alters):
            if not isinstance(alter, dict):
                continue

            alter_uuid = alter.get("UUID") or str(_uuid_mod.uuid4())
            image = alter.get("image", "") or ""
            card_color = alter.get("cardColor", "") or ""
            avatar_icon = alter.get("avatarIcon", "") or ""

            col_values = _alter_json_to_col_values(alter)

            cols = ["user_id", "uuid", "sort_order", "image", "card_color",
                    "avatar_icon", "created_at", "updated_at"]
            vals: list = [user_id, alter_uuid, sort_order, image, card_color,
                          avatar_icon, now, now]
            for cp, (vn, vc) in col_values.items():
                cols.extend([f"{cp}_nonce", f"{cp}_cipher"])
                vals.extend([vn, vc])

            ph = ", ".join(["%s"] * len(vals))
            conn.execute(
                f"INSERT INTO alters ({', '.join(cols)}) VALUES ({ph})",
                vals,
            )

        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Encrypted user data  (relationships blobs — alters use tables above)
# ---------------------------------------------------------------------------

def read_user_data(user_id: str, data_type: str) -> str | None:
    """
    Return the decrypted JSON string for the given user + data_type,
    or None if no record exists.

    * ``alters``        → read from wide ``alters`` table (one row per alter)
    * ``relationships`` → read from encrypted blob in ``user_data``
    """
    if data_type == "alters":
        conn = _get_db()
        try:
            alters = _reconstruct_all_alters(conn, user_id)
            if alters:
                return json.dumps(alters)

            # Fallback: check for an un-migrated blob still in user_data
            # (covers failed migrations or data written before the table existed)
            row = conn.execute(
                "SELECT nonce, ciphertext FROM user_data "
                "WHERE user_id = %s AND data_type = 'alters'",
                (user_id,),
            ).fetchone()
            if row:
                return decrypt(row["nonce"], row["ciphertext"]).decode("utf-8")

            return None
        finally:
            conn.close()

    # relationships (and any future blob types)
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT nonce, ciphertext FROM user_data "
            "WHERE user_id = %s AND data_type = %s",
            (user_id, data_type),
        ).fetchone()
        if row is None:
            return None
        plaintext = decrypt(row["nonce"], row["ciphertext"])
        return plaintext.decode("utf-8")
    finally:
        conn.close()


def write_user_data(user_id: str, data_type: str, json_bytes: bytes) -> None:
    """
    Encrypt and store user data.  Automatically creates a backup of the
    previous version and prunes old backups.

    * ``alters``        → written to wide ``alters`` table (one row per alter)
    * ``relationships`` → encrypted blob in ``user_data``
    """
    if data_type == "alters":
        _write_alters_to_table(user_id, json_bytes)
        return

    # relationships (and any future blob types)
    conn = _get_db()
    try:
        now = _now()
        ensure_user(conn, user_id)

        # Move current row into backups (if any)
        old = conn.execute(
            "SELECT nonce, ciphertext FROM user_data "
            "WHERE user_id = %s AND data_type = %s",
            (user_id, data_type),
        ).fetchone()
        if old:
            conn.execute(
                "INSERT INTO user_data_backups "
                "(user_id, data_type, nonce, ciphertext, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (user_id, data_type, old["nonce"], old["ciphertext"], now),
            )
            # Prune oldest backups beyond MAX_BACKUPS_PER_USER
            conn.execute(
                "DELETE FROM user_data_backups WHERE id IN ("
                "  SELECT id FROM user_data_backups "
                "  WHERE user_id = %s AND data_type = %s "
                "  ORDER BY created_at DESC "
                "  OFFSET %s"
                ")",
                (user_id, data_type, MAX_BACKUPS_PER_USER),
            )

        # Encrypt and upsert
        nonce, ct = encrypt(json_bytes)
        conn.execute(
            "INSERT INTO user_data (user_id, data_type, nonce, ciphertext, updated_at) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT(user_id, data_type) DO UPDATE SET "
            "  nonce = excluded.nonce, "
            "  ciphertext = excluded.ciphertext, "
            "  updated_at = excluded.updated_at",
            (user_id, data_type, nonce, ct, now),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Sharing  — create / resolve view-only links
# ---------------------------------------------------------------------------

def create_share(owner_id: str,
                 alters: list[dict] | None = None,
                 label: str = "",
                 expires_at: str | None = None) -> str:
    """
    Create a share link.  Returns the share_code.
    Label is encrypted at rest.

    *alters=None* means share ALL alters (scope='all').
    Pass a list of dicts with {"uuid": "...", "hidden_fields": ["Group1", ...]}
    to share only specific alters with per-alter privacy.
    """
    code = secrets.token_urlsafe(SHARE_CODE_LENGTH)
    scope = "all" if alters is None else "selected"
    conn = _get_db()
    try:
        ensure_user(conn, owner_id)
        ln, lc = _encrypt_field(label)
        conn.execute(
            "INSERT INTO shares "
            "(share_code, owner_id, label_nonce, label_cipher, share_scope, "
            " created_at, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (code, owner_id, ln, lc, scope, _now(), expires_at),
        )
        if alters:
            for a in alters:
                alter_uuid = a["uuid"]
                conn.execute(
                    "INSERT INTO share_alters (share_code, alter_uuid) "
                    "VALUES (%s, %s)",
                    (code, alter_uuid),
                )
                for group_name in a.get("hidden_fields", []):
                    if group_name:
                        conn.execute(
                            "INSERT INTO share_alter_hidden_groups "
                            "(share_code, alter_uuid, group_name) "
                            "VALUES (%s, %s, %s)",
                            (code, alter_uuid, group_name),
                        )
        conn.commit()
        return code
    finally:
        conn.close()


def resolve_share(share_code: str) -> dict | None:
    """
    Look up a share link.  Returns a dict with owner_id, owner_name, label,
    scope, alter_uuids, hidden_map, etc. — or None if invalid / expired.
    All user content is decrypted from encrypted storage.
    """
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT s.share_code, s.owner_id, "
            "       s.label_nonce, s.label_cipher, s.share_scope, "
            "       s.created_at, s.expires_at, s.is_active, "
            "       u.name_nonce AS owner_nn, u.name_cipher AS owner_nc "
            "FROM shares s "
            "LEFT JOIN users u ON s.owner_id = u.user_id "
            "WHERE s.share_code = %s AND s.is_active = TRUE",
            (share_code,),
        ).fetchone()
        if row is None:
            return None

        info = dict(row)
        # Decrypt label + owner_name
        info["label"] = _decrypt_field(
            info.pop("label_nonce", None), info.pop("label_cipher", None)
        )
        info["owner_name"] = _decrypt_field(
            info.pop("owner_nn", None), info.pop("owner_nc", None)
        )

        # Check expiry (handle both datetime objects and ISO strings)
        exp = info["expires_at"]
        if exp:
            now_dt = datetime.now(timezone.utc)
            if isinstance(exp, str):
                exp = datetime.fromisoformat(exp)
            if now_dt > exp:
                return None

        # Fetch selected alter UUIDs
        alter_rows = conn.execute(
            "SELECT alter_uuid FROM share_alters WHERE share_code = %s",
            (share_code,),
        ).fetchall()
        info["alter_uuids"] = [r["alter_uuid"] for r in alter_rows]

        # Fetch hidden groups per alter
        hidden_rows = conn.execute(
            "SELECT alter_uuid, group_name FROM share_alter_hidden_groups "
            "WHERE share_code = %s",
            (share_code,),
        ).fetchall()
        hidden_map: dict[str, list[str]] = {}
        for r in hidden_rows:
            hidden_map.setdefault(r["alter_uuid"], []).append(r["group_name"])
        info["hidden_map"] = hidden_map

        return _to_json_safe(info)
    finally:
        conn.close()


def get_shared_alters(share_code: str) -> list | None:
    """
    Decrypt the owner's alters and return only those included in the share.
    Strips groups marked as hidden per-alter privacy settings.
    Returns a list of alter dicts, or None if the share is invalid.
    """
    share = resolve_share(share_code)
    if share is None:
        return None

    raw = read_user_data(share["owner_id"], "alters")
    if raw is None:
        return []

    all_alters = json.loads(raw)

    if share["share_scope"] == "all":
        result = all_alters
    else:
        allowed = set(share["alter_uuids"])
        result = [a for a in all_alters if a.get("UUID") in allowed]

    # Strip hidden field groups per-alter
    hidden_map = share.get("hidden_map", {})
    for alter in result:
        hidden = set(hidden_map.get(alter.get("UUID", ""), []))
        for h in hidden:
            alter.pop(h, None)

    return result


def list_shares(owner_id: str) -> list[dict]:
    """Return all active shares for a user, with alter details and claim count.
    Labels and owner names are decrypted from encrypted storage."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT s.share_code, s.owner_id, "
            "       s.label_nonce, s.label_cipher, s.share_scope, "
            "       s.created_at, s.expires_at, s.is_active, "
            "       u.name_nonce AS owner_nn, u.name_cipher AS owner_nc "
            "FROM shares s "
            "LEFT JOIN users u ON s.owner_id = u.user_id "
            "WHERE s.owner_id = %s AND s.is_active = TRUE "
            "ORDER BY s.created_at DESC",
            (owner_id,),
        ).fetchall()
        result = []
        for row in rows:
            info = dict(row)
            info["label"] = _decrypt_field(
                info.pop("label_nonce", None), info.pop("label_cipher", None)
            )
            info["owner_name"] = _decrypt_field(
                info.pop("owner_nn", None), info.pop("owner_nc", None)
            )

            # Fetch alter UUIDs
            alter_rows = conn.execute(
                "SELECT alter_uuid FROM share_alters WHERE share_code = %s",
                (info["share_code"],),
            ).fetchall()

            # Fetch hidden groups per alter
            hidden_rows = conn.execute(
                "SELECT alter_uuid, group_name FROM share_alter_hidden_groups "
                "WHERE share_code = %s",
                (info["share_code"],),
            ).fetchall()
            hidden_map: dict[str, list[str]] = {}
            for hr in hidden_rows:
                hidden_map.setdefault(hr["alter_uuid"], []).append(hr["group_name"])

            info["alters"] = [
                {
                    "uuid": r["alter_uuid"],
                    "hidden_fields": hidden_map.get(r["alter_uuid"], []),
                }
                for r in alter_rows
            ]
            info["alter_uuids"] = [a["uuid"] for a in info["alters"]]

            # How many people claimed this share
            cnt = conn.execute(
                "SELECT COUNT(*) AS cnt FROM share_claims WHERE share_code = %s",
                (info["share_code"],),
            ).fetchone()["cnt"]
            info["claim_count"] = cnt
            result.append(_to_json_safe(info))
        return result
    finally:
        conn.close()


def revoke_share(owner_id: str, share_code: str) -> bool:
    """Deactivate a share link.  Returns True if it existed."""
    conn = _get_db()
    try:
        cur = conn.execute(
            "UPDATE shares SET is_active = FALSE "
            "WHERE share_code = %s AND owner_id = %s",
            (share_code, owner_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def claim_share(share_code: str, user_id: str) -> dict | None:
    """
    Claim a share code for the given user.
    Returns the share info dict or None if invalid.
    Prevents claiming your own share.
    """
    share = resolve_share(share_code)
    if share is None:
        return None
    if share["owner_id"] == user_id:
        return None  # can't claim your own share
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        conn.execute(
            "INSERT INTO share_claims (share_code, user_id, claimed_at) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT DO NOTHING",
            (share_code, user_id, _now()),
        )
        conn.commit()
        return share
    finally:
        conn.close()


def unclaim_share(share_code: str, user_id: str) -> bool:
    """Remove a claimed share from a user's shared tab."""
    conn = _get_db()
    try:
        cur = conn.execute(
            "DELETE FROM share_claims WHERE share_code = %s AND user_id = %s",
            (share_code, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_claimed_shares(user_id: str) -> list[dict]:
    """
    Return all shares that have been shared *with* this user, grouped by owner.
    Returns a list of {owner_id, owner_name, shares: [{share_code, label, ...}]}.
    All user content is decrypted from encrypted storage.
    """
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT s.share_code, s.owner_id, "
            "       u.name_nonce AS owner_nn, u.name_cipher AS owner_nc, "
            "       s.label_nonce, s.label_cipher, "
            "       s.share_scope, s.created_at, sc.claimed_at "
            "FROM share_claims sc "
            "JOIN shares s ON sc.share_code = s.share_code "
            "LEFT JOIN users u ON s.owner_id = u.user_id "
            "WHERE sc.user_id = %s AND s.is_active = TRUE "
            "ORDER BY sc.claimed_at DESC",
            (user_id,),
        ).fetchall()

        # Group by owner
        owners: dict[str, dict] = {}
        for row in rows:
            r = dict(row)
            oid = r["owner_id"]
            owner_name = _decrypt_field(
                r.get("owner_nn"), r.get("owner_nc")
            )
            label = _decrypt_field(
                r.get("label_nonce"), r.get("label_cipher")
            )
            if oid not in owners:
                owners[oid] = {
                    "owner_id": oid,
                    "owner_name": owner_name or oid[:8],
                    "shares": [],
                }
            owners[oid]["shares"].append({
                "share_code": r["share_code"],
                "label": label,
                "share_scope": r["share_scope"],
                "created_at": r["created_at"],
                "claimed_at": r["claimed_at"],
            })
        return _to_json_safe(list(owners.values()))
    finally:
        conn.close()


def get_share_owner_info(share_code: str) -> dict | None:
    """Return basic info about the share owner for display.
    All user content is decrypted from encrypted storage."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT s.owner_id, "
            "       u.name_nonce AS owner_nn, u.name_cipher AS owner_nc, "
            "       s.label_nonce, s.label_cipher "
            "FROM shares s "
            "LEFT JOIN users u ON s.owner_id = u.user_id "
            "WHERE s.share_code = %s AND s.is_active = TRUE",
            (share_code,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["owner_name"] = _decrypt_field(
            d.pop("owner_nn", None), d.pop("owner_nc", None)
        )
        d["label"] = _decrypt_field(
            d.pop("label_nonce", None), d.pop("label_cipher", None)
        )
        return _to_json_safe(d)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Friends
# ---------------------------------------------------------------------------

FRIEND_CODE_LENGTH = 8
_FRIEND_CODE_CHARS = string.ascii_uppercase + string.digits


def _generate_friend_code() -> str:
    """Generate a unique friend code like 'A3K9M2XP'."""
    return "".join(secrets.choice(_FRIEND_CODE_CHARS) for _ in range(FRIEND_CODE_LENGTH))


def get_or_create_friend_code(user_id: str) -> str:
    """Return the user's friend code, creating one if it doesn't exist."""
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        row = conn.execute(
            "SELECT friend_code FROM users WHERE user_id = %s", (user_id,)
        ).fetchone()
        if row and row["friend_code"]:
            return row["friend_code"]

        # Generate a unique code
        for _ in range(100):
            code = _generate_friend_code()
            try:
                conn.execute(
                    "UPDATE users SET friend_code = %s, updated_at = %s WHERE user_id = %s",
                    (code, _now(), user_id),
                )
                conn.commit()
                return code
            except psycopg.errors.UniqueViolation:
                conn.rollback()  # PG requires rollback after error
                continue  # collision, retry
        raise RuntimeError("Failed to generate unique friend code")
    finally:
        conn.close()


def lookup_user_by_friend_code(friend_code: str) -> dict | None:
    """Find a user by their friend code. Returns user dict or None.
    Display name is decrypted from encrypted storage."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT user_id, name_nonce, name_cipher, friend_code "
            "FROM users WHERE friend_code = %s",
            (friend_code.upper().strip(),),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["display_name"] = _decrypt_field(
            d.pop("name_nonce", None), d.pop("name_cipher", None)
        )
        d["profile"] = _get_profile_dict(conn, d["user_id"])
        return _to_json_safe(d)
    finally:
        conn.close()


def send_friend_request(from_user: str, to_user: str, message: str = "") -> dict:
    """Send a friend request. Message is encrypted at rest. Returns the request dict."""
    if from_user == to_user:
        raise ValueError("Cannot friend yourself")

    conn = _get_db()
    try:
        # Check if already friends
        existing = conn.execute(
            "SELECT 1 FROM friendships WHERE user_id = %s AND friend_id = %s",
            (from_user, to_user),
        ).fetchone()
        if existing:
            raise ValueError("Already friends")

        # Check if there's already a pending request either direction
        pending = conn.execute(
            "SELECT id, from_user, status FROM friend_requests "
            "WHERE ((from_user = %s AND to_user = %s) OR (from_user = %s AND to_user = %s)) "
            "AND status = 'pending'",
            (from_user, to_user, to_user, from_user),
        ).fetchone()

        if pending:
            p = dict(pending)
            # If they sent us a request, auto-accept it
            if p["from_user"] == to_user:
                return _accept_friend_request_inner(conn, p["id"], to_user, from_user)
            raise ValueError("Friend request already pending")

        now = _now()
        # Remove any old non-pending requests so the UNIQUE constraint
        # doesn't block a fresh request
        conn.execute(
            "DELETE FROM friend_requests "
            "WHERE from_user = %s AND to_user = %s AND status != 'pending'",
            (from_user, to_user),
        )
        mn, mc = _encrypt_field(message)
        conn.execute(
            "INSERT INTO friend_requests "
            "(from_user, to_user, msg_nonce, msg_cipher, status, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, 'pending', %s, %s)",
            (from_user, to_user, mn, mc, now, now),
        )
        conn.commit()
        return {"status": "pending", "message": "Friend request sent"}
    finally:
        conn.close()


def _accept_friend_request_inner(conn, request_id: int,
                                  from_user: str, accepting_user: str) -> dict:
    """Accept a friend request (inner, uses existing connection)."""
    now = _now()
    conn.execute(
        "UPDATE friend_requests SET status = 'accepted', updated_at = %s WHERE id = %s",
        (now, request_id),
    )
    # Create bidirectional friendship
    conn.execute(
        "INSERT INTO friendships (user_id, friend_id, created_at) VALUES (%s, %s, %s) "
        "ON CONFLICT DO NOTHING",
        (from_user, accepting_user, now),
    )
    conn.execute(
        "INSERT INTO friendships (user_id, friend_id, created_at) VALUES (%s, %s, %s) "
        "ON CONFLICT DO NOTHING",
        (accepting_user, from_user, now),
    )
    conn.commit()
    return {"status": "accepted", "message": "Friend request accepted"}


def respond_friend_request(request_id: int, user_id: str, accept: bool) -> dict:
    """Accept or decline a friend request. user_id must be the recipient."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM friend_requests WHERE id = %s AND to_user = %s AND status = 'pending'",
            (request_id, user_id),
        ).fetchone()
        if not row:
            raise ValueError("Request not found or already handled")
        req = dict(row)

        if accept:
            return _accept_friend_request_inner(conn, request_id, req["from_user"], user_id)
        else:
            conn.execute(
                "UPDATE friend_requests SET status = 'declined', updated_at = %s WHERE id = %s",
                (_now(), request_id),
            )
            conn.commit()
            return {"status": "declined", "message": "Friend request declined"}
    finally:
        conn.close()


def cancel_friend_request(request_id: int, user_id: str) -> bool:
    """Cancel a friend request you sent."""
    conn = _get_db()
    try:
        cur = conn.execute(
            "UPDATE friend_requests SET status = 'cancelled', updated_at = %s "
            "WHERE id = %s AND from_user = %s AND status = 'pending'",
            (_now(), request_id, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_friend_requests(user_id: str) -> dict:
    """Return incoming and outgoing pending friend requests.
    All user content is decrypted from encrypted storage."""
    conn = _get_db()
    try:
        incoming = conn.execute(
            "SELECT fr.id, fr.from_user, fr.msg_nonce, fr.msg_cipher, "
            "       fr.created_at, "
            "       u.name_nonce AS u_nn, u.name_cipher AS u_nc, "
            "       u.friend_code, u.avatar_url "
            "FROM friend_requests fr "
            "LEFT JOIN users u ON u.user_id = fr.from_user "
            "WHERE fr.to_user = %s AND fr.status = 'pending' "
            "ORDER BY fr.created_at DESC",
            (user_id,),
        ).fetchall()

        incoming_list = []
        for r in incoming:
            d = dict(r)
            d["message"] = _decrypt_field(
                d.pop("msg_nonce", None), d.pop("msg_cipher", None)
            )
            d["display_name"] = _decrypt_field(
                d.pop("u_nn", None), d.pop("u_nc", None)
            )
            d["profile"] = _get_profile_dict(conn, d["from_user"])
            incoming_list.append(d)

        outgoing = conn.execute(
            "SELECT fr.id, fr.to_user, fr.msg_nonce, fr.msg_cipher, "
            "       fr.created_at, "
            "       u.name_nonce AS u_nn, u.name_cipher AS u_nc, "
            "       u.friend_code, u.avatar_url "
            "FROM friend_requests fr "
            "LEFT JOIN users u ON u.user_id = fr.to_user "
            "WHERE fr.from_user = %s AND fr.status = 'pending' "
            "ORDER BY fr.created_at DESC",
            (user_id,),
        ).fetchall()

        outgoing_list = []
        for r in outgoing:
            d = dict(r)
            d["message"] = _decrypt_field(
                d.pop("msg_nonce", None), d.pop("msg_cipher", None)
            )
            d["display_name"] = _decrypt_field(
                d.pop("u_nn", None), d.pop("u_nc", None)
            )
            d["profile"] = _get_profile_dict(conn, d["to_user"])
            outgoing_list.append(d)

        return _to_json_safe({
            "incoming": incoming_list,
            "outgoing": outgoing_list,
        })
    finally:
        conn.close()


def get_friends(user_id: str) -> list[dict]:
    """Return list of friends with their profile info.
    All user content is decrypted from encrypted storage."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT f.friend_id, f.created_at AS friends_since, "
            "       u.name_nonce, u.name_cipher, u.friend_code, u.avatar_url "
            "FROM friendships f "
            "LEFT JOIN users u ON u.user_id = f.friend_id "
            "WHERE f.user_id = %s",
            (user_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["display_name"] = _decrypt_field(
                d.pop("name_nonce", None), d.pop("name_cipher", None)
            )
            d["profile"] = _get_profile_dict(conn, d["friend_id"])
            result.append(d)
        # Sort by display_name in Python (can't ORDER BY encrypted column)
        result.sort(key=lambda x: (
            (x.get("display_name") or "").lower(),
            x.get("friends_since", ""),
        ))
        return _to_json_safe(result)
    finally:
        conn.close()


def remove_friend(user_id: str, friend_id: str) -> bool:
    """Remove a friendship (both directions) and all related shares.
    CASCADE on foreign keys cleans up hidden_groups tables automatically."""
    conn = _get_db()
    try:
        # Remove friendship rows (both directions)
        conn.execute(
            "DELETE FROM friendships WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        )
        conn.execute(
            "DELETE FROM friendships WHERE user_id = %s AND friend_id = %s",
            (friend_id, user_id),
        )
        # Remove friend shares both directions (CASCADE cleans hidden_groups)
        conn.execute(
            "DELETE FROM friend_shares WHERE (user_id = %s AND friend_id = %s) "
            "OR (user_id = %s AND friend_id = %s)",
            (user_id, friend_id, friend_id, user_id),
        )
        # Remove fronting shares both directions (CASCADE cleans hidden_groups)
        conn.execute(
            "DELETE FROM fronting_shares WHERE (user_id = %s AND friend_id = %s) "
            "OR (user_id = %s AND friend_id = %s)",
            (user_id, friend_id, friend_id, user_id),
        )
        # Remove any friend request history between the two users
        conn.execute(
            "DELETE FROM friend_requests "
            "WHERE (from_user = %s AND to_user = %s) "
            "OR (from_user = %s AND to_user = %s)",
            (user_id, friend_id, friend_id, user_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def update_friend_shares(user_id: str, friend_id: str,
                          alters: list[dict]) -> None:
    """
    Update what alters a user shares with a friend.
    alters: list of {uuid, hidden_fields: [group_names]}
    Pass an empty list to stop sharing.
    CASCADE deletes hidden groups when parent rows are removed.
    """
    conn = _get_db()
    try:
        # Verify friendship exists
        f = conn.execute(
            "SELECT 1 FROM friendships WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        ).fetchone()
        if not f:
            raise ValueError("Not friends")

        # Clear existing shares for this pair (CASCADE cleans hidden groups)
        conn.execute(
            "DELETE FROM friend_shares WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        )
        # Insert new shares + hidden groups
        if alters:
            for a in alters:
                alter_uuid = a["uuid"]
                conn.execute(
                    "INSERT INTO friend_shares (user_id, friend_id, alter_uuid) "
                    "VALUES (%s, %s, %s)",
                    (user_id, friend_id, alter_uuid),
                )
                for group_name in a.get("hidden_fields", []):
                    if group_name:
                        conn.execute(
                            "INSERT INTO friend_share_hidden_groups "
                            "(user_id, friend_id, alter_uuid, group_name) "
                            "VALUES (%s, %s, %s, %s)",
                            (user_id, friend_id, alter_uuid, group_name),
                        )
        conn.commit()
    finally:
        conn.close()


def get_friend_shared_alters(user_id: str, friend_id: str) -> list[dict] | None:
    """
    Get alters that friend_id has shared with user_id.
    Decrypts the friend's data and returns privacy-filtered alters.
    Returns list of alter dicts, or None if not friends.
    """
    conn = _get_db()
    try:
        # Verify friendship
        f = conn.execute(
            "SELECT 1 FROM friendships WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        ).fetchone()
        if not f:
            return None

        # Get what friend shared with us
        share_rows = conn.execute(
            "SELECT alter_uuid FROM friend_shares "
            "WHERE user_id = %s AND friend_id = %s",
            (friend_id, user_id),
        ).fetchall()

        if not share_rows:
            return []

        allowed = {r["alter_uuid"] for r in share_rows}

        # Fetch hidden groups per alter
        hidden_rows = conn.execute(
            "SELECT alter_uuid, group_name FROM friend_share_hidden_groups "
            "WHERE user_id = %s AND friend_id = %s",
            (friend_id, user_id),
        ).fetchall()
        hidden_map: dict[str, list[str]] = {}
        for r in hidden_rows:
            hidden_map.setdefault(r["alter_uuid"], []).append(r["group_name"])
    finally:
        conn.close()

    # Read friend's alter data (decrypted)
    raw = read_user_data(friend_id, "alters")
    if raw is None:
        return []

    all_alters = json.loads(raw)
    result = [a for a in all_alters if a.get("UUID") in allowed]

    # Strip hidden fields per alter
    for alter in result:
        hidden = set(hidden_map.get(alter.get("UUID", ""), []))
        for h in hidden:
            alter.pop(h, None)

    return result


def get_my_shares_to_friend(user_id: str, friend_id: str) -> list[dict]:
    """Return what alters I'm sharing with a specific friend."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT alter_uuid FROM friend_shares "
            "WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        ).fetchall()

        result = []
        for r in rows:
            hidden_rows = conn.execute(
                "SELECT group_name FROM friend_share_hidden_groups "
                "WHERE user_id = %s AND friend_id = %s AND alter_uuid = %s",
                (user_id, friend_id, r["alter_uuid"]),
            ).fetchall()
            result.append({
                "uuid": r["alter_uuid"],
                "hidden_fields": [hr["group_name"] for hr in hidden_rows],
            })
        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Fronting sharing (share your live fronting status with friends)
# ---------------------------------------------------------------------------

def set_fronting_share(user_id: str, friend_id: str,
                       enabled: bool, hidden_fields: list[str] | None = None) -> None:
    """Enable or disable sharing your fronting status with a specific friend.
    When enabled, the friend can see which of your alters are currently fronting.
    hidden_fields applies to ALL shown alters (since you don't choose which appear).
    Hidden groups stored in a normalized junction table (3NF).
    """
    conn = _get_db()
    try:
        # Verify friendship
        f = conn.execute(
            "SELECT 1 FROM friendships WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        ).fetchone()
        if not f:
            raise ValueError("Not friends")

        if enabled:
            conn.execute(
                "INSERT INTO fronting_shares (user_id, friend_id) "
                "VALUES (%s, %s) "
                "ON CONFLICT DO NOTHING",
                (user_id, friend_id),
            )
            # Replace hidden groups
            conn.execute(
                "DELETE FROM fronting_share_hidden_groups "
                "WHERE user_id = %s AND friend_id = %s",
                (user_id, friend_id),
            )
            for g in (hidden_fields or []):
                if g:
                    conn.execute(
                        "INSERT INTO fronting_share_hidden_groups "
                        "(user_id, friend_id, group_name) VALUES (%s, %s, %s)",
                        (user_id, friend_id, g),
                    )
        else:
            # CASCADE will clean up hidden groups
            conn.execute(
                "DELETE FROM fronting_shares WHERE user_id = %s AND friend_id = %s",
                (user_id, friend_id),
            )
        conn.commit()
    finally:
        conn.close()


def get_fronting_share_settings(user_id: str, friend_id: str) -> dict | None:
    """Return fronting share settings for user_id → friend_id, or None if not sharing."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT 1 FROM fronting_shares "
            "WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        ).fetchone()
        if not row:
            return None

        hidden_rows = conn.execute(
            "SELECT group_name FROM fronting_share_hidden_groups "
            "WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        ).fetchall()

        return {
            "enabled": True,
            "hidden_fields": [r["group_name"] for r in hidden_rows],
        }
    finally:
        conn.close()


def get_friend_fronting(user_id: str, friend_id: str) -> dict | None:
    """
    Get the fronting alters of friend_id, if they've shared fronting with user_id.
    Returns {fronting: [{alter data}], hidden_fields: [...]} or None if not shared.
    """
    conn = _get_db()
    try:
        # Verify friendship
        f = conn.execute(
            "SELECT 1 FROM friendships WHERE user_id = %s AND friend_id = %s",
            (user_id, friend_id),
        ).fetchone()
        if not f:
            return None

        # Check if friend is sharing fronting with us
        share = conn.execute(
            "SELECT 1 FROM fronting_shares "
            "WHERE user_id = %s AND friend_id = %s",
            (friend_id, user_id),
        ).fetchone()
        if not share:
            return None

        # Fetch hidden groups
        hidden_rows = conn.execute(
            "SELECT group_name FROM fronting_share_hidden_groups "
            "WHERE user_id = %s AND friend_id = %s",
            (friend_id, user_id),
        ).fetchall()
        hidden = [r["group_name"] for r in hidden_rows]

        # Get friend's currently fronting alters
        fronting_rows = conn.execute(
            "SELECT alter_uuid, role FROM fronting WHERE user_id = %s "
            "ORDER BY CASE role WHEN 'primary' THEN 0 ELSE 1 END, set_at",
            (friend_id,),
        ).fetchall()
    finally:
        conn.close()

    if not fronting_rows:
        return {"fronting": [], "hidden_fields": hidden}

    fronting_uuids = {r["alter_uuid"]: r["role"] for r in fronting_rows}

    # Read friend's alter data (decrypted)
    raw = read_user_data(friend_id, "alters")
    if raw is None:
        return {"fronting": [], "hidden_fields": hidden}

    all_alters = json.loads(raw)
    result = []
    for alter in all_alters:
        uuid = alter.get("UUID", "")
        if uuid in fronting_uuids:
            # Strip hidden fields from ALL fronting alters
            for h in hidden:
                alter.pop(h, None)
            alter["_fronting_role"] = fronting_uuids[uuid]
            result.append(alter)

    return {"fronting": result, "hidden_fields": hidden}


def get_user_profile(user_id: str) -> dict:
    """Return the user's profile data as a dict.
    Display name and profile values are decrypted from encrypted storage."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT name_nonce, name_cipher FROM users WHERE user_id = %s",
            (user_id,),
        ).fetchone()
        if not row:
            return {}
        profile = _get_profile_dict(conn, user_id)
        profile["display_name"] = _decrypt_field(
            row["name_nonce"], row["name_cipher"]
        )
        return profile
    finally:
        conn.close()


def update_user_profile(user_id: str, profile: dict) -> None:
    """Update the user's profile data.
    Display name and profile values are encrypted at rest.
    Handles both the wide table and the legacy EAV table transparently."""
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        display_name = profile.pop("display_name", None)
        now = _now()
        up_cols = _get_columns(conn, "user_profiles")

        # Delete existing rows for this user
        conn.execute(
            "DELETE FROM user_profiles WHERE user_id = %s", (user_id,)
        )

        if "field_name" not in up_cols:
            # ── Wide table (current schema) ───────────────────────────
            cols = ["user_id"]
            vals: list = [user_id]
            for json_key, value in profile.items():
                col_prefix = _PROFILE_JSON_TO_COL.get(json_key)
                if col_prefix and value:
                    vn, vc = _encrypt_field(str(value))
                    cols.extend([f"{col_prefix}_nonce", f"{col_prefix}_cipher"])
                    vals.extend([vn, vc])
            ph = ", ".join(["%s"] * len(vals))
            conn.execute(
                f"INSERT INTO user_profiles ({', '.join(cols)}) VALUES ({ph})",
                vals,
            )
        else:
            # ── Legacy EAV table (pre-migration fallback) ─────────────
            for key, value in profile.items():
                if value:
                    vn, vc = _encrypt_field(str(value))
                    conn.execute(
                        "INSERT INTO user_profiles "
                        "(user_id, field_name, value_nonce, value_cipher) "
                        "VALUES (%s, %s, %s, %s)",
                        (user_id, key, vn, vc),
                    )

        conn.execute(
            "UPDATE users SET updated_at = %s WHERE user_id = %s",
            (now, user_id),
        )
        if display_name is not None:
            nn, nc = _encrypt_field(display_name)
            conn.execute(
                "UPDATE users SET name_nonce = %s, name_cipher = %s "
                "WHERE user_id = %s",
                (nn, nc, user_id),
            )
        conn.commit()
    finally:
        conn.close()


def get_friend_poll_counts(user_id: str) -> dict:
    """Return counts for polling: incoming requests, outgoing requests, friends."""
    conn = _get_db()
    try:
        inc = conn.execute(
            "SELECT COUNT(*) AS cnt FROM friend_requests "
            "WHERE to_user = %s AND status = 'pending'",
            (user_id,),
        ).fetchone()
        out = conn.execute(
            "SELECT COUNT(*) AS cnt FROM friend_requests "
            "WHERE from_user = %s AND status = 'pending'",
            (user_id,),
        ).fetchone()
        fri = conn.execute(
            "SELECT COUNT(*) AS cnt FROM friendships WHERE user_id = %s",
            (user_id,),
        ).fetchone()
        return {
            "incoming": inc["cnt"] if inc else 0,
            "outgoing": out["cnt"] if out else 0,
            "friends":  fri["cnt"] if fri else 0,
        }
    finally:
        conn.close()


def sync_avatar_url(user_id: str, avatar_url: str) -> None:
    """Store the user's avatar URL (e.g. from Clerk)."""
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        conn.execute(
            "UPDATE users SET avatar_url = %s, updated_at = %s WHERE user_id = %s",
            (avatar_url or "", _now(), user_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_friend_names(user_id: str) -> list[dict]:
    """Return minimal info for all friends (for the alter relationship picker).
    Display names are decrypted from encrypted storage."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT f.friend_id, u.name_nonce, u.name_cipher "
            "FROM friendships f "
            "LEFT JOIN users u ON u.user_id = f.friend_id "
            "WHERE f.user_id = %s",
            (user_id,),
        ).fetchall()
        result = []
        for r in rows:
            name = _decrypt_field(r["name_nonce"], r["name_cipher"])
            if not name:
                profile = _get_profile_dict(conn, r["friend_id"])
                name = profile.get("Name", "") or profile.get("display_name", "")
            result.append({"friend_id": r["friend_id"], "name": name or "Unknown"})
        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Fronting
# ---------------------------------------------------------------------------

def get_fronting(user_id: str) -> list[dict]:
    """Return the currently-fronting alter UUIDs + metadata for a user.
    Ordered: primary first, then secondary by set_at."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM fronting WHERE user_id = %s "
            "ORDER BY CASE role WHEN 'primary' THEN 0 ELSE 1 END, set_at",
            (user_id,),
        ).fetchall()
        return [_to_json_safe(dict(r)) for r in rows]
    finally:
        conn.close()


def get_primary_fronting(user_id: str) -> dict | None:
    """Return the primary fronting alter, or None."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM fronting WHERE user_id = %s AND role = 'primary'",
            (user_id,),
        ).fetchone()
        return _to_json_safe(dict(row)) if row else None
    finally:
        conn.close()


def set_fronting(user_id: str, alter_uuid: str, via: str = "site") -> None:
    """
    Set a single alter as fronting (clears previous).
    The alter is set as primary.
    Use add_fronting() for co-fronting.
    """
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        conn.execute("DELETE FROM fronting WHERE user_id = %s", (user_id,))
        conn.execute(
            "INSERT INTO fronting (user_id, alter_uuid, role, set_at, set_via) "
            "VALUES (%s, %s, 'primary', %s, %s)",
            (user_id, alter_uuid, _now(), via),
        )
        conn.commit()
    finally:
        conn.close()


def add_fronting(user_id: str, alter_uuid: str, via: str = "site",
                 role: str = "secondary") -> None:
    """Add an alter to the fronting list.
    role: 'primary' or 'secondary'.
    If role='primary', demotes any existing primary to secondary first.
    """
    if role not in ("primary", "secondary"):
        role = "secondary"
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        if role == "primary":
            # Demote any existing primary to secondary
            conn.execute(
                "UPDATE fronting SET role = 'secondary' "
                "WHERE user_id = %s AND role = 'primary'",
                (user_id,),
            )
        conn.execute(
            "INSERT INTO fronting (user_id, alter_uuid, role, set_at, set_via) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT(user_id, alter_uuid) DO UPDATE SET "
            "  role = excluded.role, set_at = excluded.set_at, set_via = excluded.set_via",
            (user_id, alter_uuid, role, _now(), via),
        )
        conn.commit()
    finally:
        conn.close()


def set_fronting_role(user_id: str, alter_uuid: str, role: str) -> None:
    """Change the role of an existing fronting alter.
    If promoting to primary, demotes the current primary to secondary.
    """
    if role not in ("primary", "secondary"):
        return
    conn = _get_db()
    try:
        if role == "primary":
            conn.execute(
                "UPDATE fronting SET role = 'secondary' "
                "WHERE user_id = %s AND role = 'primary'",
                (user_id,),
            )
        conn.execute(
            "UPDATE fronting SET role = %s WHERE user_id = %s AND alter_uuid = %s",
            (role, user_id, alter_uuid),
        )
        conn.commit()
    finally:
        conn.close()


def remove_fronting(user_id: str, alter_uuid: str) -> None:
    """Remove one alter from the fronting list."""
    conn = _get_db()
    try:
        conn.execute(
            "DELETE FROM fronting WHERE user_id = %s AND alter_uuid = %s",
            (user_id, alter_uuid),
        )
        conn.commit()
    finally:
        conn.close()


def clear_fronting(user_id: str) -> None:
    """Clear all fronting alters."""
    conn = _get_db()
    try:
        conn.execute("DELETE FROM fronting WHERE user_id = %s", (user_id,))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Discord link codes  — short-lived codes for account linking
# ---------------------------------------------------------------------------

def generate_link_code(user_id: str) -> str:
    """
    Create a 6-character alphanumeric code for linking Discord.
    Returns the code.  Code expires in LINK_CODE_TTL_MINUTES.
    """
    # Clean up expired codes first
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        now = _now()
        conn.execute("DELETE FROM link_codes WHERE expires_at < %s", (now,))
        # Remove any existing codes for this user
        conn.execute("DELETE FROM link_codes WHERE user_id = %s", (user_id,))

        code = "".join(
            secrets.choice(string.ascii_uppercase + string.digits)
            for _ in range(LINK_CODE_LENGTH)
        )
        expires = (
            datetime.now(timezone.utc) + timedelta(minutes=LINK_CODE_TTL_MINUTES)
        ).isoformat()

        conn.execute(
            "INSERT INTO link_codes (code, user_id, created_at, expires_at) "
            "VALUES (%s, %s, %s, %s)",
            (code, user_id, now, expires),
        )
        conn.commit()
        return code
    finally:
        conn.close()


def redeem_link_code(code: str, discord_id: str) -> str | None:
    """
    Attempt to redeem a link code.  On success, links the Discord ID to
    the Clerk user and returns the user_id.  Returns None if the code
    is invalid or expired.
    """
    conn = _get_db()
    try:
        now = _now()
        row = conn.execute(
            "SELECT * FROM link_codes WHERE code = %s AND expires_at > %s",
            (code.upper().strip(), now),
        ).fetchone()
        if row is None:
            return None

        user_id = row["user_id"]
        # Link the accounts (via user_discord_settings)
        conn.execute(
            "INSERT INTO user_discord_settings (user_id, discord_id) "
            "VALUES (%s, %s) "
            "ON CONFLICT(user_id) DO UPDATE SET discord_id = excluded.discord_id",
            (user_id, str(discord_id)),
        )
        conn.execute(
            "UPDATE users SET updated_at = %s WHERE user_id = %s",
            (now, user_id),
        )
        # Delete the used code
        conn.execute("DELETE FROM link_codes WHERE code = %s", (code.upper().strip(),))
        conn.commit()
        return user_id
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Discord Bot — proxy configuration (prefix/suffix encrypted at rest)
# ---------------------------------------------------------------------------

def set_proxy(user_id: str, alter_uuid: str,
              prefix: str = "", suffix: str = "") -> None:
    """Create or update a Discord proxy trigger for an alter.
    Prefix and suffix are encrypted at rest."""
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        pn, pc = _encrypt_field(prefix)
        sn, sc = _encrypt_field(suffix)
        conn.execute(
            "INSERT INTO discord_proxies "
            "(user_id, alter_uuid, prefix_nonce, prefix_cipher, "
            " suffix_nonce, suffix_cipher) "
            "VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT(user_id, alter_uuid) DO UPDATE SET "
            "  prefix_nonce = excluded.prefix_nonce, "
            "  prefix_cipher = excluded.prefix_cipher, "
            "  suffix_nonce = excluded.suffix_nonce, "
            "  suffix_cipher = excluded.suffix_cipher, "
            "  is_active = TRUE",
            (user_id, alter_uuid, pn, pc, sn, sc),
        )
        conn.commit()
    finally:
        conn.close()


def get_proxies(user_id: str) -> list[dict]:
    """Return all active proxy triggers for a user.
    Prefix and suffix are decrypted from encrypted storage."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM discord_proxies "
            "WHERE user_id = %s AND is_active = TRUE",
            (user_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["prefix"] = _decrypt_field(
                d.pop("prefix_nonce", None), d.pop("prefix_cipher", None)
            )
            d["suffix"] = _decrypt_field(
                d.pop("suffix_nonce", None), d.pop("suffix_cipher", None)
            )
            result.append(d)
        return result
    finally:
        conn.close()


def match_proxy(discord_id: str, message: str) -> dict | None:
    """
    Given a Discord user's message, check if it matches any proxy trigger
    or should be auto-proxied as the fronting alter.

    Returns {'user_id', 'alter_uuid', 'content'} or None.

    Logic:
      1. If proxy_enabled is True, check prefix/suffix triggers first.
         First match wins.
      2. If autoproxy_enabled is True AND no trigger matched, proxy the
         whole message as the primary (highest) fronting alter.
      3. Otherwise return None (no proxying).
    """
    user = get_user_by_discord(discord_id)
    if user is None:
        return None

    proxy_on = bool(user.get("proxy_enabled"))
    autoproxy_on = bool(user.get("autoproxy_enabled"))

    # Nothing enabled → skip entirely
    if not proxy_on and not autoproxy_on:
        return None

    # 1. Trigger-based proxy (requires proxy_enabled)
    if proxy_on:
        proxies = get_proxies(user["user_id"])
        for p in proxies:
            px, sx = p["prefix"], p["suffix"]
            if px and message.startswith(px):
                return {
                    "user_id": user["user_id"],
                    "alter_uuid": p["alter_uuid"],
                    "content": message[len(px):].strip(),
                }
            if sx and message.endswith(sx):
                return {
                    "user_id": user["user_id"],
                    "alter_uuid": p["alter_uuid"],
                    "content": message[:-len(sx)].strip(),
                }

    # 2. Auto-proxy fallback (requires autoproxy_enabled)
    if autoproxy_on:
        primary = get_primary_fronting(user["user_id"])
        if primary:
            return {
                "user_id": user["user_id"],
                "alter_uuid": primary["alter_uuid"],
                "content": message,
            }

    return None


def get_alter_info(user_id: str, alter_uuid: str) -> dict | None:
    """
    Return a single alter dict for *alter_uuid*, or None.
    Queries the wide ``alters`` table directly (no need to load the whole
    list).
    """
    conn = _get_db()
    try:
        return _reconstruct_alter(conn, user_id, alter_uuid)
    finally:
        conn.close()


def extract_alter_name(alter: dict) -> str:
    """
    Extract the display name from a raw alter dict.
    Name is stored inside group arrays, e.g.:
      "Basic Info": [{"Name": "Zion"}, {"Age": "25"}, ...]
    """
    for group_key in ("Basic Info", "System Info", "Identity"):
        group = alter.get(group_key, [])
        if isinstance(group, list):
            for field in group:
                if isinstance(field, dict) and "Name" in field:
                    name = str(field["Name"]).strip()
                    if name:
                        return name
    # Fallback: check top-level (some formats)
    if alter.get("Name"):
        return str(alter["Name"]).strip()
    return "Unnamed"


def get_all_alters(user_id: str) -> list[dict]:
    """Return all decrypted alters for a user (used by bot for dropdown)."""
    conn = _get_db()
    try:
        return _reconstruct_all_alters(conn, user_id)
    except Exception:
        return []
    finally:
        conn.close()


def remove_proxy(user_id: str, alter_uuid: str) -> bool:
    """Deactivate a proxy trigger."""
    conn = _get_db()
    try:
        cur = conn.execute(
            "UPDATE discord_proxies SET is_active = FALSE "
            "WHERE user_id = %s AND alter_uuid = %s",
            (user_id, alter_uuid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
#  Journal  (title + body + tags all encrypted at rest)
# ---------------------------------------------------------------------------

MAX_JOURNAL_ENTRIES = 500  # per user


def create_journal_entry(user_id: str, alter_uuid: str = "",
                         title: str = "", body: str = "",
                         tags: list[str] | None = None,
                         via: str = "site") -> dict:
    """Create a new journal entry.  Title and body are encrypted at rest.
    Tags are per-user encrypted in journal_tags + journal_entry_tags tables.
    Returns the new entry dict (with decrypted body)."""
    conn = _get_db()
    try:
        ensure_user(conn, user_id)
        now = _now()
        title_nonce, title_cipher = _encrypt_field(title)
        body_nonce = body_cipher = None
        if body:
            body_nonce, body_cipher = encrypt(body.encode("utf-8"))
        cur = conn.execute(
            "INSERT INTO journal_entries "
            "(user_id, alter_uuid, title_nonce, title_cipher, "
            " body_nonce, body_cipher, created_at, updated_at, via) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (user_id, alter_uuid or "", title_nonce, title_cipher,
             body_nonce, body_cipher, now, now, via),
        )
        entry_id = cur.fetchone()["id"]

        # Handle tags via per-user encrypted junction table
        clean_tags = tags or []
        if clean_tags:
            tag_ids = _ensure_tags(conn, user_id, clean_tags)
            _set_entry_tags(conn, entry_id, tag_ids)

        conn.commit()
        return {
            "id": entry_id,
            "alter_uuid": alter_uuid or "",
            "title": title,
            "body": body,
            "tags": clean_tags,
            "created_at": now,
            "updated_at": now,
            "via": via,
        }
    finally:
        conn.close()


def update_journal_entry(user_id: str, entry_id: int,
                         title: str | None = None,
                         body: str | None = None,
                         tags: list[str] | None = None) -> dict | None:
    """Update an existing journal entry.  Returns updated dict or None.
    Title and body are encrypted at rest."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM journal_entries WHERE id = %s AND user_id = %s",
            (entry_id, user_id),
        ).fetchone()
        if not row:
            return None

        now = _now()
        updates = ["updated_at = %s"]
        params: list = [now]

        if title is not None:
            tn, tc = _encrypt_field(title)
            updates.append("title_nonce = %s")
            params.append(tn)
            updates.append("title_cipher = %s")
            params.append(tc)
        if body is not None:
            if body:
                bn, bc = encrypt(body.encode("utf-8"))
                updates.append("body_nonce = %s")
                params.append(bn)
                updates.append("body_cipher = %s")
                params.append(bc)
            else:
                updates.append("body_nonce = NULL")
                updates.append("body_cipher = NULL")
        if tags is not None:
            # Update tags via per-user encrypted junction table
            tag_ids = _ensure_tags(conn, user_id, tags)
            _set_entry_tags(conn, entry_id, tag_ids)

        params.extend([entry_id, user_id])
        conn.execute(
            f"UPDATE journal_entries SET {', '.join(updates)} "
            f"WHERE id = %s AND user_id = %s",
            params,
        )
        conn.commit()

        # Return fresh entry
        fresh = conn.execute(
            "SELECT * FROM journal_entries WHERE id = %s AND user_id = %s",
            (entry_id, user_id),
        ).fetchone()
        return _journal_row_to_dict(fresh, conn) if fresh else None
    finally:
        conn.close()


def delete_journal_entry(user_id: str, entry_id: int) -> bool:
    """Delete a journal entry.  CASCADE removes journal_entry_tags too."""
    conn = _get_db()
    try:
        cur = conn.execute(
            "DELETE FROM journal_entries WHERE id = %s AND user_id = %s",
            (entry_id, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_journal_entry(user_id: str, entry_id: int) -> dict | None:
    """Return a single journal entry with decrypted title + body, or None."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM journal_entries WHERE id = %s AND user_id = %s",
            (entry_id, user_id),
        ).fetchone()
        if not row:
            return None
        return _journal_row_to_dict(row, conn)
    finally:
        conn.close()


def list_journal_entries(user_id: str,
                         alter_uuid: str | None = None,
                         tag: str | None = None,
                         limit: int = 50,
                         offset: int = 0) -> list[dict]:
    """List journal entries (newest first) with optional alter / tag filter.
    Title + body are decrypted.  Tag filter works on encrypted per-user tags
    by decrypting and matching in Python, then filtering by tag_id."""
    conn = _get_db()
    try:
        sql = "SELECT e.* FROM journal_entries e WHERE e.user_id = %s"
        params: list = [user_id]

        if alter_uuid is not None:
            sql += " AND e.alter_uuid = %s"
            params.append(alter_uuid)

        # Tag filter: decrypt all user's tags, find matching IDs, use IN clause
        if tag:
            all_tags = conn.execute(
                "SELECT id, name_nonce, name_cipher FROM journal_tags "
                "WHERE user_id = %s",
                (user_id,),
            ).fetchall()
            matching_ids = [
                r["id"] for r in all_tags
                if _decrypt_field(r["name_nonce"], r["name_cipher"]).lower()
                   == tag.strip().lower()
            ]
            if matching_ids:
                placeholders = ",".join("%s" * len(matching_ids))
                sql += (
                    f" AND e.id IN ("
                    f"  SELECT et.entry_id FROM journal_entry_tags et "
                    f"  WHERE et.tag_id IN ({placeholders})"
                    f")"
                )
                params.extend(matching_ids)
            else:
                sql += " AND 0"  # no matching tag → no results

        sql += " ORDER BY e.created_at DESC LIMIT %s OFFSET %s"
        params.extend([min(limit, 100), offset])

        rows = conn.execute(sql, params).fetchall()
        return [_journal_row_to_dict(r, conn) for r in rows]
    finally:
        conn.close()


def get_journal_tags(user_id: str) -> list[str]:
    """Return all unique decrypted tags used across journal entries for a user."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT DISTINCT t.name_nonce, t.name_cipher FROM journal_tags t "
            "JOIN journal_entry_tags et ON t.id = et.tag_id "
            "JOIN journal_entries e ON et.entry_id = e.id "
            "WHERE e.user_id = %s",
            (user_id,),
        ).fetchall()
        tags = [_decrypt_field(r["name_nonce"], r["name_cipher"]) for r in rows]
        return sorted([t for t in tags if t], key=str.lower)
    finally:
        conn.close()


def count_journal_entries(user_id: str, alter_uuid: str | None = None) -> int:
    """Return journal entry count for a user, optionally filtered by alter."""
    conn = _get_db()
    try:
        sql = "SELECT COUNT(*) AS cnt FROM journal_entries WHERE user_id = %s"
        params: list = [user_id]
        if alter_uuid is not None:
            sql += " AND alter_uuid = %s"
            params.append(alter_uuid)
        row = conn.execute(sql, params).fetchone()
        return row["cnt"] if row else 0
    finally:
        conn.close()


def _journal_row_to_dict(row: dict,
                         conn: psycopg.Connection) -> dict:
    """Convert a journal_entries row to a dict with decrypted title + body
    and tags from the encrypted per-user junction table."""
    d = dict(row)

    # Decrypt title (prefer encrypted columns; fall back to legacy plaintext)
    enc_title = _decrypt_field(d.pop("title_nonce", None), d.pop("title_cipher", None))
    if enc_title:
        d["title"] = enc_title
    elif "title" not in d:
        d["title"] = ""

    # Decrypt body
    body = ""
    if d.get("body_nonce") and d.get("body_cipher"):
        try:
            body = decrypt(d["body_nonce"], d["body_cipher"]).decode("utf-8")
        except Exception:
            body = "[decryption error]"
    d["body"] = body
    d.pop("body_nonce", None)
    d.pop("body_cipher", None)

    # Remove legacy columns if present (from pre-encryption schema)
    d.pop("tags", None)

    # Fetch tags from encrypted per-user junction table
    d["tags"] = _get_entry_tags(conn, d["id"])
    return _to_json_safe(d)


# ---------------------------------------------------------------------------
#  JWT verification
# ---------------------------------------------------------------------------

# Cache the JWKS client per domain to avoid re-fetching keys on every request.
_jwk_clients: dict = {}  # {jwks_url: PyJWKClient}


def verify_token(auth_header: str) -> str | None:
    """
    Verify the Bearer JWT and return the Clerk user-id (sub claim),
    or None on failure.

    The PyJWKClient is cached per JWKS URL so that signing keys are
    re-used across requests within the same process (important for
    CGI+mod_cgid and the long-lived Discord bot process).
    """
    try:
        import jwt
        from jwt import PyJWKClient
    except ImportError:
        print("[db.py] PyJWT not installed", file=sys.stderr)
        return None

    pub_key = (
        os.environ.get("NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", "")
        or CLERK_PK_FALLBACK
    )
    if not pub_key:
        print("[db.py] CLERK publishable key not set", file=sys.stderr)
        return None

    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]
    try:
        encoded = pub_key.split("_", 2)[2]
        padded = encoded + "=" * (-len(encoded) % 4)
        domain = base64.b64decode(padded).decode("utf-8").rstrip("$")
        jwks_url = f"https://{domain}/.well-known/jwks.json"

        if jwks_url not in _jwk_clients:
            _jwk_clients[jwks_url] = PyJWKClient(jwks_url, cache_keys=True)
        client = _jwk_clients[jwks_url]

        signing_key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token, signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        return claims.get("sub")
    except Exception as exc:
        print(f"[db.py] JWT verification failed: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
#  CGI response helper
# ---------------------------------------------------------------------------

def respond(status: str, body: str = "", content_type: str = "application/json"):
    """Write a CGI response to stdout."""
    sys.stdout.write(f"Status: {status}\r\n")
    sys.stdout.write(f"Content-Type: {content_type}\r\n")
    sys.stdout.write("Access-Control-Allow-Origin: *\r\n")
    sys.stdout.write("Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS\r\n")
    sys.stdout.write("Access-Control-Allow-Headers: Content-Type, Authorization\r\n")
    sys.stdout.write("Cache-Control: no-store\r\n")
    sys.stdout.write("\r\n")
    if body:
        sys.stdout.write(body)
    sys.stdout.flush()
