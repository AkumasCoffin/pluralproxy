/**
 * PostgreSQL connection pool + schema initialization.
 *
 * Creates all tables (IF NOT EXISTS) and indexes on first use.
 * Schema is auto-created on first startup.
 */

const { Pool } = require('pg');
const {
  PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD,
} = require('./config');

// ── Connection pool ──────────────────────────────────────────────────

const pool = new Pool({
  host: PG_HOST,
  port: PG_PORT,
  database: PG_DATABASE,
  user: PG_USER,
  password: PG_PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// ── Schema DDL ───────────────────────────────────────────────────────

const SCHEMA_TABLES = `
-- ── Core ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    name_nonce   BYTEA,
    name_cipher  BYTEA,
    avatar_url   TEXT    DEFAULT '',
    friend_code  TEXT,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS user_discord_settings (
    user_id           TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    discord_id        TEXT UNIQUE,
    proxy_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    autoproxy_enabled BOOLEAN NOT NULL DEFAULT FALSE
);

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
    -- Basic Info
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
    share_code   TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    label_nonce  BYTEA,
    label_cipher BYTEA,
    share_scope  TEXT NOT NULL DEFAULT 'selected'
                      CHECK(share_scope IN ('all','selected')),
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS share_alters (
    share_code TEXT NOT NULL REFERENCES shares(share_code) ON DELETE CASCADE,
    alter_uuid TEXT NOT NULL,
    PRIMARY KEY (share_code, alter_uuid)
);

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
    prefix_nonce  BYTEA,
    prefix_cipher BYTEA,
    suffix_nonce  BYTEA,
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

-- ── Share claims ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS share_claims (
    share_code TEXT NOT NULL REFERENCES shares(share_code) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    claimed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (share_code, user_id)
);

-- ── Friends ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS friend_requests (
    id          SERIAL PRIMARY KEY,
    from_user   TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    to_user     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    msg_nonce   BYTEA,
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
    title_nonce  BYTEA,
    title_cipher BYTEA,
    body_nonce   BYTEA,
    body_cipher  BYTEA,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    via          TEXT    NOT NULL DEFAULT 'site'
);

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

`;

const SCHEMA_INDEXES = [
  'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_friend_code ON users(friend_code) WHERE friend_code IS NOT NULL',
  'CREATE INDEX IF NOT EXISTS idx_alters_user ON alters(user_id, sort_order)',
  'CREATE INDEX IF NOT EXISTS idx_backups_user ON user_data_backups(user_id, data_type, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_shares_owner ON shares(owner_id)',
  'CREATE INDEX IF NOT EXISTS idx_proxies_user ON discord_proxies(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_share_claims_user ON share_claims(user_id)',

  'CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests(to_user, status)',
  'CREATE INDEX IF NOT EXISTS idx_friend_requests_from ON friend_requests(from_user, status)',
  'CREATE INDEX IF NOT EXISTS idx_friend_shares_friend ON friend_shares(friend_id)',
  'CREATE INDEX IF NOT EXISTS idx_journal_user ON journal_entries(user_id, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_journal_alter ON journal_entries(user_id, alter_uuid)',
  'CREATE INDEX IF NOT EXISTS idx_journal_tags_user ON journal_tags(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_journal_entry_tags_tag ON journal_entry_tags(tag_id)',
];

// ── Schema initialization ────────────────────────────────────────────

let _initialized = false;

async function initSchema() {
  if (_initialized) return;
  const client = await pool.connect();
  try {
    // Advisory lock to prevent concurrent init
    await client.query('SELECT pg_advisory_lock(42)');

    // Split and execute each CREATE statement
    const stmts = SCHEMA_TABLES.split(';')
      .map((s) => {
        // Remove comment-only lines
        return s
          .split('\n')
          .filter((line) => {
            const trimmed = line.trim();
            return trimmed && !trimmed.startsWith('--');
          })
          .join('\n')
          .trim();
      })
      .filter(Boolean);

    for (const stmt of stmts) {
      await client.query(stmt);
    }

    // Create indexes
    for (const idx of SCHEMA_INDEXES) {
      try {
        await client.query(idx);
      } catch {
        // Index may already exist with different params, ignore
      }
    }

    _initialized = true;
  } catch (err) {
    console.error('[db] Schema init error:', err.message);
    _initialized = true; // Mark to avoid retrying every request
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock(42)');
    } catch {
      // ignore
    }
    client.release();
  }
}

// ── Transaction helper ───────────────────────────────────────────────

/**
 * Execute a callback inside a transaction.
 * @param {(client: import('pg').PoolClient) => Promise<T>} callback
 * @returns {Promise<T>}
 * @template T
 */
async function withTransaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── Utility ──────────────────────────────────────────────────────────

/** UTC timestamp as ISO-8601 string. */
function now() {
  return new Date().toISOString();
}

/** Convert Date objects to ISO strings for JSON responses. */
function toJsonSafe(obj) {
  if (obj === null || obj === undefined) return obj;
  if (obj instanceof Date) return obj.toISOString();
  if (Array.isArray(obj)) return obj.map(toJsonSafe);
  if (typeof obj === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(obj)) {
      result[k] = toJsonSafe(v);
    }
    return result;
  }
  return obj;
}

module.exports = {
  pool,
  initSchema,
  withTransaction,
  now,
  toJsonSafe,
};
