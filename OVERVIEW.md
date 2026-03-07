# Plural Proxy — Project Overview

> **A privacy-first web application for DID/OSDD plural systems** — manage alter profiles, track fronting, map relationships, share with friends, journal, and let alters speak on Discord.
>
> Set your domain via the `SITE_URL` environment variable.

---

## Table of Contents

- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Frontend](#frontend)
- [Backend API (CGI)](#backend-api-cgi)
- [Discord Bot](#discord-bot)
- [Database Schema](#database-schema)
- [Security & Encryption](#security--encryption)
- [Authentication](#authentication)
- [Alter Data Model](#alter-data-model)
- [Feature Breakdown](#feature-breakdown)
- [API Endpoints](#api-endpoints)
- [Infrastructure & Deployment](#infrastructure--deployment)
- [Environment Variables](#environment-variables)
- [Dependencies](#dependencies)
- [Codebase Stats](#codebase-stats)

---

## Architecture

```
┌──────────────┐     ┌───────────────┐     ┌──────────────────┐
│   Frontend   │────▶│  Apache + CGI │────▶│   PostgreSQL     │
│  (HTML/JS)   │     │  (.htaccess)  │     │  (AES-256-GCM    │
│              │     │               │     │   encrypted)     │
│  Clerk Auth  │     │  cgi-bin/*.py │     └──────────────────┘
└──────────────┘     └───────────────┘              ▲
                                                    │
┌──────────────┐                                    │
│ Discord Bot  │────────────────────────────────────┘
│  (bot.py)    │
│  via PM2     │
└──────────────┘
```

- **Frontend** → Static HTML/CSS/JS served by Apache; authenticates via Clerk JS SDK
- **Backend** → Python CGI scripts behind Apache; all share a common `db.py` module
- **Bot** → Long-running `discord.py` process managed by PM2; imports the same `db.py`
- **Database** → PostgreSQL with per-column AES-256-GCM encryption at rest
- **CDN/Proxy** → Cloudflare (real-IP restoration configured in Apache)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML / CSS / JavaScript (single-page style) |
| Authentication | [Clerk](https://clerk.com) — JWT (RS256) with Discord SSO |
| Backend API | Python 3 CGI scripts on Apache |
| Database | PostgreSQL (via `psycopg` 3) |
| Encryption | AES-256-GCM (`cryptography` library) |
| JWT Verification | `PyJWT[crypto]` with Clerk JWKS |
| Discord Bot | `discord.py` 2.3+ |
| Process Manager | PM2 |
| Web Server | Apache 2 with `mod_cgi`, `mod_rewrite`, `mod_remoteip` |
| CDN | Cloudflare |

---

## Project Structure

```
/var/www/plural-proxy/
│
├── index.html                 # Public landing page (806 lines)
├── dashboard.html             # Authenticated SPA — the main app (9,716 lines)
├── .htaccess                  # Apache routing, security headers, data protection
├── alters.conf                # Apache VirtualHost config
│
├── cgi-bin/                   # Backend API (Python CGI scripts)
│   ├── db.py                  # Shared module: DB, encryption, JWT, helpers (4,059 lines)
│   ├── read.py                # GET /data/{alters|relationships}/{user}.json
│   ├── save.py                # PUT /data/{alters|relationships}/{user}.json
│   ├── upload.py              # POST /assets/images/{uuid}.{ext}
│   ├── discord_api.py         # GET/POST /api/discord — Discord account linking
│   ├── share_api.py           # GET/POST /api/share — view-only share links
│   ├── friends_api.py         # GET/POST /api/friends — friend system
│   └── journal_api.py         # GET/POST /api/journal — journal entries & tags
│
├── bot/                       # Discord bot
│   ├── bot.py                 # Main bot file (1,133 lines)
│   ├── sync_commands.py       # Slash command registration helper
│   └── requirements.txt       # Bot-specific dependencies
│
├── data/                      # Runtime data directory (owned by www-data)
│   ├── did_tracker.db         # Legacy SQLite database (pre-migration)
│   ├── alters/                # Legacy JSON files (pre-migration)
│   └── relationships/         # Legacy JSON files (pre-migration)
│
├── assets/
│   └── images/                # User-uploaded alter avatars (UUID-named)
│
├── backups/                   # JSON backup files per user
│
├── server.py                  # Lightweight dev server (legacy / local testing)
├── install.sh                 # First-time setup script (generates encryption key, inits DB)
├── update.sh                  # Deploy script for file updates
├── .env                       # Environment variables (NEVER commit)
├── example.env                # Template for .env
├── requirements.txt           # Root Python dependencies
├── schema_dbeaver.sql         # Full PostgreSQL schema (for DBeaver diagrams)
├── example_queries.sql        # Useful PostgreSQL queries for debugging
├── README.md                  # GitHub README & setup instructions
└── to-do.txt                  # Feature ideas & alter field template
```

---

## Frontend

### Landing Page (`index.html`)

Public-facing marketing page describing features:
- Alter profiles with 50+ customizable fields
- Fronting tracker
- Relationship mapping
- Discord bot integration
- Encrypted, private data storage
- View-only share links

### Dashboard (`dashboard.html`)

The main authenticated single-page application (~9,700 lines of HTML/CSS/JS). Features include:

- **Alter Management** — Create, edit, reorder, and delete alter profiles with rich field groups
- **Fronting Tracker** — Set primary/secondary fronting status for alters
- **Relationship Map** — Visual mapping of relationships between alters
- **User Profile** — System-level profile (age, pronouns, bio, etc.)
- **Sharing** — Generate view-only share links with granular control over which alters and field groups are visible
- **Friends System** — Send/accept friend requests via friend codes; share specific alters with friends
- **Fronting Sharing** — Let friends see who's currently fronting
- **Journal** — Write entries tagged to specific alters with custom tags
- **Discord Integration** — Link Discord account, configure proxy triggers
- **Avatar Uploads** — Upload images for alter profile cards
- **Card Customization** — Per-alter card colors and avatars

Authentication is handled entirely client-side via the **Clerk JS SDK**. The JWT is sent as a `Bearer` token on every API request.

---

## Backend API (CGI)

All CGI scripts live in `cgi-bin/` and share the `db.py` module which provides:

- **PostgreSQL connection management** (via `psycopg`)
- **AES-256-GCM encryption/decryption** for all user data
- **JWT verification** against Clerk's JWKS endpoint
- **CORS headers** and CGI response helpers
- **All database queries** — CRUD for users, alters, shares, friends, journal, proxies, fronting, etc.

### Request Flow

```
Client (dashboard.html)
  │  Bearer JWT in Authorization header
  ▼
Apache (.htaccess rewrite rules)
  │  Routes to appropriate CGI script
  ▼
cgi-bin/*.py
  │  1. Verify JWT (db.verify_token)
  │  2. Validate request
  │  3. Encrypt/decrypt via db.py
  │  4. Read/write PostgreSQL
  ▼
JSON response back to client
```

---

## Discord Bot

Located in `bot/bot.py` (1,133 lines), managed by PM2.

### Slash Commands

| Command | Description |
|---|---|
| `/link` | Link Discord account to the web dashboard (via Clerk Discord SSO) |
| `/unlink` | Unlink Discord account |
| `/alter` | Select who's fronting (interactive dropdown) |
| `/fronting` | Show who's currently fronting |
| `/proxy` | Enable/disable/configure trigger-based proxy |
| `/status` | Show connection + proxy status |
| `/journal` | Write a journal entry (tagged to current fronter) |
| `/entries` | View recent journal entries |

### Proxy System

- **Trigger Proxy** — Messages matching a configured prefix/suffix (e.g. `z: hello`) are deleted and re-sent via a Discord webhook using the alter's name and avatar
- **Autoproxy** — When enabled and no trigger matches, every message is automatically proxied as the primary fronting alter

The bot imports the same `db.py` module as the CGI scripts, so it reads/writes to the same encrypted PostgreSQL database.

---

## Database Schema

PostgreSQL with **21 tables**, all user content encrypted at rest:

### Core Tables

| Table | Purpose |
|---|---|
| `users` | One row per Clerk user (display name encrypted) |
| `user_profiles` | Wide table — one row per user, profile fields encrypted in column pairs |
| `user_discord_settings` | 1:1 Discord link + proxy/autoproxy settings |
| `alters` | Wide table — one row per alter, 30+ field pairs encrypted |
| `user_data` | Encrypted JSON blobs (relationships) |
| `user_data_backups` | Automatic version history (last N per user+type) |

### Sharing & Friends

| Table | Purpose |
|---|---|
| `shares` | View-only share links (label encrypted) |
| `share_alters` | Which alter UUIDs are in each share |
| `share_alter_hidden_groups` | Per-alter hidden field groups in shares |
| `share_claims` | Who has claimed/viewed which share |
| `friend_requests` | Pending/accepted/declined friend requests (message encrypted) |
| `friendships` | Bidirectional friend pairs |
| `friend_shares` | Which alters are shared with each friend |
| `friend_share_hidden_groups` | Per-alter hidden field groups for friend shares |
| `fronting_shares` | Share fronting status with friends |
| `fronting_share_hidden_groups` | Hidden groups for fronting shares |

### Discord & Fronting

| Table | Purpose |
|---|---|
| `discord_proxies` | Alter proxy triggers — prefix/suffix encrypted |
| `fronting` | Currently fronting alters per user (primary/secondary role) |
| `link_codes` | Legacy Discord linking codes (kept for compat) |

### Journal

| Table | Purpose |
|---|---|
| `journal_entries` | Per-alter encrypted journal (title + body encrypted) |
| `journal_tags` | Per-user encrypted tag names |
| `journal_entry_tags` | Junction table: entries ↔ tags |

### Encryption Pattern

Every sensitive text field is stored as a **(nonce, cipher)** BYTEA column pair:

```sql
name_nonce  BYTEA,
name_cipher BYTEA
```

The server encrypts on write and decrypts on read using a single `DATA_ENCRYPTION_KEY`.

---

## Security & Encryption

### Encryption at Rest

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Scope:** Every user-submitted text field — alter names, ages, journal entries, proxy triggers, friend request messages, share labels, etc.
- **Key:** `DATA_ENCRYPTION_KEY` in `.env` — base64-encoded 32 bytes, auto-generated by `install.sh`

> ⚠️ **Losing the `DATA_ENCRYPTION_KEY` means ALL user data is permanently unrecoverable.**

### Transport Security

- Cloudflare SSL/TLS termination
- Apache security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `X-XSS-Protection`, `Permissions-Policy`

### Access Control

- `.htaccess` blocks direct access to: `.env`, `*.db`, `server.py`, migration scripts, bot directory, backup files, and all raw data files
- All data endpoints require a valid Clerk JWT where the `sub` claim matches the requested user ID
- Users can **only** access their own data — enforced server-side

### File Security

- Uploaded images are UUID-named (no user-controlled filenames)
- Max upload size: 5 MB
- Allowed extensions: `png`, `jpg`, `gif`

---

## Authentication

Uses **[Clerk](https://clerk.com)** for authentication:

1. User signs in via Clerk JS SDK on the frontend (supports Discord SSO)
2. Frontend obtains a session JWT from Clerk
3. Every API request includes `Authorization: Bearer <JWT>`
4. Backend CGI scripts verify the JWT against Clerk's JWKS endpoint (`/.well-known/jwks.json`)
5. The JWT `sub` claim (Clerk user ID, e.g. `user_3ALo4e2F...`) is used as the primary key throughout the system
6. Discord linking uses Clerk's Discord external account data (verified via `CLERK_SECRET_KEY` → Clerk Backend API)

---

## Alter Data Model

Each alter has **50+ fields** organized into groups:

| Group | Fields |
|---|---|
| **Basic Info** | Name, Nicknames/Aliases, Age, Gender, Sexuality, Presentation, Dominant emotion |
| **System Info** | Role, Subsystem/Group |
| **Fronting & Switching** | Fronting frequency, Fronting signs, Dissociation level, Handoffs |
| **Personality & Traits** | Personality description, Strengths, Struggles, Fears, Values, Humor style, Love language/comfort style, Energy level |
| **Boundaries & Consent** | Hard boundaries, Soft boundaries, Consent reminders |
| **Triggers & Warnings** | Known triggers, Alter triggers, Common sensitivities, Early warning signs |
| **Mental Health** | Diagnosis/known conditions, Coping strategies, Crisis plan, Therapist notes |
| **Skills, Interests & Habits** | Skills, Special interests, Likes, Dislikes, Comfort items, Food/drink preferences, Music/aesthetic, Shows/games they like |
| **Relationships** | Closest alters, Tension/conflict, Caretakers, External relationships |
| **Communication** | Internal Communication, Communication Method, Tone Use |
| **Notes** | General notes, Session notes, Goals, To-do/follow-up |
| **Quick Summary** | 1–3 sentence summary |

Each alter also has metadata: UUID, sort order, avatar image, card color, avatar icon, created/updated timestamps.

---

## Feature Breakdown

### Alter Profiles
Create detailed profiles for each alter with 50+ fields across 12 groups. Drag-and-drop reordering, avatar uploads, and per-card color customization.

### Fronting Tracker
Mark one alter as **primary** (currently in front) and others as **secondary** (co-fronting). Status is stored in the database and visible to friends (if shared) and the Discord bot.

### Relationship Mapping
Visual graph of relationships between alters — stored as encrypted JSON blobs.

### View-Only Sharing
Generate share links with fine-grained control:
- Select which alters to include
- Hide specific field groups per alter
- Share scope: all alters or selected only
- Optional expiration
- Track who has claimed/viewed the share

### Friends System
- Each user gets a unique **friend code**
- Send friend requests with optional messages
- Accept/decline/cancel requests
- Share specific alters with each friend
- Per-friend hidden field groups
- Share fronting status with friends

### Journal
- Write entries tagged to specific alters
- Custom tags per user
- Create entries from the dashboard or Discord bot
- Entries stored with encrypted title + body

### Discord Proxy
- Configure prefix/suffix triggers per alter (e.g. `z:` for alter "Z")
- Messages matching triggers are deleted and re-sent via webhook as the alter (with their name and avatar)
- Autoproxy mode sends all messages as the primary fronting alter

---

## API Endpoints

| Method | Path | Handler | Description |
|---|---|---|---|
| `GET` | `/data/alters/{user}.json` | `read.py` | Fetch user's encrypted alter data |
| `PUT` | `/data/alters/{user}.json` | `save.py` | Save user's alter data |
| `GET` | `/data/relationships/{user}.json` | `read.py` | Fetch user's relationship data |
| `PUT` | `/data/relationships/{user}.json` | `save.py` | Save user's relationship data |
| `POST` | `/assets/images/{uuid}.{ext}` | `upload.py` | Upload alter avatar image |
| `GET/POST` | `/api/discord` | `discord_api.py` | Discord account linking/unlinking |
| `GET/POST` | `/api/share` | `share_api.py` | Create/read/manage share links |
| `GET/POST` | `/api/friends` | `friends_api.py` | Friend requests, friendships, friend shares |
| `GET/POST` | `/api/journal` | `journal_api.py` | Journal entries & tags CRUD |

All endpoints (except OPTIONS preflight) require `Authorization: Bearer <Clerk JWT>`.

---

## Infrastructure & Deployment

### Server

- **OS:** Linux
- **Web Server:** Apache 2 with `mod_cgi`, `mod_rewrite`, `mod_headers`, `mod_remoteip`
- **Process Manager:** PM2 (for the Discord bot)
- **CDN:** Cloudflare

### Apache Configuration

- `alters.conf` — VirtualHost definition pointing to `/var/www/plural-proxy/`
- `.htaccess` — URL rewrites (CGI routing), security headers, dotfile blocking, asset caching
- CGI scripts run as `www-data` user

### First-Time Install

```bash
sudo bash install.sh
```

Generates `DATA_ENCRYPTION_KEY`, initializes the database schema, configures Apache, and starts the Discord bot.

### Deploy Updates

```bash
sudo bash update.sh
```

Fixes line endings, sets permissions, restarts the bot and Apache.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Yes | Clerk publishable key (e.g. `pk_live_...`) |
| `CLERK_SECRET_KEY` | Yes | Clerk secret key for backend API calls |
| `DISCORD_BOT_TOKEN` | Yes | Discord bot token |
| `DATA_ENCRYPTION_KEY` | Auto | Base64-encoded 32-byte AES key (auto-generated) |
| `PG_HOST` | Yes | PostgreSQL host (default: `localhost`) |
| `PG_PORT` | Yes | PostgreSQL port (default: `5432`) |
| `PG_DATABASE` | Yes | PostgreSQL database name (default: `did_tracker`) |
| `PG_USER` | Yes | PostgreSQL user (default: `postgres`) |
| `PG_PASSWORD` | Yes | PostgreSQL password |

---

## Dependencies

### Root (`requirements.txt`)

```
PyJWT[crypto]>=2.8.0
cryptography>=41.0.0
psycopg[binary]>=3.1.0
```

### Bot (`bot/requirements.txt`)

```
discord.py>=2.3.0
PyJWT[crypto]>=2.8.0
cryptography>=41.0.0
psycopg[binary]>=3.1.0
```

### Frontend (CDN)

- Clerk JS SDK
- Font Awesome 6.5
- Google Fonts (Inter)

---

## Codebase Stats

**~19,325 total lines** across 27 source files.

| Category | Lines | % |
|---|---|---|
| Frontend (HTML/CSS/JS) | 10,521 | 54% |
| Backend API (Python CGI) | 4,753 | 25% |
| Discord Bot | 1,178 | 6% |
| Infrastructure & Config | 711 | 4% |
| Docs, Schema & Reference | 1,162 | 6% |

### Largest Files

| Lines | File | Description |
|---|---|---|
| 9,716 | `dashboard.html` | Main application SPA |
| 4,059 | `cgi-bin/db.py` | Shared backend module |
| 1,133 | `bot/bot.py` | Discord bot |
| 805 | `index.html` | Landing page |
| 369 | `schema_dbeaver.sql` | Database schema |
| 323 | `cgi-bin/friends_api.py` | Friends API |
