/**
 * Environment loading & shared constants.
 *
 * Reads from ../.env (project root) and exports config values
 * used throughout the backend.
 */

const path = require('path');
const dotenv = require('dotenv');

// ── Paths ────────────────────────────────────────────────────────────
const BACKEND_DIR = path.resolve(__dirname, '..');
const PROJECT_DIR = path.resolve(BACKEND_DIR, '..');
const DATA_DIR = path.join(PROJECT_DIR, 'data');
const ENV_FILE = path.join(PROJECT_DIR, '.env');

// Load .env from project root
dotenv.config({ path: ENV_FILE });

// ── PostgreSQL ───────────────────────────────────────────────────────
const PG_HOST = process.env.PG_HOST || 'localhost';
const PG_PORT = parseInt(process.env.PG_PORT || '5432', 10);
const PG_DATABASE = process.env.PG_DATABASE || 'did_tracker';
const PG_USER = process.env.PG_USER || 'postgres';
const PG_PASSWORD = process.env.PG_PASSWORD || '';

// ── Site URL ─────────────────────────────────────────────────────────
const SITE_URL = (process.env.SITE_URL || 'http://localhost:3001').replace(/\/+$/, '');

// ── Clerk ────────────────────────────────────────────────────────────
const CLERK_PK = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || '';
const CLERK_FRONTEND_API = (process.env.CLERK_FRONTEND_API || '').replace(/\/+$/, '');
const CLERK_JS_URL = CLERK_FRONTEND_API
  ? `${CLERK_FRONTEND_API}/npm/@clerk/clerk-js@latest/dist/clerk.browser.js`
  : 'https://cdn.jsdelivr.net/npm/@clerk/clerk-js@latest/dist/clerk.browser.js';
const CLERK_PK_FALLBACK = CLERK_PK;

// ── Constants ────────────────────────────────────────────────────────
const MAX_BACKUPS_PER_USER = 3;
const SHARE_CODE_LENGTH = 12;
const LINK_CODE_LENGTH = 6;
const LINK_CODE_TTL_MINUTES = 10;
const FRIEND_CODE_LENGTH = 8;
const MAX_JOURNAL_ENTRIES = 500;

module.exports = {
  BACKEND_DIR,
  PROJECT_DIR,
  DATA_DIR,
  ENV_FILE,
  SITE_URL,
  PG_HOST,
  PG_PORT,
  PG_DATABASE,
  PG_USER,
  PG_PASSWORD,
  MAX_BACKUPS_PER_USER,
  SHARE_CODE_LENGTH,
  LINK_CODE_LENGTH,
  LINK_CODE_TTL_MINUTES,
  FRIEND_CODE_LENGTH,
  MAX_JOURNAL_ENTRIES,
  CLERK_PK,
  CLERK_PK_FALLBACK,
  CLERK_FRONTEND_API,
  CLERK_JS_URL,
};
