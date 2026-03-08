/**
 * Express entry point.
 *
 * Routes:
 *   /data/{alters|relationships}/{user_id}.json  → routes/data.js
 *   /assets/images/{uuid}.{ext}                  → routes/upload.js
 *   /api/discord                                 → routes/discord.js
 *   /api/share                                   → routes/share.js
 *   /api/friends                                 → routes/friends.js
 *   /api/journal                                 → routes/journal.js
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { initSchema } = require('./lib/db');
const { PROJECT_DIR, SITE_URL, CLERK_PK, CLERK_JS_URL } = require('./lib/config');

const app = express();
const PORT = process.env.PORT || 3001;

// ── CORS ─────────────────────────────────────────────────────────────

app.use(cors({
  origin: '*',
  methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Body parsing ─────────────────────────────────────────────────────

// JSON for most API routes (5 MB limit)
app.use(express.json({ limit: '5mb' }));

// Raw binary for image uploads only (POST /assets/images/*)
app.post('/assets/images/*', express.raw({ type: '*/*', limit: '5mb' }));

// ── Security headers ─────────────────────────────────────────────────

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// ── Static files ─────────────────────────────────────────────────────

// Uploaded images — aggressive caching (URLs use cache-busting ?v= params)
app.use('/assets/images', express.static(
  path.join(PROJECT_DIR, 'assets', 'images'),
  { maxAge: '1y', immutable: true }
));

// Site assets (icons, fonts, etc.)
app.use('/assets/site', express.static(
  path.join(PROJECT_DIR, 'assets', 'site'),
  { maxAge: '1y', immutable: true }
));

// ── API & data routes (no-store) ─────────────────────────────────────

const noStore = (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); };

app.use('/data', noStore, require('./routes/data'));
app.use('/assets', require('./routes/upload'));  // POST /assets/images/:file upload handler
app.use('/api/discord', noStore, require('./routes/discord'));
app.use('/api/share', noStore, require('./routes/share'));
app.use('/api/friends', noStore, require('./routes/friends'));
app.use('/api/journal', noStore, require('./routes/journal'));

// ── Health check ─────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

// ── Frontend pages (inject env vars into HTML) ─────────────────────

/**
 * Read an HTML file and replace {{PLACEHOLDER}} tokens with env values.
 * In production the result is cached; in dev it's re-read every request.
 */
const _htmlCache = {};
const _cacheHtml = process.env.NODE_ENV === 'production';
function serveHtml(filePath) {
  return (req, res) => {
    if (!_cacheHtml || !_htmlCache[filePath]) {
      let html = fs.readFileSync(filePath, 'utf8');
      html = html
        .replace(/\{\{SITE_URL\}\}/g, SITE_URL)
        .replace(/\{\{CLERK_PK\}\}/g, CLERK_PK)
        .replace(/\{\{CLERK_JS_URL\}\}/g, CLERK_JS_URL);
      _htmlCache[filePath] = html;
    }
    res.type('html').send(_htmlCache[filePath]);
  };
}

const dashboardPath = path.join(PROJECT_DIR, 'dashboard.html');
const indexPath = path.join(PROJECT_DIR, 'index.html');

app.get('/dashboard', serveHtml(dashboardPath));
app.get('/dashboard.html', serveHtml(dashboardPath));
app.get('/', serveHtml(indexPath));
app.get('/index.html', serveHtml(indexPath));

// ── 404 fallback ─────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Error handler ────────────────────────────────────────────────────

app.use((err, req, res, _next) => {
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ────────────────────────────────────────────────────────────

async function start() {
  try {
    console.log('[server] Initializing database schema...');
    await initSchema();
    console.log('[server] Database schema ready.');
  } catch (err) {
    console.error('[server] Schema init failed:', err.message);
    console.error('[server] Server will start but DB may not be ready.');
  }

  app.listen(PORT, () => {
    console.log(`[server] Listening on http://localhost:${PORT}`);
  });
}

start();
