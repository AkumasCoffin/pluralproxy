/**
 * Routes for /data/{alters|relationships}/{user_id}.json
 *
 * GET  — read + decrypt
 * PUT  — encrypt + store (with auto-backup)
 */

const express = require('express');
const router = express.Router();
const { authenticate } = require('../lib/auth');
const { readUserData, writeUserData } = require('../lib/alters');

// GET /data/:type/:file
router.get('/:type/:file', authenticate, async (req, res) => {
  try {
    const { type, file } = req.params;

    if (!['alters', 'relationships'].includes(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }

    const m = file.match(/^(user_[A-Za-z0-9]+)\.json$/);
    if (!m) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    const urlUserId = m[1];

    if (req.userId !== urlUserId) {
      return res.status(403).json({ error: 'Access denied — you can only view your own data' });
    }

    const content = await readUserData(urlUserId, type);
    if (content === null) {
      return res.status(404).json(null);
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.send(content);
  } catch (err) {
    console.error('[data GET]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /data/:type/:file
router.put('/:type/:file', authenticate, async (req, res) => {
  try {
    const { type, file } = req.params;

    if (!['alters', 'relationships'].includes(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }

    const m = file.match(/^(user_[A-Za-z0-9]+)\.json$/);
    if (!m) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    const urlUserId = m[1];

    if (req.userId !== urlUserId) {
      return res.status(403).json({ error: 'Token user does not match URL' });
    }

    const body = req.body;

    // Alters must be a JSON array; relationships is a JSON object
    if (type === 'alters') {
      if (!Array.isArray(body)) {
        return res.status(400).json({ error: 'Expected a JSON array' });
      }
    } else {
      if (body == null || typeof body !== 'object') {
        return res.status(400).json({ error: 'Expected a JSON object' });
      }
    }

    const jsonBytes = JSON.stringify(body);
    await writeUserData(urlUserId, type, jsonBytes);

    res.json({ ok: true, count: Array.isArray(body) ? body.length : 1 });
  } catch (err) {
    console.error('[data PUT]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
