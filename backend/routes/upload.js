/**
 * Routes for image uploads: POST /assets/images/:uuid.:ext
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const { authenticate } = require('../lib/auth');
const { PROJECT_DIR } = require('../lib/config');

const IMAGES_DIR = path.join(PROJECT_DIR, 'assets', 'images');
const ALLOWED_EXTENSIONS = new Set(['png', 'jpg', 'gif']);
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

// POST /assets/images/:filename
router.post('/images/:filename', authenticate, (req, res) => {
  try {
    const { filename } = req.params;
    const m = filename.match(
      /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(\w+)$/i
    );
    if (!m) {
      return res.status(400).json({
        error: 'Invalid path — expected /assets/images/{uuid}.{ext}',
      });
    }

    const uuid = m[1];
    const ext = m[2].toLowerCase();

    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return res.status(400).json({
        error: `File type not allowed. Use: ${[...ALLOWED_EXTENSIONS].sort().join(', ')}`,
      });
    }

    // req.body is a raw Buffer when using express.raw()
    const body = req.body;
    if (!body || !body.length) {
      return res.status(400).json({ error: 'Empty body' });
    }
    if (body.length > MAX_FILE_SIZE) {
      return res.status(413).json({
        error: `File too large. Max ${MAX_FILE_SIZE / 1024 / 1024} MB`,
      });
    }

    // Ensure directory exists
    fs.mkdirSync(IMAGES_DIR, { recursive: true });

    // Remove existing images with same UUID
    for (const oldExt of ALLOWED_EXTENSIONS) {
      const oldFile = path.join(IMAGES_DIR, `${uuid}.${oldExt}`);
      if (fs.existsSync(oldFile)) {
        fs.unlinkSync(oldFile);
      }
    }

    // Write file
    const target = path.join(IMAGES_DIR, `${uuid}.${ext}`);
    fs.writeFileSync(target, body);

    res.json({ ok: true, path: `/assets/images/${uuid}.${ext}` });
  } catch (err) {
    console.error('[upload]', err);
    res.status(500).json({ error: String(err) });
  }
});

module.exports = router;
