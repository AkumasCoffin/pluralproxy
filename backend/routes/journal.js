/**
 * Routes for /api/journal?action=...
 *
 * Mirrors the Python journal_api.py CGI endpoints.
 */

const express = require('express');
const router = express.Router();
const { authenticate } = require('../lib/auth');
const journal = require('../lib/journal');

router.use(authenticate);

// ── GET ──────────────────────────────────────────────────────────────

router.get('/', async (req, res) => {
  const action = req.query.action || '';
  try {
    switch (action) {
      case 'list': {
        const alterUuid = req.query.alter || undefined;
        const tag = req.query.tag || undefined;
        const limit = parseInt(req.query.limit || '50', 10) || 50;
        const offset = parseInt(req.query.offset || '0', 10) || 0;
        const entries = await journal.listJournalEntries(req.userId, {
          alterUuid, tag, limit, offset,
        });
        return res.json({ entries });
      }
      case 'get': {
        const entryId = req.query.id;
        if (!entryId) return res.status(400).json({ error: 'Missing entry id' });
        const entry = await journal.getJournalEntry(req.userId, parseInt(entryId, 10));
        if (!entry) return res.status(404).json({ error: 'Entry not found' });
        return res.json({ entry });
      }
      case 'tags': {
        const tags = await journal.getJournalTags(req.userId);
        return res.json({ tags });
      }
      case 'count': {
        const alterUuid = req.query.alter || undefined;
        const count = await journal.countJournalEntries(req.userId, alterUuid);
        return res.json({ count });
      }
      default:
        return res.status(400).json({ error: `Unknown GET action: ${action}` });
    }
  } catch (err) {
    console.error('[journal GET]', err);
    res.status(500).json({ error: String(err) });
  }
});

// ── POST ─────────────────────────────────────────────────────────────

router.post('/', async (req, res) => {
  const action = req.query.action || '';
  const body = req.body || {};
  try {
    switch (action) {
      case 'create': {
        const alterUuid = (body.alter_uuid || '').trim();
        const title = (body.title || '').trim();
        const text = (body.body || '').trim();
        let tags = body.tags || [];

        if (!Array.isArray(tags)) {
          return res.status(400).json({ error: 'tags must be a list' });
        }
        tags = tags.filter((t) => typeof t === 'string' && t.trim()).map((t) => t.trim());
        if (tags.length > 20) {
          return res.status(400).json({ error: 'Maximum 20 tags per entry' });
        }
        if (!title && !text) {
          return res.status(400).json({ error: 'Entry must have a title or body' });
        }

        const count = await journal.countJournalEntries(req.userId);
        if (count >= journal.MAX_JOURNAL_ENTRIES) {
          return res.status(400).json({
            error: `Maximum ${journal.MAX_JOURNAL_ENTRIES} journal entries reached`,
          });
        }

        const entry = await journal.createJournalEntry(req.userId, {
          alterUuid, title, body: text, tags, via: 'site',
        });
        return res.json({ entry });
      }
      case 'update': {
        const entryId = body.id;
        if (entryId == null) return res.status(400).json({ error: 'Missing entry id' });

        const title = body.title;
        const text = body.body;
        let tags = body.tags;

        if (tags !== undefined && tags !== null) {
          if (!Array.isArray(tags)) {
            return res.status(400).json({ error: 'tags must be a list' });
          }
          tags = tags.filter((t) => typeof t === 'string' && t.trim()).map((t) => t.trim());
          if (tags.length > 20) {
            return res.status(400).json({ error: 'Maximum 20 tags per entry' });
          }
        }

        const entry = await journal.updateJournalEntry(req.userId, parseInt(entryId, 10), {
          title, body: text, tags,
        });
        if (!entry) return res.status(404).json({ error: 'Entry not found' });
        return res.json({ entry });
      }
      case 'delete': {
        const entryId = body.id;
        if (entryId == null) return res.status(400).json({ error: 'Missing entry id' });
        const ok = await journal.deleteJournalEntry(req.userId, parseInt(entryId, 10));
        return res.json({ ok });
      }
      default:
        return res.status(400).json({ error: `Unknown POST action: ${action}` });
    }
  } catch (err) {
    console.error('[journal POST]', err);
    res.status(500).json({ error: String(err) });
  }
});

module.exports = router;
