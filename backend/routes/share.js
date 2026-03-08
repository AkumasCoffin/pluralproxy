/**
 * Routes for /api/share?action=...
 *
 * Handles share link API actions.
 */

const express = require('express');
const router = express.Router();
const { authenticate } = require('../lib/auth');
const shares = require('../lib/shares');

router.use(authenticate);

// ── GET ──────────────────────────────────────────────────────────────

router.get('/', async (req, res) => {
  const action = req.query.action || '';
  const code = req.query.code || '';
  try {
    switch (action) {
      case 'my_shares':
        return res.json({ shares: await shares.listShares(req.userId) });
      case 'claimed':
        return res.json({ owners: await shares.getClaimedShares(req.userId) });
      case 'view': {
        if (!code) return res.status(400).json({ error: 'Missing share code' });
        const share = await shares.resolveShare(code);
        if (!share) return res.status(404).json({ error: 'Invalid or expired share' });
        // Must be the owner or have claimed it
        if (share.owner_id !== req.userId) {
          const { pool } = require('../lib/db');
          const { rows: claimRows } = await pool.query(
            'SELECT 1 FROM share_claims WHERE share_code = $1 AND user_id = $2',
            [code, req.userId]
          );
          if (!claimRows[0]) {
            return res.status(403).json({ error: 'You have not claimed this share' });
          }
        }
        const alters = await shares.getSharedAlters(code);
        const ownerInfo = await shares.getShareOwnerInfo(code);
        return res.json({
          owner_id: share.owner_id,
          owner_name: ownerInfo ? (ownerInfo.owner_name || '') : '',
          label: share.label || '',
          alters: alters || [],
        });
      }
      case 'share_info': {
        if (!code) return res.status(400).json({ error: 'Missing share code' });
        const share = await shares.resolveShare(code);
        if (!share) return res.status(404).json({ error: 'Invalid or expired share' });
        return res.json({
          owner_name: share.owner_name || '',
          label: share.label || '',
          alter_count: (share.alter_uuids || []).length,
          share_scope: share.share_scope || 'selected',
        });
      }
      default:
        return res.status(400).json({ error: `Unknown GET action: ${action}` });
    }
  } catch (err) {
    console.error('[share GET]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST ─────────────────────────────────────────────────────────────

router.post('/', async (req, res) => {
  const action = req.query.action || '';
  const code = req.query.code || '';
  const body = req.body || {};
  try {
    switch (action) {
      case 'create': {
        const alters = body.alters !== undefined ? body.alters : null;
        const label = (body.label || '').trim();
        const expiresAt = body.expires_at || null;
        if (alters !== null && !Array.isArray(alters)) {
          return res.status(400).json({ error: 'alters must be a list' });
        }
        if (alters !== null && alters.length === 0) {
          return res.status(400).json({ error: 'Must select at least one alter' });
        }
        const shareCode = await shares.createShare(req.userId, alters, label, expiresAt);
        return res.json({ share_code: shareCode });
      }
      case 'claim': {
        if (!code) return res.status(400).json({ error: 'Missing share code' });
        const claimedShare = await shares.claimShare(code, req.userId);
        if (!claimedShare) {
          return res.status(400).json({ error: 'Invalid share code or cannot claim your own share' });
        }
        return res.json({ ok: true, owner_name: claimedShare.owner_name || '' });
      }
      case 'unclaim': {
        if (!code) return res.status(400).json({ error: 'Missing share code' });
        const ok = await shares.unclaimShare(code, req.userId);
        return res.json({ ok });
      }
      case 'revoke': {
        if (!code) return res.status(400).json({ error: 'Missing share code' });
        const ok = await shares.revokeShare(req.userId, code);
        return res.json({ ok });
      }
      default:
        return res.status(400).json({ error: `Unknown POST action: ${action}` });
    }
  } catch (err) {
    console.error('[share POST]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
