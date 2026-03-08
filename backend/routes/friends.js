/**
 * Routes for /api/friends?action=...
 *
 * Handles friends system API actions.
 */

const express = require('express');
const router = express.Router();
const { authenticate } = require('../lib/auth');
const friends = require('../lib/friends');
const { getUserProfile, updateUserProfile, syncAvatarUrl } = require('../lib/users');

router.use(authenticate);

// ── GET ──────────────────────────────────────────────────────────────

router.get('/', async (req, res) => {
  const action = req.query.action || '';
  const targetId = req.query.id || '';
  try {
    switch (action) {
      case 'my_code': {
        const code = await friends.getOrCreateFriendCode(req.userId);
        return res.json({ friend_code: code });
      }
      case 'list':
        return res.json({ friends: await friends.getFriends(req.userId) });
      case 'requests':
        return res.json(await friends.getFriendRequests(req.userId));
      case 'request_count':
        return res.json(await friends.getFriendPollCounts(req.userId));
      case 'profile':
        return res.json({ profile: await getUserProfile(req.userId) });
      case 'friend_profile': {
        if (!targetId) return res.status(400).json({ error: 'Missing id' });
        // Verify friendship before revealing profile
        const friendsList = await friends.getFriends(req.userId);
        if (!friendsList.some((f) => f.friend_id === targetId)) {
          return res.status(403).json({ error: 'Not friends with this user' });
        }
        const profile = await getUserProfile(targetId);
        return res.json({ profile });
      }
      case 'view_friend': {
        if (!targetId) return res.status(400).json({ error: 'Missing id' });
        const alters = await friends.getFriendSharedAlters(req.userId, targetId);
        if (alters === null) return res.status(404).json({ error: 'Not found' });
        return res.json({ alters });
      }
      case 'my_shares_to': {
        if (!targetId) return res.status(400).json({ error: 'Missing id' });
        const shareList = await friends.getMySharesToFriend(req.userId, targetId);
        return res.json({ alters: shareList });
      }
      case 'friend_names':
        return res.json({ friends: await friends.getFriendNames(req.userId) });
      case 'fronting_share': {
        if (!targetId) return res.status(400).json({ error: 'Missing id' });
        const settings = await friends.getFrontingShareSettings(req.userId, targetId);
        return res.json({ settings: settings || { enabled: false, hidden_fields: [] } });
      }
      case 'friend_fronting': {
        if (!targetId) return res.status(400).json({ error: 'Missing id' });
        const data = await friends.getFriendFronting(req.userId, targetId);
        if (!data) return res.json({ shared: false, fronting: [] });
        return res.json({ shared: true, fronting: data.fronting || [] });
      }
      default:
        return res.status(400).json({ error: `Unknown GET action: ${action}` });
    }
  } catch (err) {
    console.error('[friends GET]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST ─────────────────────────────────────────────────────────────

router.post('/', async (req, res) => {
  const action = req.query.action || '';
  const body = req.body || {};
  try {
    switch (action) {
      case 'send_request': {
        const code = (body.code || '').trim();
        const message = (body.message || '').trim();
        if (!code) return res.status(400).json({ error: 'Friend code required' });
        const target = await friends.lookupUserByFriendCode(code);
        if (!target) return res.status(404).json({ error: 'User not found' });
        if (target.user_id === req.userId) {
          return res.status(400).json({ error: "That's your own code" });
        }
        const result = await friends.sendFriendRequest(req.userId, target.user_id, message);
        return res.json(result);
      }
      case 'respond_request': {
        const requestId = body.request_id;
        const accept = Boolean(body.accept);
        if (!requestId) return res.status(400).json({ error: 'request_id required' });
        const result = await friends.respondFriendRequest(requestId, req.userId, accept);
        return res.json(result);
      }
      case 'cancel_request': {
        const requestId = body.request_id;
        if (!requestId) return res.status(400).json({ error: 'request_id required' });
        const ok = await friends.cancelFriendRequest(requestId, req.userId);
        return res.json({ ok });
      }
      case 'remove_friend': {
        const friendId = body.friend_id;
        if (!friendId) return res.status(400).json({ error: 'friend_id required' });
        await friends.removeFriend(req.userId, friendId);
        return res.json({ ok: true });
      }
      case 'update_sharing': {
        const friendId = body.friend_id;
        const alters = body.alters || [];
        if (!friendId) return res.status(400).json({ error: 'friend_id required' });
        await friends.updateFriendShares(req.userId, friendId, alters);
        return res.json({ ok: true });
      }
      case 'update_fronting_share': {
        const friendId = body.friend_id;
        const enabled = Boolean(body.enabled);
        const hiddenFields = body.hidden_fields || [];
        if (!friendId) return res.status(400).json({ error: 'friend_id required' });
        await friends.setFrontingShare(req.userId, friendId, enabled, hiddenFields);
        return res.json({ ok: true });
      }
      case 'update_profile': {
        const profile = body.profile || {};
        await updateUserProfile(req.userId, profile);
        return res.json({ ok: true });
      }
      case 'sync_avatar': {
        const avatarUrl = body.avatar_url || '';
        await syncAvatarUrl(req.userId, avatarUrl);
        return res.json({ ok: true });
      }
      default:
        return res.status(400).json({ error: `Unknown POST action: ${action}` });
    }
  } catch (err) {
    console.error('[friends POST]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
