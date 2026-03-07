/**
 * Friends system — requests, friendships, friend shares, profiles,
 * fronting sharing.
 */

const crypto = require('crypto');
const { pool, withTransaction, now, toJsonSafe } = require('./db');
const { encryptField, decryptField } = require('./encryption');
const { FRIEND_CODE_LENGTH } = require('./config');
const { ensureUser, getProfileDict } = require('./users');
const { readUserData } = require('./alters');

const _FRIEND_CODE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function generateFriendCode() {
  let code = '';
  for (let i = 0; i < FRIEND_CODE_LENGTH; i++) {
    code += _FRIEND_CODE_CHARS[crypto.randomInt(_FRIEND_CODE_CHARS.length)];
  }
  return code;
}

// ── Friend code ──────────────────────────────────────────────────────

async function getOrCreateFriendCode(userId) {
  return withTransaction(async (client) => {
    await ensureUser(client, userId);
    const { rows } = await client.query(
      'SELECT friend_code FROM users WHERE user_id = $1',
      [userId]
    );
    if (rows[0] && rows[0].friend_code) return rows[0].friend_code;

    for (let i = 0; i < 100; i++) {
      const code = generateFriendCode();
      try {
        await client.query(
          'UPDATE users SET friend_code = $1, updated_at = $2 WHERE user_id = $3',
          [code, now(), userId]
        );
        return code;
      } catch (err) {
        if (err.code === '23505') continue; // unique violation, retry
        throw err;
      }
    }
    throw new Error('Failed to generate unique friend code');
  });
}

async function lookupUserByFriendCode(friendCode) {
  const { rows } = await pool.query(
    'SELECT user_id, name_nonce, name_cipher, friend_code FROM users WHERE friend_code = $1',
    [friendCode.toUpperCase().trim()]
  );
  if (!rows[0]) return null;
  const d = { ...rows[0] };
  d.display_name = decryptField(d.name_nonce, d.name_cipher);
  delete d.name_nonce; delete d.name_cipher;
  d.profile = await getProfileDict(pool, d.user_id);
  return toJsonSafe(d);
}

// ── Friend requests ──────────────────────────────────────────────────

async function sendFriendRequest(fromUser, toUser, message = '') {
  if (fromUser === toUser) throw new Error('Cannot friend yourself');

  return withTransaction(async (client) => {
    // Check already friends
    const { rows: existing } = await client.query(
      'SELECT 1 FROM friendships WHERE user_id = $1 AND friend_id = $2',
      [fromUser, toUser]
    );
    if (existing[0]) throw new Error('Already friends');

    // Check pending request either direction
    const { rows: pending } = await client.query(
      `SELECT id, from_user, status FROM friend_requests
       WHERE ((from_user = $1 AND to_user = $2) OR (from_user = $3 AND to_user = $4))
       AND status = 'pending'`,
      [fromUser, toUser, toUser, fromUser]
    );

    if (pending[0]) {
      if (pending[0].from_user === toUser) {
        // They sent us a request — auto-accept
        return acceptFriendRequestInner(client, pending[0].id, toUser, fromUser);
      }
      throw new Error('Friend request already pending');
    }

    const ts = now();
    // Remove old non-pending requests
    await client.query(
      `DELETE FROM friend_requests
       WHERE from_user = $1 AND to_user = $2 AND status != 'pending'`,
      [fromUser, toUser]
    );
    const { nonce: mn, cipher: mc } = encryptField(message);
    await client.query(
      `INSERT INTO friend_requests
       (from_user, to_user, msg_nonce, msg_cipher, status, created_at, updated_at)
       VALUES ($1, $2, $3, $4, 'pending', $5, $6)`,
      [fromUser, toUser, mn, mc, ts, ts]
    );
    return { status: 'pending', message: 'Friend request sent' };
  });
}

async function acceptFriendRequestInner(client, requestId, fromUser, acceptingUser) {
  const ts = now();
  await client.query(
    "UPDATE friend_requests SET status = 'accepted', updated_at = $1 WHERE id = $2",
    [ts, requestId]
  );
  await client.query(
    `INSERT INTO friendships (user_id, friend_id, created_at) VALUES ($1, $2, $3)
     ON CONFLICT DO NOTHING`,
    [fromUser, acceptingUser, ts]
  );
  await client.query(
    `INSERT INTO friendships (user_id, friend_id, created_at) VALUES ($1, $2, $3)
     ON CONFLICT DO NOTHING`,
    [acceptingUser, fromUser, ts]
  );
  return { status: 'accepted', message: 'Friend request accepted' };
}

async function respondFriendRequest(requestId, userId, accept) {
  return withTransaction(async (client) => {
    const { rows } = await client.query(
      "SELECT * FROM friend_requests WHERE id = $1 AND to_user = $2 AND status = 'pending'",
      [requestId, userId]
    );
    if (!rows[0]) throw new Error('Request not found or already handled');

    if (accept) {
      return acceptFriendRequestInner(client, requestId, rows[0].from_user, userId);
    }
    await client.query(
      "UPDATE friend_requests SET status = 'declined', updated_at = $1 WHERE id = $2",
      [now(), requestId]
    );
    return { status: 'declined', message: 'Friend request declined' };
  });
}

async function cancelFriendRequest(requestId, userId) {
  const result = await pool.query(
    `UPDATE friend_requests SET status = 'cancelled', updated_at = $1
     WHERE id = $2 AND from_user = $3 AND status = 'pending'`,
    [now(), requestId, userId]
  );
  return result.rowCount > 0;
}

async function getFriendRequests(userId) {
  const { rows: incoming } = await pool.query(
    `SELECT fr.id, fr.from_user, fr.msg_nonce, fr.msg_cipher,
            fr.created_at,
            u.name_nonce AS u_nn, u.name_cipher AS u_nc,
            u.friend_code, u.avatar_url
     FROM friend_requests fr
     LEFT JOIN users u ON u.user_id = fr.from_user
     WHERE fr.to_user = $1 AND fr.status = 'pending'
     ORDER BY fr.created_at DESC`,
    [userId]
  );

  const incomingList = [];
  for (const r of incoming) {
    const d = { ...r };
    d.message = decryptField(d.msg_nonce, d.msg_cipher);
    d.display_name = decryptField(d.u_nn, d.u_nc);
    delete d.msg_nonce; delete d.msg_cipher;
    delete d.u_nn; delete d.u_nc;
    d.profile = await getProfileDict(pool, d.from_user);
    incomingList.push(d);
  }

  const { rows: outgoing } = await pool.query(
    `SELECT fr.id, fr.to_user, fr.msg_nonce, fr.msg_cipher,
            fr.created_at,
            u.name_nonce AS u_nn, u.name_cipher AS u_nc,
            u.friend_code, u.avatar_url
     FROM friend_requests fr
     LEFT JOIN users u ON u.user_id = fr.to_user
     WHERE fr.from_user = $1 AND fr.status = 'pending'
     ORDER BY fr.created_at DESC`,
    [userId]
  );

  const outgoingList = [];
  for (const r of outgoing) {
    const d = { ...r };
    d.message = decryptField(d.msg_nonce, d.msg_cipher);
    d.display_name = decryptField(d.u_nn, d.u_nc);
    delete d.msg_nonce; delete d.msg_cipher;
    delete d.u_nn; delete d.u_nc;
    d.profile = await getProfileDict(pool, d.to_user);
    outgoingList.push(d);
  }

  return toJsonSafe({ incoming: incomingList, outgoing: outgoingList });
}

// ── Friends list ─────────────────────────────────────────────────────

async function getFriends(userId) {
  const { rows } = await pool.query(
    `SELECT f.friend_id, f.created_at AS friends_since,
            u.name_nonce, u.name_cipher, u.friend_code, u.avatar_url
     FROM friendships f
     LEFT JOIN users u ON u.user_id = f.friend_id
     WHERE f.user_id = $1`,
    [userId]
  );
  const result = [];
  for (const r of rows) {
    const d = { ...r };
    d.display_name = decryptField(d.name_nonce, d.name_cipher);
    delete d.name_nonce; delete d.name_cipher;
    d.profile = await getProfileDict(pool, d.friend_id);
    result.push(d);
  }
  result.sort((a, b) => {
    const nameA = (a.display_name || '').toLowerCase();
    const nameB = (b.display_name || '').toLowerCase();
    return nameA.localeCompare(nameB) || String(a.friends_since).localeCompare(String(b.friends_since));
  });
  return toJsonSafe(result);
}

async function removeFriend(userId, friendId) {
  return withTransaction(async (client) => {
    await client.query(
      'DELETE FROM friendships WHERE user_id = $1 AND friend_id = $2',
      [userId, friendId]
    );
    await client.query(
      'DELETE FROM friendships WHERE user_id = $1 AND friend_id = $2',
      [friendId, userId]
    );
    await client.query(
      `DELETE FROM friend_shares WHERE (user_id = $1 AND friend_id = $2)
       OR (user_id = $3 AND friend_id = $4)`,
      [userId, friendId, friendId, userId]
    );
    await client.query(
      `DELETE FROM fronting_shares WHERE (user_id = $1 AND friend_id = $2)
       OR (user_id = $3 AND friend_id = $4)`,
      [userId, friendId, friendId, userId]
    );
    await client.query(
      `DELETE FROM friend_requests
       WHERE (from_user = $1 AND to_user = $2) OR (from_user = $3 AND to_user = $4)`,
      [userId, friendId, friendId, userId]
    );
    return true;
  });
}

// ── Friend sharing ───────────────────────────────────────────────────

async function updateFriendShares(userId, friendId, alters) {
  return withTransaction(async (client) => {
    const { rows } = await client.query(
      'SELECT 1 FROM friendships WHERE user_id = $1 AND friend_id = $2',
      [userId, friendId]
    );
    if (!rows[0]) throw new Error('Not friends');

    await client.query(
      'DELETE FROM friend_shares WHERE user_id = $1 AND friend_id = $2',
      [userId, friendId]
    );
    if (alters && alters.length) {
      for (const a of alters) {
        const alterUuid = a.uuid;
        await client.query(
          'INSERT INTO friend_shares (user_id, friend_id, alter_uuid) VALUES ($1, $2, $3)',
          [userId, friendId, alterUuid]
        );
        for (const groupName of (a.hidden_fields || [])) {
          if (groupName) {
            await client.query(
              `INSERT INTO friend_share_hidden_groups
               (user_id, friend_id, alter_uuid, group_name) VALUES ($1, $2, $3, $4)`,
              [userId, friendId, alterUuid, groupName]
            );
          }
        }
      }
    }
  });
}

async function getFriendSharedAlters(userId, friendId) {
  // Verify friendship
  const { rows: f } = await pool.query(
    'SELECT 1 FROM friendships WHERE user_id = $1 AND friend_id = $2',
    [userId, friendId]
  );
  if (!f[0]) return null;

  // Get what friend shared with us
  const { rows: shareRows } = await pool.query(
    'SELECT alter_uuid FROM friend_shares WHERE user_id = $1 AND friend_id = $2',
    [friendId, userId]
  );
  if (!shareRows.length) return [];

  const allowed = new Set(shareRows.map((r) => r.alter_uuid));

  // Fetch hidden groups per alter
  const { rows: hiddenRows } = await pool.query(
    'SELECT alter_uuid, group_name FROM friend_share_hidden_groups WHERE user_id = $1 AND friend_id = $2',
    [friendId, userId]
  );
  const hiddenMap = {};
  for (const r of hiddenRows) {
    if (!hiddenMap[r.alter_uuid]) hiddenMap[r.alter_uuid] = [];
    hiddenMap[r.alter_uuid].push(r.group_name);
  }

  const raw = await readUserData(friendId, 'alters');
  if (!raw) return [];

  const allAlters = JSON.parse(raw);
  const result = allAlters.filter((a) => allowed.has(a.UUID));

  for (const alter of result) {
    const hidden = new Set(hiddenMap[alter.UUID] || []);
    for (const h of hidden) delete alter[h];
  }
  return result;
}

async function getMySharesToFriend(userId, friendId) {
  const { rows } = await pool.query(
    'SELECT alter_uuid FROM friend_shares WHERE user_id = $1 AND friend_id = $2',
    [userId, friendId]
  );
  const result = [];
  for (const r of rows) {
    const { rows: hiddenRows } = await pool.query(
      `SELECT group_name FROM friend_share_hidden_groups
       WHERE user_id = $1 AND friend_id = $2 AND alter_uuid = $3`,
      [userId, friendId, r.alter_uuid]
    );
    result.push({
      uuid: r.alter_uuid,
      hidden_fields: hiddenRows.map((hr) => hr.group_name),
    });
  }
  return result;
}

// ── Fronting sharing ─────────────────────────────────────────────────

async function setFrontingShare(userId, friendId, enabled, hiddenFields = []) {
  return withTransaction(async (client) => {
    const { rows } = await client.query(
      'SELECT 1 FROM friendships WHERE user_id = $1 AND friend_id = $2',
      [userId, friendId]
    );
    if (!rows[0]) throw new Error('Not friends');

    if (enabled) {
      await client.query(
        `INSERT INTO fronting_shares (user_id, friend_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING`,
        [userId, friendId]
      );
      await client.query(
        'DELETE FROM fronting_share_hidden_groups WHERE user_id = $1 AND friend_id = $2',
        [userId, friendId]
      );
      for (const g of (hiddenFields || [])) {
        if (g) {
          await client.query(
            `INSERT INTO fronting_share_hidden_groups
             (user_id, friend_id, group_name) VALUES ($1, $2, $3)`,
            [userId, friendId, g]
          );
        }
      }
    } else {
      await client.query(
        'DELETE FROM fronting_shares WHERE user_id = $1 AND friend_id = $2',
        [userId, friendId]
      );
    }
  });
}

async function getFrontingShareSettings(userId, friendId) {
  const { rows } = await pool.query(
    'SELECT 1 FROM fronting_shares WHERE user_id = $1 AND friend_id = $2',
    [userId, friendId]
  );
  if (!rows[0]) return null;

  const { rows: hiddenRows } = await pool.query(
    'SELECT group_name FROM fronting_share_hidden_groups WHERE user_id = $1 AND friend_id = $2',
    [userId, friendId]
  );
  return {
    enabled: true,
    hidden_fields: hiddenRows.map((r) => r.group_name),
  };
}

async function getFriendFronting(userId, friendId) {
  // Verify friendship
  const { rows: f } = await pool.query(
    'SELECT 1 FROM friendships WHERE user_id = $1 AND friend_id = $2',
    [userId, friendId]
  );
  if (!f[0]) return null;

  // Check if friend is sharing fronting with us
  const { rows: share } = await pool.query(
    'SELECT 1 FROM fronting_shares WHERE user_id = $1 AND friend_id = $2',
    [friendId, userId]
  );
  if (!share[0]) return null;

  // Fetch hidden groups
  const { rows: hiddenRows } = await pool.query(
    'SELECT group_name FROM fronting_share_hidden_groups WHERE user_id = $1 AND friend_id = $2',
    [friendId, userId]
  );
  const hidden = hiddenRows.map((r) => r.group_name);

  // Get friend's currently fronting alters
  const { rows: frontingRows } = await pool.query(
    `SELECT alter_uuid, role FROM fronting WHERE user_id = $1
     ORDER BY CASE role WHEN 'primary' THEN 0 ELSE 1 END, set_at`,
    [friendId]
  );

  if (!frontingRows.length) {
    return { fronting: [], hidden_fields: hidden };
  }

  const frontingUuids = {};
  for (const r of frontingRows) frontingUuids[r.alter_uuid] = r.role;

  const raw = await readUserData(friendId, 'alters');
  if (!raw) return { fronting: [], hidden_fields: hidden };

  const allAlters = JSON.parse(raw);
  const result = [];
  for (const alter of allAlters) {
    const uuid = alter.UUID || '';
    if (uuid in frontingUuids) {
      for (const h of hidden) delete alter[h];
      alter._fronting_role = frontingUuids[uuid];
      result.push(alter);
    }
  }
  return { fronting: result, hidden_fields: hidden };
}

// ── Friend poll counts ───────────────────────────────────────────────

async function getFriendPollCounts(userId) {
  const { rows: [inc] } = await pool.query(
    "SELECT COUNT(*) AS cnt FROM friend_requests WHERE to_user = $1 AND status = 'pending'",
    [userId]
  );
  const { rows: [out] } = await pool.query(
    "SELECT COUNT(*) AS cnt FROM friend_requests WHERE from_user = $1 AND status = 'pending'",
    [userId]
  );
  const { rows: [fri] } = await pool.query(
    'SELECT COUNT(*) AS cnt FROM friendships WHERE user_id = $1',
    [userId]
  );
  return {
    incoming: parseInt(inc.cnt, 10),
    outgoing: parseInt(out.cnt, 10),
    friends: parseInt(fri.cnt, 10),
  };
}

// ── Friend names ─────────────────────────────────────────────────────

async function getFriendNames(userId) {
  const { rows } = await pool.query(
    `SELECT f.friend_id, u.name_nonce, u.name_cipher
     FROM friendships f
     LEFT JOIN users u ON u.user_id = f.friend_id
     WHERE f.user_id = $1`,
    [userId]
  );
  const result = [];
  for (const r of rows) {
    let name = decryptField(r.name_nonce, r.name_cipher);
    if (!name) {
      const profile = await getProfileDict(pool, r.friend_id);
      name = profile.Name || profile.display_name || '';
    }
    result.push({ friend_id: r.friend_id, name: name || 'Unknown' });
  }
  return result;
}

module.exports = {
  getOrCreateFriendCode,
  lookupUserByFriendCode,
  sendFriendRequest,
  respondFriendRequest,
  cancelFriendRequest,
  getFriendRequests,
  getFriends,
  removeFriend,
  updateFriendShares,
  getFriendSharedAlters,
  getMySharesToFriend,
  setFrontingShare,
  getFrontingShareSettings,
  getFriendFronting,
  getFriendPollCounts,
  getFriendNames,
};
