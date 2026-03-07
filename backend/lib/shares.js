/**
 * Share link operations — create / resolve / claim / revoke.
 */

const crypto = require('crypto');
const { pool, withTransaction, now, toJsonSafe } = require('./db');
const { encryptField, decryptField } = require('./encryption');
const { SHARE_CODE_LENGTH } = require('./config');
const { ensureUser } = require('./users');
const { readUserData } = require('./alters');

// ── Create a share ───────────────────────────────────────────────────

async function createShare(ownerId, alters = null, label = '', expiresAt = null) {
  const code = crypto.randomBytes(SHARE_CODE_LENGTH).toString('base64url');
  const scope = alters === null ? 'all' : 'selected';

  return withTransaction(async (client) => {
    await ensureUser(client, ownerId);
    const { nonce: ln, cipher: lc } = encryptField(label);
    await client.query(
      `INSERT INTO shares
       (share_code, owner_id, label_nonce, label_cipher, share_scope, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [code, ownerId, ln, lc, scope, now(), expiresAt]
    );

    if (alters) {
      for (const a of alters) {
        const alterUuid = a.uuid;
        await client.query(
          'INSERT INTO share_alters (share_code, alter_uuid) VALUES ($1, $2)',
          [code, alterUuid]
        );
        for (const groupName of (a.hidden_fields || [])) {
          if (groupName) {
            await client.query(
              `INSERT INTO share_alter_hidden_groups
               (share_code, alter_uuid, group_name) VALUES ($1, $2, $3)`,
              [code, alterUuid, groupName]
            );
          }
        }
      }
    }
    return code;
  });
}

// ── Resolve a share ──────────────────────────────────────────────────

async function resolveShare(shareCode) {
  const { rows } = await pool.query(
    `SELECT s.share_code, s.owner_id,
            s.label_nonce, s.label_cipher, s.share_scope,
            s.created_at, s.expires_at, s.is_active,
            u.name_nonce AS owner_nn, u.name_cipher AS owner_nc
     FROM shares s
     LEFT JOIN users u ON s.owner_id = u.user_id
     WHERE s.share_code = $1 AND s.is_active = TRUE`,
    [shareCode]
  );
  if (!rows[0]) return null;

  const info = { ...rows[0] };
  info.label = decryptField(info.label_nonce, info.label_cipher);
  info.owner_name = decryptField(info.owner_nn, info.owner_nc);
  delete info.label_nonce; delete info.label_cipher;
  delete info.owner_nn; delete info.owner_nc;

  // Check expiry
  if (info.expires_at) {
    const exp = new Date(info.expires_at);
    if (Date.now() > exp.getTime()) return null;
  }

  // Fetch alter UUIDs
  const alterRes = await pool.query(
    'SELECT alter_uuid FROM share_alters WHERE share_code = $1',
    [shareCode]
  );
  info.alter_uuids = alterRes.rows.map((r) => r.alter_uuid);

  // Fetch hidden groups per alter
  const hiddenRes = await pool.query(
    'SELECT alter_uuid, group_name FROM share_alter_hidden_groups WHERE share_code = $1',
    [shareCode]
  );
  const hiddenMap = {};
  for (const r of hiddenRes.rows) {
    if (!hiddenMap[r.alter_uuid]) hiddenMap[r.alter_uuid] = [];
    hiddenMap[r.alter_uuid].push(r.group_name);
  }
  info.hidden_map = hiddenMap;

  return toJsonSafe(info);
}

// ── Get shared alters (with privacy filtering) ───────────────────────

async function getSharedAlters(shareCode) {
  const share = await resolveShare(shareCode);
  if (!share) return null;

  const raw = await readUserData(share.owner_id, 'alters');
  if (!raw) return [];

  const allAlters = JSON.parse(raw);
  let result;
  if (share.share_scope === 'all') {
    result = allAlters;
  } else {
    const allowed = new Set(share.alter_uuids);
    result = allAlters.filter((a) => allowed.has(a.UUID));
  }

  // Strip hidden field groups per alter
  const hiddenMap = share.hidden_map || {};
  for (const alter of result) {
    const hidden = new Set(hiddenMap[alter.UUID] || []);
    for (const h of hidden) {
      delete alter[h];
    }
  }
  return result;
}

// ── List shares I created ────────────────────────────────────────────

async function listShares(ownerId) {
  const { rows } = await pool.query(
    `SELECT s.share_code, s.owner_id,
            s.label_nonce, s.label_cipher, s.share_scope,
            s.created_at, s.expires_at, s.is_active,
            u.name_nonce AS owner_nn, u.name_cipher AS owner_nc
     FROM shares s
     LEFT JOIN users u ON s.owner_id = u.user_id
     WHERE s.owner_id = $1 AND s.is_active = TRUE
     ORDER BY s.created_at DESC`,
    [ownerId]
  );

  const result = [];
  for (const row of rows) {
    const info = { ...row };
    info.label = decryptField(info.label_nonce, info.label_cipher);
    info.owner_name = decryptField(info.owner_nn, info.owner_nc);
    delete info.label_nonce; delete info.label_cipher;
    delete info.owner_nn; delete info.owner_nc;

    const alterRes = await pool.query(
      'SELECT alter_uuid FROM share_alters WHERE share_code = $1',
      [info.share_code]
    );
    const hiddenRes = await pool.query(
      'SELECT alter_uuid, group_name FROM share_alter_hidden_groups WHERE share_code = $1',
      [info.share_code]
    );
    const hiddenMap = {};
    for (const hr of hiddenRes.rows) {
      if (!hiddenMap[hr.alter_uuid]) hiddenMap[hr.alter_uuid] = [];
      hiddenMap[hr.alter_uuid].push(hr.group_name);
    }

    info.alters = alterRes.rows.map((r) => ({
      uuid: r.alter_uuid,
      hidden_fields: hiddenMap[r.alter_uuid] || [],
    }));
    info.alter_uuids = info.alters.map((a) => a.uuid);

    const cntRes = await pool.query(
      'SELECT COUNT(*) AS cnt FROM share_claims WHERE share_code = $1',
      [info.share_code]
    );
    info.claim_count = parseInt(cntRes.rows[0].cnt, 10);

    result.push(toJsonSafe(info));
  }
  return result;
}

// ── Revoke / claim / unclaim ─────────────────────────────────────────

async function revokeShare(ownerId, shareCode) {
  const result = await pool.query(
    'UPDATE shares SET is_active = FALSE WHERE share_code = $1 AND owner_id = $2',
    [shareCode, ownerId]
  );
  return result.rowCount > 0;
}

async function claimShare(shareCode, userId) {
  const share = await resolveShare(shareCode);
  if (!share) return null;
  if (share.owner_id === userId) return null; // can't claim own

  return withTransaction(async (client) => {
    await ensureUser(client, userId);
    await client.query(
      `INSERT INTO share_claims (share_code, user_id, claimed_at)
       VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
      [shareCode, userId, now()]
    );
    return share;
  });
}

async function unclaimShare(shareCode, userId) {
  const result = await pool.query(
    'DELETE FROM share_claims WHERE share_code = $1 AND user_id = $2',
    [shareCode, userId]
  );
  return result.rowCount > 0;
}

// ── Get claimed shares (shares others shared with me) ────────────────

async function getClaimedShares(userId) {
  const { rows } = await pool.query(
    `SELECT s.share_code, s.owner_id,
            u.name_nonce AS owner_nn, u.name_cipher AS owner_nc,
            s.label_nonce, s.label_cipher,
            s.share_scope, s.created_at, sc.claimed_at
     FROM share_claims sc
     JOIN shares s ON sc.share_code = s.share_code
     LEFT JOIN users u ON s.owner_id = u.user_id
     WHERE sc.user_id = $1 AND s.is_active = TRUE
     ORDER BY sc.claimed_at DESC`,
    [userId]
  );

  const owners = {};
  for (const row of rows) {
    const oid = row.owner_id;
    const ownerName = decryptField(row.owner_nn, row.owner_nc);
    const label = decryptField(row.label_nonce, row.label_cipher);

    if (!owners[oid]) {
      owners[oid] = {
        owner_id: oid,
        owner_name: ownerName || oid.slice(0, 8),
        shares: [],
      };
    }
    owners[oid].shares.push({
      share_code: row.share_code,
      label,
      share_scope: row.share_scope,
      created_at: row.created_at,
      claimed_at: row.claimed_at,
    });
  }
  return toJsonSafe(Object.values(owners));
}

// ── Get share owner info ─────────────────────────────────────────────

async function getShareOwnerInfo(shareCode) {
  const { rows } = await pool.query(
    `SELECT s.owner_id,
            u.name_nonce AS owner_nn, u.name_cipher AS owner_nc,
            s.label_nonce, s.label_cipher
     FROM shares s
     LEFT JOIN users u ON s.owner_id = u.user_id
     WHERE s.share_code = $1 AND s.is_active = TRUE`,
    [shareCode]
  );
  if (!rows[0]) return null;
  const d = { ...rows[0] };
  d.owner_name = decryptField(d.owner_nn, d.owner_nc);
  d.label = decryptField(d.label_nonce, d.label_cipher);
  delete d.owner_nn; delete d.owner_nc;
  delete d.label_nonce; delete d.label_cipher;
  return toJsonSafe(d);
}

module.exports = {
  createShare,
  resolveShare,
  getSharedAlters,
  listShares,
  revokeShare,
  claimShare,
  unclaimShare,
  getClaimedShares,
  getShareOwnerInfo,
};
