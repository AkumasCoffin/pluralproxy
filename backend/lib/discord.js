/**
 * Discord integration — linking, fronting, proxy triggers.
 */

const https = require('https');
const { pool, withTransaction, now, toJsonSafe } = require('./db');
const { encryptField, decryptField } = require('./encryption');
const { ensureUser, getUser, getUserByDiscord } = require('./users');
const { getAlterInfo, extractAlterName } = require('./alters');
const crypto = require('crypto');

// ── Clerk Backend API ────────────────────────────────────────────────

function getDiscordIdFromClerk(userId) {
  return new Promise((resolve) => {
    const secret = process.env.CLERK_SECRET_KEY || '';
    if (!secret) {
      console.error('[discord.js] CLERK_SECRET_KEY not set');
      return resolve(null);
    }

    const url = `https://api.clerk.com/v1/users/${userId}`;
    const req = https.get(url, {
      headers: { Authorization: `Bearer ${secret}` },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          for (const acct of (json.external_accounts || [])) {
            if ((acct.provider || '').toLowerCase().includes('discord')) {
              const pid = acct.provider_user_id;
              if (pid) return resolve(String(pid));
            }
          }
          resolve(null);
        } catch {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

// ── Link / unlink ────────────────────────────────────────────────────

async function linkDiscord(userId, discordId) {
  await withTransaction(async (client) => {
    await ensureUser(client, userId);
    await client.query(
      `INSERT INTO user_discord_settings (user_id, discord_id)
       VALUES ($1, $2)
       ON CONFLICT(user_id) DO UPDATE SET discord_id = EXCLUDED.discord_id`,
      [userId, discordId]
    );
    await client.query(
      'UPDATE users SET updated_at = $1 WHERE user_id = $2',
      [now(), userId]
    );
  });
}

async function unlinkDiscord(userId) {
  await withTransaction(async (client) => {
    await client.query(
      'DELETE FROM user_discord_settings WHERE user_id = $1',
      [userId]
    );
    await client.query(
      'UPDATE discord_proxies SET is_active = FALSE WHERE user_id = $1',
      [userId]
    );
    await client.query(
      'UPDATE users SET updated_at = $1 WHERE user_id = $2',
      [now(), userId]
    );
  });
}

async function autoLinkDiscord(userId, frontendDiscordId = null) {
  let discordId = await getDiscordIdFromClerk(userId);
  if (!discordId && frontendDiscordId) {
    discordId = String(frontendDiscordId).trim();
  }
  if (!discordId) return null;

  // Check if already linked to another account
  const existing = await getUserByDiscord(discordId);
  if (existing && existing.user_id !== userId) return null;

  await linkDiscord(userId, discordId);
  return discordId;
}

// ── Proxy settings ───────────────────────────────────────────────────

async function setProxyEnabled(userId, enabled) {
  await withTransaction(async (client) => {
    await client.query(
      'UPDATE user_discord_settings SET proxy_enabled = $1 WHERE user_id = $2',
      [enabled, userId]
    );
    await client.query(
      'UPDATE users SET updated_at = $1 WHERE user_id = $2',
      [now(), userId]
    );
  });
}

async function setAutoproxyEnabled(userId, enabled) {
  await withTransaction(async (client) => {
    await client.query(
      'UPDATE user_discord_settings SET autoproxy_enabled = $1 WHERE user_id = $2',
      [enabled, userId]
    );
    await client.query(
      'UPDATE users SET updated_at = $1 WHERE user_id = $2',
      [now(), userId]
    );
  });
}

// ── Fronting ─────────────────────────────────────────────────────────

async function getFronting(userId) {
  const { rows } = await pool.query(
    `SELECT * FROM fronting WHERE user_id = $1
     ORDER BY CASE role WHEN 'primary' THEN 0 ELSE 1 END, set_at`,
    [userId]
  );
  return rows.map(toJsonSafe);
}

async function getPrimaryFronting(userId) {
  const { rows } = await pool.query(
    "SELECT * FROM fronting WHERE user_id = $1 AND role = 'primary'",
    [userId]
  );
  return rows[0] ? toJsonSafe(rows[0]) : null;
}

async function setFronting(userId, alterUuid, via = 'site') {
  await withTransaction(async (client) => {
    await ensureUser(client, userId);
    await client.query('DELETE FROM fronting WHERE user_id = $1', [userId]);
    await client.query(
      `INSERT INTO fronting (user_id, alter_uuid, role, set_at, set_via)
       VALUES ($1, $2, 'primary', $3, $4)`,
      [userId, alterUuid, now(), via]
    );
  });
}

async function addFronting(userId, alterUuid, via = 'site', role = 'secondary') {
  if (!['primary', 'secondary'].includes(role)) role = 'secondary';
  await withTransaction(async (client) => {
    await ensureUser(client, userId);
    if (role === 'primary') {
      await client.query(
        "UPDATE fronting SET role = 'secondary' WHERE user_id = $1 AND role = 'primary'",
        [userId]
      );
    }
    await client.query(
      `INSERT INTO fronting (user_id, alter_uuid, role, set_at, set_via)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT(user_id, alter_uuid) DO UPDATE SET
         role = EXCLUDED.role, set_at = EXCLUDED.set_at, set_via = EXCLUDED.set_via`,
      [userId, alterUuid, role, now(), via]
    );
  });
}

async function setFrontingRole(userId, alterUuid, role) {
  if (!['primary', 'secondary'].includes(role)) return;
  await withTransaction(async (client) => {
    if (role === 'primary') {
      await client.query(
        "UPDATE fronting SET role = 'secondary' WHERE user_id = $1 AND role = 'primary'",
        [userId]
      );
    }
    await client.query(
      'UPDATE fronting SET role = $1 WHERE user_id = $2 AND alter_uuid = $3',
      [role, userId, alterUuid]
    );
  });
}

async function removeFronting(userId, alterUuid) {
  await pool.query(
    'DELETE FROM fronting WHERE user_id = $1 AND alter_uuid = $2',
    [userId, alterUuid]
  );
}

async function clearFronting(userId) {
  await pool.query('DELETE FROM fronting WHERE user_id = $1', [userId]);
}

// ── Proxy triggers ───────────────────────────────────────────────────

async function setProxy(userId, alterUuid, prefix = '', suffix = '') {
  await withTransaction(async (client) => {
    await ensureUser(client, userId);
    const { nonce: pn, cipher: pc } = encryptField(prefix);
    const { nonce: sn, cipher: sc } = encryptField(suffix);
    await client.query(
      `INSERT INTO discord_proxies
       (user_id, alter_uuid, prefix_nonce, prefix_cipher, suffix_nonce, suffix_cipher)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT(user_id, alter_uuid) DO UPDATE SET
         prefix_nonce = EXCLUDED.prefix_nonce,
         prefix_cipher = EXCLUDED.prefix_cipher,
         suffix_nonce = EXCLUDED.suffix_nonce,
         suffix_cipher = EXCLUDED.suffix_cipher,
         is_active = TRUE`,
      [userId, alterUuid, pn, pc, sn, sc]
    );
  });
}

async function getProxies(userId) {
  const { rows } = await pool.query(
    `SELECT alter_uuid, prefix_nonce, prefix_cipher,
            suffix_nonce, suffix_cipher
     FROM discord_proxies WHERE user_id = $1 AND is_active = TRUE`,
    [userId]
  );
  return rows.map((r) => ({
    alter_uuid: r.alter_uuid,
    prefix: decryptField(r.prefix_nonce, r.prefix_cipher),
    suffix: decryptField(r.suffix_nonce, r.suffix_cipher),
  }));
}

async function removeProxy(userId, alterUuid) {
  const result = await pool.query(
    'DELETE FROM discord_proxies WHERE user_id = $1 AND alter_uuid = $2',
    [userId, alterUuid]
  );
  return result.rowCount > 0;
}

async function matchProxy(discordId, message) {
  const user = await getUserByDiscord(discordId);
  if (!user) return null;

  const proxyOn = Boolean(user.proxy_enabled);
  const autoproxyOn = Boolean(user.autoproxy_enabled);
  if (!proxyOn && !autoproxyOn) return null;

  // 1. Trigger-based proxy
  if (proxyOn) {
    const proxies = await getProxies(user.user_id);
    for (const p of proxies) {
      if (p.prefix && message.startsWith(p.prefix)) {
        return {
          user_id: user.user_id,
          alter_uuid: p.alter_uuid,
          content: message.slice(p.prefix.length).trim(),
        };
      }
      if (p.suffix && message.endsWith(p.suffix)) {
        return {
          user_id: user.user_id,
          alter_uuid: p.alter_uuid,
          content: message.slice(0, -p.suffix.length).trim(),
        };
      }
    }
  }

  // 2. Auto-proxy fallback
  if (autoproxyOn) {
    const primary = await getPrimaryFronting(user.user_id);
    if (primary) {
      return {
        user_id: user.user_id,
        alter_uuid: primary.alter_uuid,
        content: message,
      };
    }
  }

  return null;
}

module.exports = {
  getDiscordIdFromClerk,
  linkDiscord,
  unlinkDiscord,
  autoLinkDiscord,
  setProxyEnabled,
  setAutoproxyEnabled,
  getFronting,
  getPrimaryFronting,
  setFronting,
  addFronting,
  setFrontingRole,
  removeFronting,
  clearFronting,
  setProxy,
  getProxies,
  removeProxy,
  matchProxy,
};
