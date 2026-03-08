/**
 * User operations — auto-created on first data write.
 */

const { pool, withTransaction, now, toJsonSafe } = require('./db');
const { encryptField, decryptField } = require('./encryption');
const { PROFILE_JSON_TO_COL, PROFILE_COL_TO_JSON } = require('./fields');

// ── Ensure user exists ───────────────────────────────────────────────

async function ensureUser(client, userId) {
  const ts = now();
  await client.query(
    `INSERT INTO users (user_id, created_at, updated_at)
     VALUES ($1, $2, $3) ON CONFLICT (user_id) DO NOTHING`,
    [userId, ts, ts]
  );
}

// ── Get user ─────────────────────────────────────────────────────────

async function getUser(userId) {
  const { rows } = await pool.query(
    `SELECT u.user_id, u.name_nonce, u.name_cipher,
            u.avatar_url, u.friend_code,
            u.created_at, u.updated_at,
            d.discord_id, d.proxy_enabled, d.autoproxy_enabled
     FROM users u
     LEFT JOIN user_discord_settings d ON u.user_id = d.user_id
     WHERE u.user_id = $1`,
    [userId]
  );
  if (!rows[0]) return null;
  const d = { ...rows[0] };
  d.display_name = decryptField(d.name_nonce, d.name_cipher);
  delete d.name_nonce;
  delete d.name_cipher;
  return toJsonSafe(d);
}

// ── Get user by Discord ID ──────────────────────────────────────────

async function getUserByDiscord(discordId) {
  const { rows } = await pool.query(
    `SELECT u.user_id, u.name_nonce, u.name_cipher,
            u.avatar_url, u.friend_code,
            u.created_at, u.updated_at,
            d.discord_id, d.proxy_enabled, d.autoproxy_enabled
     FROM user_discord_settings d
     JOIN users u ON d.user_id = u.user_id
     WHERE d.discord_id = $1`,
    [discordId]
  );
  if (!rows[0]) return null;
  const d = { ...rows[0] };
  d.display_name = decryptField(d.name_nonce, d.name_cipher);
  delete d.name_nonce;
  delete d.name_cipher;
  return toJsonSafe(d);
}

// ── Profile helpers ──────────────────────────────────────────────────

async function getProfileDict(client, userId) {
  const { rows } = await client.query(
    'SELECT * FROM user_profiles WHERE user_id = $1',
    [userId]
  );
  if (!rows[0]) return {};
  const row = rows[0];
  const result = {};
  for (const [colPrefix, jsonKey] of PROFILE_COL_TO_JSON) {
    const val = decryptField(row[`${colPrefix}_nonce`], row[`${colPrefix}_cipher`]);
    if (val) result[jsonKey] = val;
  }
  return result;
}

async function getUserProfile(userId) {
  const { rows } = await pool.query(
    'SELECT name_nonce, name_cipher FROM users WHERE user_id = $1',
    [userId]
  );
  if (!rows[0]) return {};
  const profile = await getProfileDict(pool, userId);
  profile.display_name = decryptField(rows[0].name_nonce, rows[0].name_cipher);
  return profile;
}

async function updateUserProfile(userId, profile) {
  // Shallow-copy to avoid mutating the caller's object
  const data = { ...profile };
  await withTransaction(async (client) => {
    await ensureUser(client, userId);
    const displayName = data.display_name;
    delete data.display_name;
    const ts = now();

    // Delete existing profile rows
    await client.query('DELETE FROM user_profiles WHERE user_id = $1', [userId]);

    // Insert new profile (wide table)
    const cols = ['user_id'];
    const vals = [userId];
    let paramIdx = 2;
    const placeholders = ['$1'];

    for (const [jsonKey, value] of Object.entries(data)) {
      const colPrefix = PROFILE_JSON_TO_COL.get(jsonKey);
      if (colPrefix && value) {
        const { nonce, cipher } = encryptField(String(value));
        cols.push(`${colPrefix}_nonce`, `${colPrefix}_cipher`);
        vals.push(nonce, cipher);
        placeholders.push(`$${paramIdx}`, `$${paramIdx + 1}`);
        paramIdx += 2;
      }
    }

    await client.query(
      `INSERT INTO user_profiles (${cols.join(', ')}) VALUES (${placeholders.join(', ')})`,
      vals
    );

    await client.query(
      'UPDATE users SET updated_at = $1 WHERE user_id = $2',
      [ts, userId]
    );

    if (displayName !== undefined && displayName !== null) {
      const { nonce: nn, cipher: nc } = encryptField(displayName);
      await client.query(
        'UPDATE users SET name_nonce = $1, name_cipher = $2 WHERE user_id = $3',
        [nn, nc, userId]
      );
    }
  });
}

async function syncAvatarUrl(userId, avatarUrl) {
  await withTransaction(async (client) => {
    await ensureUser(client, userId);
    await client.query(
      'UPDATE users SET avatar_url = $1, updated_at = $2 WHERE user_id = $3',
      [avatarUrl || '', now(), userId]
    );
  });
}

module.exports = {
  ensureUser,
  getUser,
  getUserByDiscord,
  getProfileDict,
  getUserProfile,
  updateUserProfile,
  syncAvatarUrl,
};
