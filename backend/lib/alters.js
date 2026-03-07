/**
 * Alter operations — wide-table storage with per-field encryption.
 */

const { v4: uuidv4 } = require('uuid');
const { pool, withTransaction, now, toJsonSafe } = require('./db');
const { encrypt, decrypt, encryptField, decryptField } = require('./encryption');
const { ALTER_JSON_TO_COL, ALTER_COL_TO_JSON, ALTER_COL_PREFIXES } = require('./fields');
const { ensureUser } = require('./users');
const { MAX_BACKUPS_PER_USER } = require('./config');

// ── Reconstruct alter from DB row ────────────────────────────────────

function reconstructAlterFromRow(row) {
  const d = { UUID: row.uuid };
  if (row.image) d.image = row.image;
  if (row.card_color) d.cardColor = row.card_color;
  if (row.avatar_icon) d.avatarIcon = row.avatar_icon;

  // Group fields by groupOrder → (groupName, [(fieldOrder, fieldName, value)])
  const groups = new Map();
  for (const [colPrefix, { groupName, fieldName, groupOrder, fieldOrder }] of ALTER_COL_TO_JSON) {
    const nonce = row[`${colPrefix}_nonce`];
    const cipher = row[`${colPrefix}_cipher`];
    const val = decryptField(nonce, cipher);
    if (!groups.has(groupOrder)) {
      groups.set(groupOrder, { groupName, fields: [] });
    }
    groups.get(groupOrder).fields.push({ fieldOrder, fieldName, val });
  }

  // Sort groups by groupOrder, fields by fieldOrder
  const sortedGroups = [...groups.entries()].sort(([a], [b]) => a - b);
  for (const [, { groupName, fields }] of sortedGroups) {
    fields.sort((a, b) => a.fieldOrder - b.fieldOrder);
    d[groupName] = fields.map(({ fieldName, val }) => ({ [fieldName]: val }));
  }

  return d;
}

async function reconstructAlter(client, userId, alterUuid) {
  const { rows } = await client.query(
    'SELECT * FROM alters WHERE user_id = $1 AND uuid = $2',
    [userId, alterUuid]
  );
  if (!rows[0]) return null;
  return reconstructAlterFromRow(rows[0]);
}

async function reconstructAllAlters(client, userId) {
  const { rows } = await client.query(
    'SELECT * FROM alters WHERE user_id = $1 ORDER BY sort_order',
    [userId]
  );
  return rows.map(reconstructAlterFromRow);
}

// ── Convert alter JSON to column values ──────────────────────────────

function alterJsonToColValues(alter) {
  const colValues = {};
  for (const [key, value] of Object.entries(alter)) {
    if (['UUID', 'image', 'cardColor', 'avatarIcon', 'sort_id'].includes(key)) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const fieldDict of value) {
        if (fieldDict && typeof fieldDict === 'object') {
          for (const [fname, fval] of Object.entries(fieldDict)) {
            const col = ALTER_JSON_TO_COL.get(`${key}\0${fname}`);
            if (col) {
              const { nonce, cipher } = encryptField(
                fval != null ? String(fval) : ''
              );
              colValues[col] = { nonce, cipher };
            }
          }
        }
      }
    }
  }
  return colValues;
}

// ── Backup current alters ────────────────────────────────────────────

async function backupCurrentAlters(client, userId, ts) {
  const alters = await reconstructAllAlters(client, userId);
  if (!alters.length) return;

  const { nonce, ciphertext } = encrypt(Buffer.from(JSON.stringify(alters), 'utf-8'));
  await client.query(
    `INSERT INTO user_data_backups (user_id, data_type, nonce, ciphertext, created_at)
     VALUES ($1, 'alters', $2, $3, $4)`,
    [userId, nonce, ciphertext, ts]
  );
  // Prune old backups
  await client.query(
    `DELETE FROM user_data_backups WHERE id IN (
       SELECT id FROM user_data_backups
       WHERE user_id = $1 AND data_type = 'alters'
       ORDER BY created_at DESC
       OFFSET $2
     )`,
    [userId, MAX_BACKUPS_PER_USER]
  );
}

// ── Write alters to table ────────────────────────────────────────────

async function writeAltersToTable(userId, jsonBytes) {
  const alters = JSON.parse(jsonBytes);
  await withTransaction(async (client) => {
    const ts = now();
    await ensureUser(client, userId);
    await backupCurrentAlters(client, userId, ts);

    // Wipe existing
    await client.query('DELETE FROM alters WHERE user_id = $1', [userId]);

    for (let sortOrder = 0; sortOrder < alters.length; sortOrder++) {
      const alter = alters[sortOrder];
      if (!alter || typeof alter !== 'object') continue;

      const alterUuid = alter.UUID || uuidv4();
      const image = alter.image || '';
      const cardColor = alter.cardColor || '';
      const avatarIcon = alter.avatarIcon || '';

      const colValues = alterJsonToColValues(alter);
      const cols = ['user_id', 'uuid', 'sort_order', 'image', 'card_color',
        'avatar_icon', 'created_at', 'updated_at'];
      const vals = [userId, alterUuid, sortOrder, image, cardColor,
        avatarIcon, ts, ts];

      for (const [cp, { nonce, cipher }] of Object.entries(colValues)) {
        cols.push(`${cp}_nonce`, `${cp}_cipher`);
        vals.push(nonce, cipher);
      }

      const placeholders = vals.map((_, i) => `$${i + 1}`).join(', ');
      await client.query(
        `INSERT INTO alters (${cols.join(', ')}) VALUES (${placeholders})`,
        vals
      );
    }
  });
}

// ── Read / Write user data ───────────────────────────────────────────

async function readUserData(userId, dataType) {
  if (dataType === 'alters') {
    const alters = await reconstructAllAlters(pool, userId);
    if (alters.length) return JSON.stringify(alters);

    // Fallback: check for un-migrated blob
    const { rows } = await pool.query(
      `SELECT nonce, ciphertext FROM user_data
       WHERE user_id = $1 AND data_type = 'alters'`,
      [userId]
    );
    if (rows[0]) {
      return decrypt(rows[0].nonce, rows[0].ciphertext).toString('utf-8');
    }
    return null;
  }

  // relationships (and any future blob types)
  const { rows } = await pool.query(
    'SELECT nonce, ciphertext FROM user_data WHERE user_id = $1 AND data_type = $2',
    [userId, dataType]
  );
  if (!rows[0]) return null;
  return decrypt(rows[0].nonce, rows[0].ciphertext).toString('utf-8');
}

async function writeUserData(userId, dataType, jsonBytes) {
  if (dataType === 'alters') {
    await writeAltersToTable(userId, jsonBytes);
    return;
  }

  // relationships
  await withTransaction(async (client) => {
    const ts = now();
    await ensureUser(client, userId);

    // Move current row into backups
    const { rows } = await client.query(
      'SELECT nonce, ciphertext FROM user_data WHERE user_id = $1 AND data_type = $2',
      [userId, dataType]
    );
    if (rows[0]) {
      await client.query(
        `INSERT INTO user_data_backups (user_id, data_type, nonce, ciphertext, created_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [userId, dataType, rows[0].nonce, rows[0].ciphertext, ts]
      );
      await client.query(
        `DELETE FROM user_data_backups WHERE id IN (
           SELECT id FROM user_data_backups
           WHERE user_id = $1 AND data_type = $2
           ORDER BY created_at DESC OFFSET $3
         )`,
        [userId, dataType, MAX_BACKUPS_PER_USER]
      );
    }

    // Encrypt and upsert
    const data = typeof jsonBytes === 'string' ? Buffer.from(jsonBytes, 'utf-8') : jsonBytes;
    const { nonce, ciphertext } = encrypt(data);
    await client.query(
      `INSERT INTO user_data (user_id, data_type, nonce, ciphertext, updated_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT(user_id, data_type) DO UPDATE SET
         nonce = EXCLUDED.nonce,
         ciphertext = EXCLUDED.ciphertext,
         updated_at = EXCLUDED.updated_at`,
      [userId, dataType, nonce, ciphertext, ts]
    );
  });
}

// ── Alter info helpers ───────────────────────────────────────────────

async function getAlterInfo(userId, alterUuid) {
  return reconstructAlter(pool, userId, alterUuid);
}

function extractAlterName(alter) {
  for (const groupKey of ['Basic Info', 'System Info', 'Identity']) {
    const group = alter[groupKey];
    if (Array.isArray(group)) {
      for (const field of group) {
        if (field && typeof field === 'object' && 'Name' in field) {
          const name = String(field.Name).trim();
          if (name) return name;
        }
      }
    }
  }
  if (alter.Name) return String(alter.Name).trim();
  return 'Unnamed';
}

async function getAllAlters(userId) {
  try {
    return await reconstructAllAlters(pool, userId);
  } catch {
    return [];
  }
}

module.exports = {
  reconstructAlterFromRow,
  reconstructAlter,
  reconstructAllAlters,
  alterJsonToColValues,
  writeAltersToTable,
  readUserData,
  writeUserData,
  getAlterInfo,
  extractAlterName,
  getAllAlters,
};
