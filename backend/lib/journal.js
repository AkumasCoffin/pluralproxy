/**
 * Journal operations — entries + encrypted tags.
 */

const { pool, withTransaction, now, toJsonSafe } = require('./db');
const { encrypt, decrypt, encryptField, decryptField } = require('./encryption');
const { ensureUser } = require('./users');
const { MAX_JOURNAL_ENTRIES } = require('./config');

// ── Tag helpers (encrypted per-user) ─────────────────────────────────

async function ensureTags(client, userId, tags) {
  // Load existing encrypted tags for this user
  const { rows: existing } = await client.query(
    'SELECT id, name_nonce, name_cipher FROM journal_tags WHERE user_id = $1',
    [userId]
  );
  const existingMap = {}; // lowered name → id
  for (const row of existing) {
    const name = decryptField(row.name_nonce, row.name_cipher);
    if (name) existingMap[name.toLowerCase()] = row.id;
  }

  const tagIds = [];
  for (const tag of tags) {
    if (!tag) continue;
    const key = tag.trim().toLowerCase();
    if (key in existingMap) {
      tagIds.push(existingMap[key]);
    } else {
      const { nonce: nn, cipher: nc } = encryptField(tag.trim());
      const { rows } = await client.query(
        `INSERT INTO journal_tags (user_id, name_nonce, name_cipher)
         VALUES ($1, $2, $3) RETURNING id`,
        [userId, nn, nc]
      );
      const tid = rows[0].id;
      tagIds.push(tid);
      existingMap[key] = tid;
    }
  }
  return tagIds;
}

async function setEntryTags(client, entryId, tagIds) {
  await client.query('DELETE FROM journal_entry_tags WHERE entry_id = $1', [entryId]);
  for (const tagId of tagIds) {
    await client.query(
      'INSERT INTO journal_entry_tags (entry_id, tag_id) VALUES ($1, $2)',
      [entryId, tagId]
    );
  }
}

async function getEntryTags(client, entryId) {
  const { rows } = await client.query(
    `SELECT t.name_nonce, t.name_cipher FROM journal_entry_tags et
     JOIN journal_tags t ON et.tag_id = t.id
     WHERE et.entry_id = $1`,
    [entryId]
  );
  return rows.map((r) => decryptField(r.name_nonce, r.name_cipher));
}

// ── Convert journal row to dict ──────────────────────────────────────

async function journalRowToDict(row, client) {
  const d = { ...row };

  // Decrypt title
  const encTitle = decryptField(d.title_nonce, d.title_cipher);
  d.title = encTitle || d.title || '';
  delete d.title_nonce;
  delete d.title_cipher;

  // Decrypt body
  let body = '';
  if (d.body_nonce && d.body_cipher) {
    try {
      body = decrypt(d.body_nonce, d.body_cipher).toString('utf-8');
    } catch {
      body = '[decryption error]';
    }
  }
  d.body = body;
  delete d.body_nonce;
  delete d.body_cipher;

  // Fetch tags
  d.tags = await getEntryTags(client, d.id);

  return toJsonSafe(d);
}

// ── CRUD ─────────────────────────────────────────────────────────────

async function createJournalEntry(userId, { alterUuid = '', title = '', body = '', tags = [], via = 'site' } = {}) {
  return withTransaction(async (client) => {
    await ensureUser(client, userId);
    const ts = now();
    const { nonce: tn, cipher: tc } = encryptField(title);
    let bn = null, bc = null;
    if (body) {
      const enc = encrypt(Buffer.from(body, 'utf-8'));
      bn = enc.nonce;
      bc = enc.ciphertext;
    }

    const { rows } = await client.query(
      `INSERT INTO journal_entries
       (user_id, alter_uuid, title_nonce, title_cipher,
        body_nonce, body_cipher, created_at, updated_at, via)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [userId, alterUuid || '', tn, tc, bn, bc, ts, ts, via]
    );
    const entryId = rows[0].id;

    const cleanTags = (tags || []).filter((t) => typeof t === 'string' && t.trim());
    if (cleanTags.length) {
      const tagIds = await ensureTags(client, userId, cleanTags);
      await setEntryTags(client, entryId, tagIds);
    }

    return {
      id: entryId,
      alter_uuid: alterUuid || '',
      title,
      body,
      tags: cleanTags,
      created_at: ts,
      updated_at: ts,
      via,
    };
  });
}

async function updateJournalEntry(userId, entryId, { title, body, tags } = {}) {
  return withTransaction(async (client) => {
    const { rows } = await client.query(
      'SELECT * FROM journal_entries WHERE id = $1 AND user_id = $2',
      [entryId, userId]
    );
    if (!rows[0]) return null;

    const ts = now();
    const updates = ['updated_at = $1'];
    const params = [ts];
    let paramIdx = 2;

    if (title !== undefined && title !== null) {
      const { nonce: tn, cipher: tc } = encryptField(title);
      updates.push(`title_nonce = $${paramIdx}`);
      params.push(tn);
      paramIdx++;
      updates.push(`title_cipher = $${paramIdx}`);
      params.push(tc);
      paramIdx++;
    }
    if (body !== undefined && body !== null) {
      if (body) {
        const enc = encrypt(Buffer.from(body, 'utf-8'));
        updates.push(`body_nonce = $${paramIdx}`);
        params.push(enc.nonce);
        paramIdx++;
        updates.push(`body_cipher = $${paramIdx}`);
        params.push(enc.ciphertext);
        paramIdx++;
      } else {
        updates.push('body_nonce = NULL');
        updates.push('body_cipher = NULL');
      }
    }
    if (tags !== undefined && tags !== null) {
      const tagIds = await ensureTags(client, userId, tags);
      await setEntryTags(client, entryId, tagIds);
    }

    params.push(entryId, userId);
    await client.query(
      `UPDATE journal_entries SET ${updates.join(', ')}
       WHERE id = $${paramIdx} AND user_id = $${paramIdx + 1}`,
      params
    );

    // Return fresh
    const { rows: fresh } = await client.query(
      'SELECT * FROM journal_entries WHERE id = $1 AND user_id = $2',
      [entryId, userId]
    );
    return fresh[0] ? journalRowToDict(fresh[0], client) : null;
  });
}

async function deleteJournalEntry(userId, entryId) {
  const result = await pool.query(
    'DELETE FROM journal_entries WHERE id = $1 AND user_id = $2',
    [entryId, userId]
  );
  return result.rowCount > 0;
}

async function getJournalEntry(userId, entryId) {
  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      'SELECT * FROM journal_entries WHERE id = $1 AND user_id = $2',
      [entryId, userId]
    );
    if (!rows[0]) return null;
    return journalRowToDict(rows[0], client);
  } finally {
    client.release();
  }
}

async function listJournalEntries(userId, { alterUuid, tag, limit = 50, offset = 0 } = {}) {
  const client = await pool.connect();
  try {
    let sql = 'SELECT e.* FROM journal_entries e WHERE e.user_id = $1';
    const params = [userId];
    let paramIdx = 2;

    if (alterUuid !== undefined && alterUuid !== null) {
      sql += ` AND e.alter_uuid = $${paramIdx}`;
      params.push(alterUuid);
      paramIdx++;
    }

    // Tag filter: decrypt all user's tags, find matching IDs
    if (tag) {
      const { rows: allTags } = await client.query(
        'SELECT id, name_nonce, name_cipher FROM journal_tags WHERE user_id = $1',
        [userId]
      );
      const matchingIds = allTags
        .filter((r) => decryptField(r.name_nonce, r.name_cipher).toLowerCase() === tag.trim().toLowerCase())
        .map((r) => r.id);

      if (matchingIds.length) {
        const placeholders = matchingIds.map((_, i) => `$${paramIdx + i}`).join(',');
        sql += ` AND e.id IN (SELECT et.entry_id FROM journal_entry_tags et WHERE et.tag_id IN (${placeholders}))`;
        params.push(...matchingIds);
        paramIdx += matchingIds.length;
      } else {
        sql += ' AND FALSE';
      }
    }

    sql += ` ORDER BY e.created_at DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
    params.push(Math.min(limit, 100), offset);

    const { rows } = await client.query(sql, params);
    const result = [];
    for (const row of rows) {
      result.push(await journalRowToDict(row, client));
    }
    return result;
  } finally {
    client.release();
  }
}

async function getJournalTags(userId) {
  const { rows } = await pool.query(
    `SELECT DISTINCT t.name_nonce, t.name_cipher FROM journal_tags t
     JOIN journal_entry_tags et ON t.id = et.tag_id
     JOIN journal_entries e ON et.entry_id = e.id
     WHERE e.user_id = $1`,
    [userId]
  );
  const tags = rows
    .map((r) => decryptField(r.name_nonce, r.name_cipher))
    .filter(Boolean);
  tags.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  return tags;
}

async function countJournalEntries(userId, alterUuid) {
  let sql = 'SELECT COUNT(*) AS cnt FROM journal_entries WHERE user_id = $1';
  const params = [userId];
  if (alterUuid !== undefined && alterUuid !== null) {
    sql += ' AND alter_uuid = $2';
    params.push(alterUuid);
  }
  const { rows } = await pool.query(sql, params);
  return parseInt(rows[0].cnt, 10);
}

module.exports = {
  createJournalEntry,
  updateJournalEntry,
  deleteJournalEntry,
  getJournalEntry,
  listJournalEntries,
  getJournalTags,
  countJournalEntries,
  MAX_JOURNAL_ENTRIES,
};
