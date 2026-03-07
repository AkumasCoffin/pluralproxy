/**
 * AES-256-GCM encryption at rest.
 *
 * Compatible with the Python backend's cryptography library format:
 *   - 12-byte nonce (IV)
 *   - ciphertext || 16-byte GCM auth tag
 */

const crypto = require('crypto');

// ── Key management ───────────────────────────────────────────────────

function getEncryptionKey() {
  const raw = process.env.DATA_ENCRYPTION_KEY || '';
  if (!raw) {
    throw new Error(
      'DATA_ENCRYPTION_KEY not set in .env — ' +
      'run sudo bash install.sh or add it manually'
    );
  }
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) {
    throw new Error(
      `DATA_ENCRYPTION_KEY must be 32 bytes (got ${key.length})`
    );
  }
  return key;
}

// ── Core encrypt / decrypt ───────────────────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM.
 * @param {Buffer} plaintext
 * @returns {{ nonce: Buffer, ciphertext: Buffer }} — ciphertext includes the 16-byte GCM tag
 */
function encrypt(plaintext) {
  const key = getEncryptionKey();
  const nonce = crypto.randomBytes(12); // 96-bit nonce recommended for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  // Match Python format: ciphertext || tag
  return { nonce, ciphertext: Buffer.concat([encrypted, tag]) };
}

/**
 * Decrypt AES-256-GCM ciphertext.
 * @param {Buffer} nonce — 12-byte nonce
 * @param {Buffer} ciphertextWithTag — ciphertext || 16-byte GCM tag
 * @returns {Buffer}
 */
function decrypt(nonce, ciphertextWithTag) {
  const key = getEncryptionKey();
  const tag = ciphertextWithTag.slice(-16);
  const ciphertext = ciphertextWithTag.slice(0, -16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ── Per-field helpers ────────────────────────────────────────────────

/**
 * Encrypt a single text field. Returns { nonce, cipher } or { nonce: null, cipher: null }.
 */
function encryptField(value) {
  if (!value) return { nonce: null, cipher: null };
  const { nonce, ciphertext } = encrypt(Buffer.from(value, 'utf-8'));
  return { nonce, cipher: ciphertext };
}

/**
 * Decrypt a single text field. Returns plaintext string or ''.
 */
function decryptField(nonce, cipher) {
  if (!nonce || !cipher) return '';
  try {
    return decrypt(nonce, cipher).toString('utf-8');
  } catch {
    return '';
  }
}

module.exports = {
  encrypt,
  decrypt,
  encryptField,
  decryptField,
};
