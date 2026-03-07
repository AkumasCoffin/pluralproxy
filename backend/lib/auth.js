/**
 * JWT verification against Clerk's JWKS endpoint.
 *
 * Extracts the Clerk domain from the publishable key, fetches signing
 * keys from /.well-known/jwks.json, and verifies RS256 JWTs.
 */

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { CLERK_PK_FALLBACK, CLERK_FRONTEND_API } = require('./config');

// Cache JWKS clients per URL
const _jwkClients = new Map();

/**
 * Verify a Bearer JWT and return the Clerk user-id (sub claim), or null.
 * @param {string} authHeader — full "Bearer xxx" header
 * @returns {Promise<string|null>}
 */
async function verifyToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.slice(7);
  try {
    // Prefer explicit CLERK_FRONTEND_API env var; fall back to deriving from publishable key
    let jwksUrl;
    if (CLERK_FRONTEND_API) {
      const base = CLERK_FRONTEND_API.replace(/\/+$/, '');
      jwksUrl = `${base}/.well-known/jwks.json`;
    } else {
      const pubKey =
        process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || CLERK_PK_FALLBACK;
      if (!pubKey) {
        console.error('[auth] CLERK publishable key not set');
        return null;
      }
      // Extract domain from publishable key: pk_live_<base64>
      const encoded = pubKey.split('_')[2]; // everything after pk_live_
      const padded = encoded + '='.repeat((4 - (encoded.length % 4)) % 4);
      const domain = Buffer.from(padded, 'base64')
        .toString('utf-8')
        .replace(/\$$/, '');
      jwksUrl = `https://${domain}/.well-known/jwks.json`;
    }

    if (!_jwkClients.has(jwksUrl)) {
      _jwkClients.set(
        jwksUrl,
        jwksClient({
          jwksUri: jwksUrl,
          cache: true,
          rateLimit: true,
          jwksRequestsPerMinute: 10,
        })
      );
    }
    const client = _jwkClients.get(jwksUrl);

    // Decode header to get kid
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header || !decoded.header.kid) {
      return null;
    }

    const signingKey = await client.getSigningKey(decoded.header.kid);
    const publicKey = signingKey.getPublicKey();

    const claims = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
    });
    return claims.sub || null;
  } catch (err) {
    console.error(`[auth] JWT verification failed: ${err.message}`);
    return null;
  }
}

/**
 * Express middleware that verifies the JWT and attaches userId to req.
 * Responds with 401 if invalid.
 */
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  verifyToken(auth)
    .then((userId) => {
      if (!userId) {
        return res.status(401).json({ error: 'Not authenticated' });
      }
      req.userId = userId;
      next();
    })
    .catch(() => {
      res.status(401).json({ error: 'Not authenticated' });
    });
}

module.exports = { verifyToken, authMiddleware, authenticate: authMiddleware };
