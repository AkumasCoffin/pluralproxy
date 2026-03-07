/**
 * Routes for /api/discord?action=...
 *
 * Mirrors the Python discord_api.py CGI endpoints.
 */

const express = require('express');
const router = express.Router();
const { authenticate } = require('../lib/auth');
const discord = require('../lib/discord');
const { getUser } = require('../lib/users');
const { getAlterInfo, extractAlterName } = require('../lib/alters');

router.use(authenticate);

// ── GET ──────────────────────────────────────────────────────────────

router.get('/', async (req, res) => {
  const action = req.query.action || '';
  try {
    switch (action) {
      case 'status':
        return await handleStatus(req, res);
      case 'proxies':
        return await handleListProxies(req, res);
      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  } catch (err) {
    console.error('[discord GET]', err);
    res.status(500).json({ error: String(err) });
  }
});

// ── POST ─────────────────────────────────────────────────────────────

router.post('/', async (req, res) => {
  const action = req.query.action || '';
  const body = req.body || {};
  try {
    switch (action) {
      case 'auto_link':
        return await handleAutoLink(req, res, body);
      case 'unlink':
        return await handleUnlink(req, res);
      case 'set_fronting':
        return await handleSetFronting(req, res, body);
      case 'add_fronting':
        return await handleAddFronting(req, res, body);
      case 'set_fronting_role':
        return await handleSetFrontingRole(req, res, body);
      case 'remove_fronting':
        return await handleRemoveFronting(req, res, body);
      case 'clear_fronting':
        return await handleClearFronting(req, res);
      case 'set_proxy_enabled':
        return await handleSetProxyEnabled(req, res, body);
      case 'set_autoproxy_enabled':
        return await handleSetAutoproxyEnabled(req, res, body);
      case 'set_proxy':
        return await handleSetProxy(req, res, body);
      case 'remove_proxy':
        return await handleRemoveProxy(req, res, body);
      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  } catch (err) {
    console.error('[discord POST]', err);
    res.status(500).json({ error: String(err) });
  }
});

// ── Handlers ─────────────────────────────────────────────────────────

async function handleStatus(req, res) {
  const user = await getUser(req.userId);
  const linked = Boolean(user && user.discord_id);
  const proxyEnabled = Boolean(user && user.proxy_enabled);
  const autoproxyEnabled = Boolean(user && user.autoproxy_enabled);

  const frontingList = await discord.getFronting(req.userId);
  const frontingAlters = [];
  for (const f of frontingList) {
    const alter = await getAlterInfo(req.userId, f.alter_uuid);
    frontingAlters.push({
      alter_uuid: f.alter_uuid,
      name: alter ? extractAlterName(alter) : 'Unknown',
      role: f.role || 'secondary',
      set_at: f.set_at,
      set_via: f.set_via,
    });
  }

  const proxies = await discord.getProxies(req.userId);
  const proxyList = [];
  for (const p of proxies) {
    const alter = await getAlterInfo(req.userId, p.alter_uuid);
    proxyList.push({
      alter_uuid: p.alter_uuid,
      name: alter ? extractAlterName(alter) : 'Unknown',
      prefix: p.prefix,
      suffix: p.suffix,
    });
  }

  res.json({
    linked,
    discord_id: user ? user.discord_id : null,
    proxy_enabled: proxyEnabled,
    autoproxy_enabled: autoproxyEnabled,
    fronting: frontingAlters,
    proxies: proxyList,
  });
}

async function handleAutoLink(req, res, body) {
  const user = await getUser(req.userId);
  if (user && user.discord_id) {
    return res.json({ ok: true, discord_id: user.discord_id, already_linked: true });
  }

  const frontendId = (body.discord_id || '').trim() || null;
  const discordId = await discord.autoLinkDiscord(req.userId, frontendId);

  if (!discordId) {
    return res.status(400).json({
      error: 'Could not find a Discord connection. Make sure Discord is connected in your account settings.',
    });
  }
  res.json({ ok: true, discord_id: discordId });
}

async function handleUnlink(req, res) {
  await discord.unlinkDiscord(req.userId);
  res.json({ ok: true });
}

async function handleSetFronting(req, res, body) {
  const uuid = (body.alter_uuid || '').trim();
  if (!uuid) return res.status(400).json({ error: 'alter_uuid required' });
  await discord.setFronting(req.userId, uuid, 'site');
  res.json({ ok: true });
}

async function handleAddFronting(req, res, body) {
  const uuid = (body.alter_uuid || '').trim();
  if (!uuid) return res.status(400).json({ error: 'alter_uuid required' });
  const role = body.role || 'secondary';
  await discord.addFronting(req.userId, uuid, 'site', role);
  res.json({ ok: true });
}

async function handleSetFrontingRole(req, res, body) {
  const uuid = (body.alter_uuid || '').trim();
  const role = (body.role || '').trim();
  if (!uuid || !['primary', 'secondary'].includes(role)) {
    return res.status(400).json({ error: 'alter_uuid and role (primary/secondary) required' });
  }
  await discord.setFrontingRole(req.userId, uuid, role);
  res.json({ ok: true });
}

async function handleRemoveFronting(req, res, body) {
  const uuid = (body.alter_uuid || '').trim();
  if (!uuid) return res.status(400).json({ error: 'alter_uuid required' });
  await discord.removeFronting(req.userId, uuid);
  res.json({ ok: true });
}

async function handleClearFronting(req, res) {
  await discord.clearFronting(req.userId);
  res.json({ ok: true });
}

async function handleSetProxyEnabled(req, res, body) {
  const enabled = Boolean(body.enabled);
  await discord.setProxyEnabled(req.userId, enabled);
  res.json({ ok: true, proxy_enabled: enabled });
}

async function handleSetAutoproxyEnabled(req, res, body) {
  const enabled = Boolean(body.enabled);
  await discord.setAutoproxyEnabled(req.userId, enabled);
  res.json({ ok: true, autoproxy_enabled: enabled });
}

async function handleSetProxy(req, res, body) {
  const uuid = (body.alter_uuid || '').trim();
  const prefix = (body.prefix || '').trim();
  const suffix = (body.suffix || '').trim();
  if (!uuid) return res.status(400).json({ error: 'alter_uuid required' });
  if (!prefix && !suffix) return res.status(400).json({ error: 'prefix or suffix required' });
  await discord.setProxy(req.userId, uuid, prefix, suffix);
  res.json({ ok: true });
}

async function handleRemoveProxy(req, res, body) {
  const uuid = (body.alter_uuid || '').trim();
  if (!uuid) return res.status(400).json({ error: 'alter_uuid required' });
  await discord.removeProxy(req.userId, uuid);
  res.json({ ok: true });
}

async function handleListProxies(req, res) {
  const proxies = await discord.getProxies(req.userId);
  const result = [];
  for (const p of proxies) {
    const alter = await getAlterInfo(req.userId, p.alter_uuid);
    result.push({
      alter_uuid: p.alter_uuid,
      name: alter ? extractAlterName(alter) : 'Unknown',
      prefix: p.prefix,
      suffix: p.suffix,
    });
  }
  res.json({ proxies: result });
}

module.exports = router;
