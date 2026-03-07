#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  update.sh — Deploy updates for Plural Proxy
#  Run as root:  sudo bash update.sh
#
#  Use this after uploading or pulling new files.
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────
APP_DIR="/var/www/plural-proxy"
APP_USER="www-data"

# ── Helpers ───────────────────────────────────────────────────────────
info()  { echo -e "\e[1;34m[INFO]\e[0m  $*"; }
ok()    { echo -e "\e[1;32m[OK]\e[0m    $*"; }
warn()  { echo -e "\e[1;33m[WARN]\e[0m  $*"; }
fail()  { echo -e "\e[1;31m[FAIL]\e[0m  $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "This script must be run as root (sudo bash update.sh)"

cd "$APP_DIR" 2>/dev/null || fail "Project directory not found at $APP_DIR"

info "Deploying updates..."

# ── 1. Fix Windows line endings ──────────────────────────────────────
info "Fixing line endings..."
find . -maxdepth 1 -name '*.html' -o -name '.env' | xargs -r sed -i 's/\r$//'
find bot/ -name '*.py' | xargs -r sed -i 's/\r$//'
ok "Line endings fixed"

# ── 2. Install Node.js backend dependencies ──────────────────────────
info "Installing backend dependencies..."
cd backend && npm ci --production && cd ..
ok "Backend dependencies installed"

# ── 3. Fix ownership ─────────────────────────────────────────────────
info "Fixing directory ownership..."
chown -R "$APP_USER":"$APP_USER" assets/
ok "Ownership fixed"

# ── 4. Restart Node.js backend via PM2 ───────────────────────────────
info "Restarting Node.js backend..."
if command -v pm2 &>/dev/null; then
    pm2 restart plural-proxy-backend 2>/dev/null || \
        pm2 start backend/server.js --name plural-proxy-backend --cwd "$APP_DIR"
    ok "Backend restarted"
else
    warn "PM2 not found — backend not restarted"
fi

# ── 5. Restart Discord bot ───────────────────────────────────────────
info "Restarting Discord bot..."
if command -v pm2 &>/dev/null; then
    pm2 restart plural-proxy-bot 2>/dev/null || \
        pm2 start bot/bot.py --name plural-proxy-bot --interpreter python3 --cwd "$APP_DIR"
    ok "Discord bot restarted"
else
    warn "PM2 not found — bot not restarted"
fi

# ── 6. Save PM2 process list ─────────────────────────────────────────
if command -v pm2 &>/dev/null; then
    pm2 save
    ok "PM2 process list saved"
fi

# ── Done ──────────────────────────────────────────────────────────────
echo ""
ok "Update complete!"
echo ""
