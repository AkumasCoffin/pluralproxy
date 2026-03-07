#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  install.sh — First-time setup for Plural Proxy
#  Run as root:  sudo bash install.sh
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
[[ $EUID -ne 0 ]] && fail "This script must be run as root (sudo bash install.sh)"

cd "$APP_DIR" 2>/dev/null || fail "Project directory not found at $APP_DIR"

[[ -f ".env" ]] || fail ".env file not found. Copy example.env and fill it in first:\n         cp example.env .env && nano .env"

info "Starting first-time setup..."

# ── 1. Install Node.js (via NodeSource if not present) ───────────────
if ! command -v node &>/dev/null; then
    info "Installing Node.js 20.x..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    ok "Node.js $(node -v) installed"
else
    ok "Node.js $(node -v) already installed"
fi

# ── 2. Install PM2 globally ──────────────────────────────────────────
if ! command -v pm2 &>/dev/null; then
    info "Installing PM2..."
    npm install -g pm2
    ok "PM2 installed"
else
    ok "PM2 already installed"
fi

# ── 3. Install Python dependencies (for Discord bot) ─────────────────
info "Installing Python dependencies for Discord bot..."
pip3 install -q -r bot/requirements.txt
ok "Python dependencies installed"

# ── 4. Install Node.js backend dependencies ──────────────────────────
info "Installing Node.js backend dependencies..."
cd backend && npm ci --production && cd ..
ok "Backend dependencies installed"

# ── 5. PostgreSQL ────────────────────────────────────────────────────
# Source .env to get PG vars
set -a
# shellcheck disable=SC1091
source <(grep -E '^PG_' .env | sed 's/\r$//')
set +a

DB_NAME="${PG_DATABASE:-did_tracker}"
DB_USER="${PG_USER:-postgres}"

echo ""
read -rp "Install PostgreSQL locally? [y/N] " install_pg
if [[ "${install_pg,,}" == "y" ]]; then
    info "Installing PostgreSQL..."
    apt-get update -qq
    apt-get install -y -qq postgresql postgresql-client >/dev/null
    systemctl enable --now postgresql
    ok "PostgreSQL installed and running"
else
    info "Skipping PostgreSQL install — make sure it's reachable at ${PG_HOST:-localhost}:${PG_PORT:-5432}"
fi

info "Creating database '$DB_NAME'..."
if sudo -u postgres psql -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    warn "Database '$DB_NAME' already exists — skipping creation"
else
    sudo -u postgres createdb "$DB_NAME"
    ok "Database '$DB_NAME' created"
fi

# ── 6. Create directories ────────────────────────────────────────────
info "Creating asset directories..."
mkdir -p assets/images
chown -R "$APP_USER":"$APP_USER" assets/
ok "Directories created"

# ── 7. Fix Windows line endings ──────────────────────────────────────
info "Fixing line endings..."
find . -maxdepth 1 -name '*.html' -o -name '.env' | xargs -r sed -i 's/\r$//'
find bot/ -name '*.py' | xargs -r sed -i 's/\r$//'
ok "Line endings fixed"

# ── 8. Generate encryption key (if not already set) ──────────────────
if grep -q '^DATA_ENCRYPTION_KEY=' .env 2>/dev/null; then
    ok "DATA_ENCRYPTION_KEY already set in .env"
else
    info "Generating DATA_ENCRYPTION_KEY..."
    KEY=$(python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())")
    echo "" >> .env
    echo "# AES-256 encryption key for user data at rest (DO NOT LOSE THIS)" >> .env
    echo "DATA_ENCRYPTION_KEY=$KEY" >> .env
    ok "DATA_ENCRYPTION_KEY generated and appended to .env"
    warn "*** BACK UP your .env file — losing this key = losing ALL data ***"
fi

# ── 9. Lock down .env ───────────────────────────────────────────────
info "Securing .env file..."
chmod 640 .env
chown root:"$APP_USER" .env
ok ".env secured (640, root:$APP_USER)"

# ── 10. Start Node.js backend via PM2 ───────────────────────────────
info "Starting Node.js backend..."
pm2 delete plural-proxy-backend 2>/dev/null || true
pm2 start backend/server.js --name plural-proxy-backend --cwd "$APP_DIR"
ok "Backend started via PM2"

# ── 11. Start Discord bot via PM2 ───────────────────────────────────
info "Starting Discord bot..."
pm2 delete plural-proxy-bot 2>/dev/null || true
pm2 start bot/bot.py --name plural-proxy-bot --interpreter python3 --cwd "$APP_DIR"
ok "Discord bot started via PM2"

# ── 12. Save PM2 and enable startup ─────────────────────────────────
pm2 save
info "Run 'pm2 startup' to enable auto-start on boot."

# ── Done ──────────────────────────────────────────────────────────────
echo ""
echo -e "\e[1;32m══════════════════════════════════════════════════════════════\e[0m"
echo -e "\e[1;32m  Install complete!\e[0m"
echo -e "\e[1;32m══════════════════════════════════════════════════════════════\e[0m"
echo ""
echo "  Services running:"
echo "    • Backend:     pm2 status plural-proxy-backend"
echo "    • Discord bot: pm2 status plural-proxy-bot"
echo ""
echo "  Next steps:"
echo "    1. Point your reverse proxy (nginx/Caddy) to http://localhost:3001"
echo "    2. Set up Clerk: Dashboard → Social Connections → Discord → ON"
echo "    3. Enable auto-start: pm2 startup && pm2 save"
echo ""
echo -e "  \e[1;33m⚠  BACK UP YOUR .env FILE!\e[0m"
echo "  Losing DATA_ENCRYPTION_KEY = ALL user data is unrecoverable."
echo ""
