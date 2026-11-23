#!/usr/bin/env bash
# Idempotent, re-runnable Ubuntu 24.04 EC2 provisioning & deployment script for primary-miner.
# Usage (run on EC2 Ubuntu t3.micro as ubuntu user with sudo):
#   PRIMARY_DOMAIN="your-sub.duckdns.org" REPO_URL="https://github.com/danielamodu/primary-miner.git" bash scripts/deploy-ec2.sh
set -euo pipefail

PRIMARY_DOMAIN="${PRIMARY_DOMAIN:-}"
REPO_URL="${REPO_URL:-https://github.com/danielamodu/primary-miner.git}"
APP_DIR="${APP_DIR:-/opt/primary}"
BRANCH="${BRANCH:-master}"

if [[ -z "$PRIMARY_DOMAIN" ]]; then
  echo "ERROR: PRIMARY_DOMAIN is required (e.g. PRIMARY_DOMAIN=primary-miner.duckdns.org)" >&2
  exit 1
fi

echo "==> [1/6] Ensuring base packages & Node.js 24 LTS..."
sudo apt-get update -y
sudo apt-get install -y curl git ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https

if ! command -v node >/dev/null 2>&1 || [[ "$(node -v | sed 's/v//' | cut -d. -f1)" -lt 24 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi
echo "Node version: $(node -v)"

echo "==> [2/6] Ensuring Caddy (automatic Let's Encrypt HTTPS)..."
if ! command -v caddy >/dev/null 2>&1; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y caddy
fi
sudo mkdir -p /var/log/caddy
sudo chown -R caddy:caddy /var/log/caddy

echo "==> [3/6] Syncing primary-miner repo into ${APP_DIR}..."
sudo mkdir -p "${APP_DIR}"
sudo chown -R "${USER}:${USER}" "${APP_DIR}"
if [[ -d "${APP_DIR}/.git" ]]; then
  git -C "${APP_DIR}" fetch origin
  git -C "${APP_DIR}" checkout "${BRANCH}"
  git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
else
  git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
fi

echo "==> [4/6] Installing dependencies & running verification tests..."
cd "${APP_DIR}"
npm ci --no-audit --no-fund
npm run typecheck
npm run test:all

echo "==> [5/6] Installing systemd service & Caddyfile for ${PRIMARY_DOMAIN}..."
sudo cp "${APP_DIR}/deploy/primary.service" /etc/systemd/system/primary.service
sudo systemctl daemon-reload
sudo systemctl enable primary.service
sudo systemctl restart primary.service

# Configure Caddy environment and Caddyfile idempotently
sudo mkdir -p /etc/systemd/system/caddy.service.d
cat <<EOF | sudo tee /etc/systemd/system/caddy.service.d/override.conf >/dev/null
[Service]
Environment="PRIMARY_DOMAIN=${PRIMARY_DOMAIN}"
EOF
sudo cp "${APP_DIR}/deploy/Caddyfile" /etc/caddy/Caddyfile
sudo systemctl daemon-reload
sudo systemctl enable caddy
sudo systemctl restart caddy

echo "==> [6/6] Verifying local and HTTPS health..."
sleep 2
curl -fsS "http://127.0.0.1:3001/health" | head -c 300
echo ""
if curl -fsS --max-time 15 "https://${PRIMARY_DOMAIN}/health" >/dev/null; then
  echo "HTTPS_VERIFY_OK: https://${PRIMARY_DOMAIN}/health"
else
  echo "NOTE: Local service is healthy on 127.0.0.1:3001; HTTPS on https://${PRIMARY_DOMAIN} may still be issuing its Let's Encrypt cert (check: sudo journalctl -u caddy -n 30)."
fi
echo "==> Deploy complete."
