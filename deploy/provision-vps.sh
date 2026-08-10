#!/usr/bin/env bash
# Provision a fresh Ubuntu 22.04 VPS to run cyberdudebivash_army_backend.py.
#
# Run this ON THE VPS itself, as root (or via sudo), after you've pointed
# DNS at it (see deploy/README.md — DNS/Cloudflare steps are NOT part of
# this script, since they happen in a dashboard this script has no access
# to). TLS (certbot) is deliberately NOT run automatically here — it needs
# DNS already resolving to this box and an interactive prompt for your
# email/ToS acceptance. Run the printed certbot command yourself once DNS
# is confirmed.
#
# Usage: sudo bash provision-vps.sh [repo_url] [domain]
set -euo pipefail

REPO_URL="${1:-https://github.com/cyberdudebivash-pvt-ltd/CYBERDUDEBIVASH-AI-SECURITY-HUB-ARMY.git}"
DOMAIN="${2:-api.cyberdudebivash.in}"
APP_USER="cyberdudebivash"
APP_ROOT="/opt/cyberdudebivash-api"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this as root (sudo bash provision-vps.sh)." >&2
  exit 1
fi

echo "==> [1/8] apt update + base packages"
apt-get update -qq
apt-get install -y python3 python3-venv python3-pip git nginx certbot python3-certbot-nginx ufw

echo "==> [2/8] Firewall — allow SSH, HTTP, HTTPS only"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "==> [3/8] Create dedicated service user (no shell, no login)"
if ! id "$APP_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

echo "==> [4/8] Clone repo + Python venv"
mkdir -p "$APP_ROOT"
if [ -d "$APP_ROOT/app/.git" ]; then
  git -C "$APP_ROOT/app" pull origin main
else
  git clone --depth 1 "$REPO_URL" "$APP_ROOT/app"
fi
python3 -m venv "$APP_ROOT/venv"
"$APP_ROOT/venv/bin/pip" install --quiet --upgrade pip
"$APP_ROOT/venv/bin/pip" install --quiet -r "$APP_ROOT/app/requirements.txt"

echo "==> [5/8] .env"
if [ ! -f "$APP_ROOT/.env" ]; then
  cp "$APP_ROOT/app/deploy/.env.example" "$APP_ROOT/.env"
fi
chown -R "$APP_USER:$APP_USER" "$APP_ROOT"
chmod 600 "$APP_ROOT/.env"

echo "==> [6/8] systemd units (API service + KEV-seed timer)"
cp "$APP_ROOT/app/deploy/systemd/cyberdudebivash-api.service" /etc/systemd/system/
cp "$APP_ROOT/app/deploy/systemd/cyberdudebivash-kev-seed.service" /etc/systemd/system/
cp "$APP_ROOT/app/deploy/systemd/cyberdudebivash-kev-seed.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cyberdudebivash-api.service
systemctl enable --now cyberdudebivash-kev-seed.timer

echo "==> [7/8] nginx (HTTP only for now — certbot adds the HTTPS block for you)"
sed "s/api\.cyberdudebivash\.in/${DOMAIN}/g" "$APP_ROOT/app/deploy/nginx/cyberdudebivash-api.conf" \
  > /etc/nginx/sites-available/cyberdudebivash-api.conf
ln -sf /etc/nginx/sites-available/cyberdudebivash-api.conf /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

echo "==> [8/8] Done with automated steps."
echo ""
echo "Verify locally on this VPS right now (bypasses DNS/Cloudflare entirely):"
echo "  curl http://127.0.0.1:8000/api/health"
echo "  curl http://127.0.0.1/api/health   # through nginx"
echo ""
echo "REMAINING MANUAL STEPS (see deploy/README.md for full detail):"
echo "  1. Point DNS for ${DOMAIN} at this server's IP (Cloudflare dashboard)."
echo "  2. Once DNS resolves here, run:"
echo "       certbot --nginx -d ${DOMAIN}"
echo "     This adds the HTTPS server block + redirect automatically and reloads nginx."
echo "  3. Set Cloudflare's SSL/TLS mode to 'Full (strict)' for this hostname."
echo "  4. Seed real data once: sudo -u $APP_USER $APP_ROOT/venv/bin/python $APP_ROOT/app/deploy/seed_kev_feed.py"
echo "     (the systemd timer will also run this automatically every 6h from now on)"
