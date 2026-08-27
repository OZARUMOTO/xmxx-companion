#!/usr/bin/env bash
# XMXX box deploy — one shot: pruned Monero node + xmxx-companion relay.
#
# Run this ON the box (Ubuntu, nix + Foundation SDK already installed):
#
#   # copy the view key exported from the Prime (Airlock file) to the box first:
#   scp /Volumes/AIRLOCK/xmxx-viewkey.txt mikegotbtc@<box>:~/xmxx-viewkey.txt
#
#   cd ~ && bash deploy-box.sh ~/xmxx-viewkey.txt
#
# What it does:
#   1. checks the box has room for a pruned node (~60 GB)
#   2. installs monerod (nix binary cache, apt fallback)
#   3. clones/builds xmxx-companion with the SDK's cargo (native ELF)
#   4. installs the view key to /etc/xmxx/viewkey.txt
#   5. installs + starts monerod (pruned sync) then the companion
#
# The companion serves the sync page on http://<box>:8787 — the Prime scans
# the QR there. Keys never leave the device; the box only holds the view key.

set -euo pipefail

VIEWKEY="${1:-}"
if [ -z "$VIEWKEY" ]; then
  echo "usage: $0 <path-to-xmxx-viewkey.txt>"
  exit 1
fi
if [ ! -f "$VIEWKEY" ]; then
  echo "error: $VIEWKEY not found"
  exit 1
fi

echo "==> [1/6] disk check (pruned node needs ~60 GB free)"
FREE_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
echo "    free: ${FREE_GB}G"
if [ "${FREE_GB:-0}" -lt 70 ]; then
  echo "error: not enough free space for a pruned Monero node"
  exit 1
fi

echo "==> [2/6] installing monerod"
if command -v monerod >/dev/null 2>&1; then
  echo "    monerod already installed: $(command -v monerod)"
elif command -v nix >/dev/null 2>&1; then
  echo "    installing via nix binary cache..."
  nix profile install nixpkgs#monero || { echo "    nix install failed, trying apt..."; sudo apt-get update -y && sudo apt-get install -y monero; }
  command -v monerod || export PATH="$HOME/.nix-profile/bin:$PATH"
  command -v monerod || { echo "error: monerod not on PATH after install"; exit 1; }
else
  echo "    installing via apt..."
  sudo apt-get update -y && sudo apt-get install -y monero
  command -v monerod || { echo "error: monerod not on PATH after apt install"; exit 1; }
fi
MONEROD_BIN=$(command -v monerod)
echo "    monerod: $MONEROD_BIN"

echo "==> [3/6] building xmxx-companion (SDK cargo, native ELF)"
COMPANION_DIR="$HOME/xmxx-companion"
if [ ! -d "$COMPANION_DIR" ]; then
  git clone https://github.com/OZARUMOTO/xmxx-companion "$COMPANION_DIR"
fi
cd "$COMPANION_DIR"
git pull --ff-only || true
if [ -d "$HOME/.foundation/sdk/current" ]; then
  nix develop "$HOME/.foundation/sdk/current" -c cargo build --release
else
  cargo build --release
fi
sudo install -m 0755 target/release/xmxx-companion /usr/local/bin/xmxx-companion

echo "==> [4/6] installing view key (read-only, root only)"
sudo mkdir -p /etc/xmxx
sudo install -m 0400 "$VIEWKEY" /etc/xmxx/viewkey.txt

echo "==> [5/6] installing services"
sudo useradd -r -M -d /var/lib/monero monero 2>/dev/null || true
sudo mkdir -p /var/lib/monero
sudo chown monero:monero /var/lib/monero
# point the unit at the real monerod path
sudo sed "s|/usr/local/bin/monerod|$MONEROD_BIN|" "$COMPANION_DIR/deploy/monerod.service" | sudo tee /etc/systemd/system/monerod.service >/dev/null
sudo cp "$COMPANION_DIR/deploy/xmxx-companion.service" /etc/systemd/system/xmxx-companion.service
sudo systemctl daemon-reload
sudo systemctl enable monerod xmxx-companion

echo "==> [6/6] starting services"
sudo systemctl restart monerod
echo "    monerod starting (pruned sync — first sync takes a while, runs unattended)."
sudo systemctl restart xmxx-companion

echo
echo "done. status:"
systemctl --no-pager status monerod --lines=3 | head -8 || true
systemctl --no-pager status xmxx-companion --lines=3 | head -8 || true
echo
echo "companion page:  http://$(hostname -I | awk '{print $1}'):8789"
echo "  (port 8789 — 8787/8788 are taken by surf-relay; the Prime scans the QR there)"
echo
echo "monerod sync progress:"
curl -s -m 5 http://127.0.0.1:18081/json_rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":0,"method":"get_info","params":{}}' \
  | grep -o '"height":[0-9]*' | head -1 || echo "  (daemon still starting — try again in a minute)"
