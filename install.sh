#!/usr/bin/env bash
# Portcullis installer for Linux (systemd).
#   sudo bash install.sh             install and start in observe mode (blocks nothing)
#   sudo bash install.sh --enforce   install and start blocking attackers right away
# Read this file before you run it. It only touches /opt/portcullis, /etc/portcullis,
# /var/lib/portcullis and one systemd unit.
set -euo pipefail

SOURCE="https://github.com/BASIL-SAJI-MATHEW/portcullis/archive/refs/heads/main.zip"
PREFIX="/opt/portcullis"
CONF_DIR="/etc/portcullis"
CONF="$CONF_DIR/portcullis.toml"
DATA="/var/lib/portcullis"
UNIT="/etc/systemd/system/portcullis.service"
ENFORCE=0

for arg in "$@"; do
  case "$arg" in
    --enforce) ENFORCE=1 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Please run as root: sudo bash install.sh" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required." >&2; exit 1; }

PY="$(command -v python3 || true)"
if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required (found: ${PY:-none})." >&2
  exit 1
fi

echo "Installing Portcullis into $PREFIX ..."
"$PY" -m venv "$PREFIX"
"$PREFIX/bin/pip" install --quiet --upgrade "$SOURCE"

mkdir -p "$CONF_DIR" "$DATA"
chmod 700 "$CONF_DIR" "$DATA"
if [ ! -f "$CONF" ]; then
  "$PREFIX/bin/portcullis" init --path "$CONF" >/dev/null
  sed -i "s|^path = \"portcullis.db\"|path = \"$DATA/portcullis.db\"|" "$CONF"
  chmod 600 "$CONF"
fi
if [ "$ENFORCE" -eq 1 ]; then
  sed -i 's/^dry_run = true/dry_run = false/' "$CONF"
fi
"$PREFIX/bin/portcullis" check -c "$CONF"

cat > "$UNIT" <<EOF
[Unit]
Description=Portcullis login shield
After=network-online.target

[Service]
ExecStart=$PREFIX/bin/portcullis run -c $CONF
Restart=on-failure
RestartSec=5
# Needs root to read the auth log and edit iptables.
User=root
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now portcullis

echo
echo "Portcullis is running. Dashboard: http://127.0.0.1:8787 (use an SSH tunnel to view it remotely)."
if [ "$ENFORCE" -eq 1 ]; then
  echo "Blocking is ON."
else
  echo "Observe mode: nothing is blocked yet. When you are happy, set dry_run = false in $CONF"
  echo "and run: systemctl restart portcullis"
fi
echo "Logs: journalctl -u portcullis -f"
