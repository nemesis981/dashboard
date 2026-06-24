#!/bin/bash
# Nemesis Agent — Linux Installer
set -e

INSTALL_DIR="/opt/nemesis-agent"
SERVICE_NAME="nemesis-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

step()  { echo -e "\n==> $1"; }
ok()    { echo "    [OK] $1"; }
warn()  { echo "    [!!] $1"; }
fail()  { echo "    [FAIL] $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then fail "Run as root: sudo bash install_linux.sh"; fi

# ── 1. Python 3.8+ ──────────────────────────────────────────────────────────
step "Checking Python..."
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$($cmd --version 2>&1 | awk '{print $2}')
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
            PYTHON="$cmd"
            ok "Found $cmd $VER"
            break
        fi
    fi
done
if [ -z "$PYTHON" ]; then
    step "Installing Python..."
    apt-get install -y python3 python3-pip &>/dev/null
    PYTHON="python3"
    ok "Python installed"
fi

# ── 2. System packages ──────────────────────────────────────────────────────
step "Installing system dependencies..."
apt-get install -y libnotify-bin python3-pip &>/dev/null || true
ok "System packages ready"

# ── 3. pip packages ─────────────────────────────────────────────────────────
step "Installing Python packages..."
"$PYTHON" -m pip install --upgrade pip --quiet
"$PYTHON" -m pip install requests psutil watchdog plyer --quiet
ok "Packages installed"

# ── 4. Copy agent files ──────────────────────────────────────────────────────
step "Installing agent to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp -r "$SCRIPT_DIR/." "$INSTALL_DIR/"
ok "Files copied"

# ── 5. Configure ────────────────────────────────────────────────────────────
step "Configuring agent..."
CONF="$INSTALL_DIR/nemesis_agent.conf"
if [ ! -f "$CONF" ]; then
    cat > "$CONF" <<EOF
[nemesis]
nemesis_ip = REPLACE_ME
nemesis_port = 5001
nemesis_subnet = 192.168.4.0/22
device_name = My Linux PC
device_id =
poll_interval = 300
suricata_enabled = false
suricata_profile = auto
scan_on_reconnect = true
last_scan_at =
EOF
fi

if grep -q "REPLACE_ME" "$CONF"; then
    read -rp "Enter your Nemesis server IP (e.g. 192.168.4.1): " NIP
    sed -i "s/nemesis_ip = REPLACE_ME/nemesis_ip = $NIP/" "$CONF"
fi

read -rp "Enter a friendly name for this device (press Enter to keep current): " DN
if [ -n "$DN" ]; then
    sed -i "s/device_name = .*/device_name = $DN/" "$CONF"
fi
ok "Configuration saved"

# ── 6. Systemd service ───────────────────────────────────────────────────────
step "Creating systemd service..."
PYTHON_PATH="$(command -v "$PYTHON")"
CURRENT_USER="${SUDO_USER:-$(whoami)}"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Nemesis Security Agent
After=network.target

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON_PATH} ${INSTALL_DIR}/agent.py
Restart=always
RestartSec=10
StandardOutput=append:${INSTALL_DIR}/nemesis_agent.log
StandardError=append:${INSTALL_DIR}/nemesis_agent.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
ok "Service created and enabled"

# ── 7. Start agent ────────────────────────────────────────────────────────────
step "Starting Nemesis Agent..."
systemctl start "$SERVICE_NAME"
sleep 2
systemctl is-active "$SERVICE_NAME" &>/dev/null && ok "Agent running" || warn "Check logs: journalctl -u $SERVICE_NAME"

echo ""
echo "============================================================"
echo "  Nemesis Agent installed successfully!"
echo "  Install dir: $INSTALL_DIR"
echo "  Log file:    $INSTALL_DIR/nemesis_agent.log"
echo "  Config:      $INSTALL_DIR/nemesis_agent.conf"
echo "  Status:      systemctl status $SERVICE_NAME"
echo "============================================================"
