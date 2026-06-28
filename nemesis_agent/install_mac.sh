#!/bin/bash
# Nemesis Agent — macOS Installer
set -e

INSTALL_DIR="$HOME/.nemesis-agent"
PLIST_LABEL="com.nemesis.agent"
PLIST_PATH="$HOME/Library/LaunchAgents/${PLIST_LABEL}.plist"

step()  { echo -e "\n==> $1"; }
ok()    { echo "    [OK] $1"; }
warn()  { echo "    [!!] $1"; }
fail()  { echo "    [FAIL] $1"; exit 1; }

# ── 1. Xcode Command Line Tools ──────────────────────────────────────────────
step "Checking Xcode Command Line Tools..."
if ! xcode-select -p &>/dev/null; then
    warn "Not installed — prompting install (follow the dialog)..."
    xcode-select --install || true
    echo "    Re-run this script after Xcode CLT finishes installing."
    exit 0
fi
ok "Xcode CLT present: $(xcode-select -p)"

# ── 2. Python 3.8+ ──────────────────────────────────────────────────────────
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
    fail "Python 3.8+ not found. Install via: brew install python  OR  https://www.python.org/downloads/"
fi

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
nemesis_subnet =
device_name = My Mac
device_id =
poll_interval = 300
suricata_enabled = false
suricata_profile = auto
scan_on_reconnect = true
last_scan_at =
EOF
fi

if grep -q "REPLACE_ME" "$CONF"; then
    read -rp "Enter your Nemesis server address (Tailscale IP or LAN IP): " NIP
    sed -i "" "s/nemesis_ip = REPLACE_ME/nemesis_ip = $NIP/" "$CONF"
fi

read -rp "Enter a friendly name for this device (press Enter to keep current): " DN
if [ -n "$DN" ]; then
    sed -i "" "s/device_name = .*/device_name = $DN/" "$CONF"
fi
ok "Configuration saved"

# ── 6. LaunchAgent plist ──────────────────────────────────────────────────────
step "Creating LaunchAgent..."
PYTHON_PATH="$(command -v "$PYTHON")"
cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON_PATH}</string>
        <string>${INSTALL_DIR}/agent.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${INSTALL_DIR}/nemesis_agent.log</string>
    <key>StandardErrorPath</key>
    <string>${INSTALL_DIR}/nemesis_agent.log</string>
</dict>
</plist>
EOF
ok "LaunchAgent plist created: $PLIST_PATH"

# ── 7. Start agent ────────────────────────────────────────────────────────────
step "Starting Nemesis Agent..."
launchctl load "$PLIST_PATH" 2>/dev/null || true
launchctl start "$PLIST_LABEL" 2>/dev/null || true

echo ""
echo "============================================================"
echo "  Nemesis Agent installed successfully!"
echo "  Install dir: $INSTALL_DIR"
echo "  Log file:    $INSTALL_DIR/nemesis_agent.log"
echo "  Config:      $INSTALL_DIR/nemesis_agent.conf"
echo ""
echo "  NOTE: You may need to grant Full Disk Access in:"
echo "  System Settings → Privacy & Security → Full Disk Access"
echo "============================================================"
