#!/usr/bin/env bash
# Nemesis Firewall — Linux Install Script
# Supports Ubuntu 22.04 LTS, 24.04 LTS, 26.04 LTS
# Usage: sudo bash install.sh

###############################################################################
# COLORS & OUTPUT HELPERS
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()    { echo -e "${GREEN}  ✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}  ⚠${NC}  $*"; }
info()  { echo -e "${BLUE}  →${NC}  $*"; }
fail()  { echo -e "${RED}  ✗  ERROR:${NC}  $*" >&2; }

die() {
    fail "$*"
    echo ""
    exit 1
}

step_header() {
    local step="$1" desc="$2"
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  [Step $step]  $desc${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

###############################################################################
# CONFIGURATION VARIABLES (populated during setup, used by all install steps)
###############################################################################

CFG_WATCHDOG_EMAIL=""
CFG_WATCHDOG_PASSWORD=""
CFG_WATCHDOG_TO=""
CFG_SMTP_HOST="smtp.gmail.com"
CFG_SMTP_PORT="587"
CFG_ANTHROPIC_API_KEY=""
CFG_ABUSEIPDB_KEY=""
CFG_IPINFO_TOKEN=""
CFG_PIHOLE_PASSWORD=""
CFG_ANTHROPIC_INPUT_PRICE="3.00"
CFG_ANTHROPIC_OUTPUT_PRICE="15.00"

# Auto-detected in preflight
DETECTED_IFACE=""
DETECTED_IP=""
DETECTED_SUBNET=""
DASHBOARD_DIR=""

# Config file path used by config-first mode
CONF_FILE="./nemesis-install.conf"

###############################################################################
# STEP 1/9 — PREFLIGHT CHECKS
###############################################################################

preflight_checks() {
    step_header "1/9" "Preflight Checks"

    # Must be run with sudo (not 'sudo su && bash')
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root. Please use:  sudo bash install.sh"
    fi

    if [[ -z "${SUDO_USER:-}" ]]; then
        die "Could not determine the real user. Run with: sudo bash install.sh  (not 'sudo su' then bash)"
    fi

    ok "Running as root — real user: $SUDO_USER"

    # Ubuntu version check
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            local ver_major
            ver_major=$(echo "$VERSION_ID" | cut -d. -f1)
            if [[ "$ver_major" -ge 22 ]]; then
                ok "OS: $PRETTY_NAME — supported"
            else
                warn "OS: $PRETTY_NAME is older than Ubuntu 22.04. Install may not work correctly."
            fi
        else
            warn "OS: ${PRETTY_NAME:-unknown} — not Ubuntu. Proceeding, but this is untested."
        fi
    else
        warn "Cannot read /etc/os-release — OS check skipped."
    fi

    # Internet connectivity
    info "Checking internet connectivity..."
    if ! ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
        die "No internet connectivity. Nemesis requires internet access to download dependencies."
    fi
    ok "Internet connectivity confirmed"

    # Auto-detect outbound network interface
    DETECTED_IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || true)
    if [[ -z "$DETECTED_IFACE" ]]; then
        die "Could not auto-detect network interface. Check your network connection."
    fi
    ok "Network interface: $DETECTED_IFACE"

    # Auto-detect this machine's IP
    DETECTED_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -1 || true)
    if [[ -z "$DETECTED_IP" ]]; then
        die "Could not auto-detect IP address."
    fi
    ok "IP address: $DETECTED_IP"

    # Derive local subnet
    local cidr
    cidr=$(ip -o -f inet addr show "$DETECTED_IFACE" 2>/dev/null | awk '{print $4}' | head -1 || true)
    if [[ -n "$cidr" ]]; then
        DETECTED_SUBNET=$(python3 -c \
            "import ipaddress; print(str(ipaddress.ip_interface('$cidr').network))" 2>/dev/null || true)
    fi
    if [[ -z "$DETECTED_SUBNET" ]]; then
        # Fallback: assume /24 from the first three octets
        DETECTED_SUBNET="$(echo "$DETECTED_IP" | grep -oP '^\d+\.\d+\.\d+').0/24"
    fi
    ok "Local subnet: $DETECTED_SUBNET"

    # Confirm dashboard is present
    DASHBOARD_DIR="/home/$SUDO_USER/dashboard"
    if [[ ! -f "$DASHBOARD_DIR/dashboard.py" ]]; then
        die "dashboard.py not found at $DASHBOARD_DIR/dashboard.py" \
            "— is the repo cloned at ~/dashboard for user $SUDO_USER?"
    fi
    ok "Dashboard directory: $DASHBOARD_DIR"
}

###############################################################################
# INPUT HELPERS
###############################################################################

# prompt <varname> <label> [default]
prompt() {
    local _var="$1" _label="$2" _default="${3:-}"
    local _resp
    if [[ -n "$_default" ]]; then
        echo -ne "  ${BOLD}$_label${NC} [default: $_default]: "
    else
        echo -ne "  ${BOLD}$_label${NC}: "
    fi
    read -r _resp
    [[ -z "$_resp" && -n "$_default" ]] && _resp="$_default"
    printf -v "$_var" '%s' "$_resp"
}

# prompt_secret <varname> <label>  — hidden input, no echo
prompt_secret() {
    local _var="$1" _label="$2"
    local _resp
    echo -ne "  ${BOLD}$_label${NC} (hidden): "
    read -rs _resp
    echo ""
    printf -v "$_var" '%s' "$_resp"
}

###############################################################################
# MODE 1 — GUIDED SETUP
###############################################################################

guided_mode() {
    echo ""
    echo -e "  ${BOLD}GUIDED SETUP${NC} — I'll ask each question one at a time."
    echo "  Press Enter to accept the value shown in [brackets]."
    echo "  For optional items, press Enter to skip."
    echo ""

    # ── Email alerts ─────────────────────────────────────────────────────────
    echo -e "  ${BOLD}── Email Alert Settings ─────────────────────────────────────────────${NC}"
    echo "  Nemesis emails you when it detects threats. You need an outbound"
    echo "  email account — a dedicated Gmail address with an App Password works well."
    echo ""
    echo "  Gmail App Passwords: myaccount.google.com → Security → 2-Step → App passwords"
    echo ""

    prompt CFG_WATCHDOG_EMAIL "Email address to SEND alerts FROM (or Enter to skip email setup)" ""
    while [[ -n "$CFG_WATCHDOG_EMAIL" && ! "$CFG_WATCHDOG_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; do
        warn "That doesn't look like a valid email address. Try again, or press Enter to skip."
        prompt CFG_WATCHDOG_EMAIL "Email address to SEND alerts FROM" ""
    done

    if [[ -n "$CFG_WATCHDOG_EMAIL" ]]; then
        prompt_secret CFG_WATCHDOG_PASSWORD "Password or App Password for $CFG_WATCHDOG_EMAIL"
        prompt CFG_WATCHDOG_TO \
            "Email address to RECEIVE alerts (can be the same address)" \
            "$CFG_WATCHDOG_EMAIL"
        prompt CFG_SMTP_HOST \
            "SMTP server hostname  (Hostinger: smtp.hostinger.com, Outlook: smtp.office365.com)" \
            "smtp.gmail.com"
        prompt CFG_SMTP_PORT \
            "SMTP port  (use 465 for SSL, 587 for STARTTLS)" \
            "587"
    else
        info "Skipping email setup — add credentials later in /etc/nemesis.env"
    fi

    echo ""

    # ── Optional API keys ────────────────────────────────────────────────────
    echo -e "  ${BOLD}── Optional API Keys (all free — press Enter to skip any) ───────────${NC}"
    echo ""

    echo "  ${BOLD}Anthropic API key${NC}"
    echo "  Enables AI-powered analysis of security incidents."
    echo "  Free key at: console.anthropic.com"
    prompt CFG_ANTHROPIC_API_KEY "Anthropic API key" ""
    echo ""

    echo "  ${BOLD}AbuseIPDB API key${NC}"
    echo "  Checks whether attacking IPs are known bad actors, and can auto-report them."
    echo "  Free account at: abuseipdb.com"
    prompt CFG_ABUSEIPDB_KEY "AbuseIPDB API key" ""
    echo ""

    echo "  ${BOLD}IPinfo token${NC}"
    echo "  Shows you where attacking IP addresses are located on a map."
    echo "  Free account at: ipinfo.io"
    prompt CFG_IPINFO_TOKEN "IPinfo token" ""
    echo ""

    # ── Confirm before installing ────────────────────────────────────────────
    echo -e "  ${CYAN}${BOLD}── Configuration Summary ─────────────────────────────────────────────${NC}"
    echo ""
    printf "  %-28s %s\n" "Install user:"          "$SUDO_USER"
    printf "  %-28s %s\n" "Dashboard directory:"   "$DASHBOARD_DIR"
    printf "  %-28s %s\n" "Network interface:"     "$DETECTED_IFACE"
    printf "  %-28s %s\n" "IP address:"            "$DETECTED_IP"
    printf "  %-28s %s\n" "Local subnet:"          "$DETECTED_SUBNET"
    echo ""
    printf "  %-28s %s\n" "Alert sender email:"    "${CFG_WATCHDOG_EMAIL:-<not set>}"
    printf "  %-28s %s\n" "Alert recipient email:" "${CFG_WATCHDOG_TO:-<not set>}"
    printf "  %-28s %s\n" "SMTP host:"             "${CFG_SMTP_HOST}"
    printf "  %-28s %s\n" "SMTP port:"             "${CFG_SMTP_PORT}"
    printf "  %-28s %s\n" "Anthropic API key:"     "${CFG_ANTHROPIC_API_KEY:+<set>}${CFG_ANTHROPIC_API_KEY:-<not set>}"
    printf "  %-28s %s\n" "AbuseIPDB key:"         "${CFG_ABUSEIPDB_KEY:+<set>}${CFG_ABUSEIPDB_KEY:-<not set>}"
    printf "  %-28s %s\n" "IPinfo token:"          "${CFG_IPINFO_TOKEN:+<set>}${CFG_IPINFO_TOKEN:-<not set>}"
    echo ""

    local confirm
    echo -ne "  ${BOLD}Proceed with installation? [Y/n]:${NC} "
    read -r confirm
    confirm="${confirm:-y}"
    if [[ "${confirm,,}" != "y" ]]; then
        echo ""
        info "Installation cancelled. Run this script again to start over."
        exit 0
    fi
}

###############################################################################
# MODE 2 — CONFIG-FIRST SETUP
###############################################################################

# read_conf <key> [default]  — reads a value from $CONF_FILE
read_conf() {
    local key="$1" default="${2:-}"
    local val
    val=$(grep -E "^${key}=" "$CONF_FILE" 2>/dev/null \
        | head -1 \
        | cut -d= -f2- \
        | sed 's/^[[:space:]]*//' \
        | sed 's/[[:space:]]*$//' \
        || true)
    echo "${val:-$default}"
}

config_first_mode() {
    echo ""
    echo -e "  ${BOLD}CONFIG-FIRST SETUP${NC} — A config file will be generated for you."
    echo "  Edit it, save (Ctrl+O, Enter), then exit nano (Ctrl+X)."
    echo "  The install will begin automatically after you exit."
    echo ""
    info "Generating $CONF_FILE ..."

    cat > "$CONF_FILE" <<EOF
# ══════════════════════════════════════════════════════════════════════════════
#  Nemesis Firewall — Install Configuration
#  Edit values below, then save (Ctrl+O, Enter) and exit (Ctrl+X).
#  Lines beginning with # are comments — they are ignored.
# ══════════════════════════════════════════════════════════════════════════════

# ── Auto-detected network settings ───────────────────────────────────────────
# Change these only if auto-detection picked the wrong interface or IP.
DETECTED_IFACE=$DETECTED_IFACE
DETECTED_IP=$DETECTED_IP
DETECTED_SUBNET=$DETECTED_SUBNET

# ── Email Alerts ──────────────────────────────────────────────────────────────
# The email address that SENDS alerts. Use a dedicated account, or a Gmail
# address with an App Password (not your main Gmail password).
# Gmail App Passwords: myaccount.google.com → Security → 2-Step → App passwords
WATCHDOG_EMAIL=

# SMTP password or Gmail App Password for the sending account above.
WATCHDOG_PASSWORD=

# The email address that RECEIVES alerts. Can be the same as WATCHDOG_EMAIL.
WATCHDOG_TO=

# SMTP server hostname.
#   Gmail:      smtp.gmail.com
#   Hostinger:  smtp.hostinger.com
#   Outlook:    smtp.office365.com
SMTP_HOST=smtp.gmail.com

# SMTP port: 587 for STARTTLS (recommended), 465 for SSL.
SMTP_PORT=587

# ── Optional API Keys (leave blank to skip) ───────────────────────────────────

# Anthropic API key — enables AI analysis of security incidents.
# Free key at: console.anthropic.com
ANTHROPIC_API_KEY=

# AbuseIPDB API key — checks attacker IP reputation and auto-reports abuse.
# Free account at: abuseipdb.com
ABUSEIPDB_KEY=

# IPinfo token — shows attacker IP geolocation on a map.
# Free account at: ipinfo.io
IPINFO_TOKEN=

# Pi-hole admin password — lets the dashboard read Pi-hole blocking stats.
# NOTE: Pi-hole hasn't installed yet. You can leave this blank now and
# the script will ask you for it after Pi-hole finishes.
PIHOLE_PASSWORD=

# ── AI Cost Estimates ─────────────────────────────────────────────────────────
# Used to display API cost estimates in the dashboard.
# Update if Anthropic changes pricing — see: claude.com/pricing
ANTHROPIC_INPUT_PRICE_PER_MTOK=3.00
ANTHROPIC_OUTPUT_PRICE_PER_MTOK=15.00
EOF

    ok "Config file created: $CONF_FILE"
    echo ""
    info "Opening in nano — edit your settings, then Ctrl+O to save and Ctrl+X to exit."
    sleep 1
    nano "$CONF_FILE"

    # Read values back from the file
    info "Reading configuration from $CONF_FILE ..."

    local conf_iface conf_ip conf_subnet
    conf_iface=$(read_conf "DETECTED_IFACE" "$DETECTED_IFACE")
    conf_ip=$(read_conf "DETECTED_IP" "$DETECTED_IP")
    conf_subnet=$(read_conf "DETECTED_SUBNET" "$DETECTED_SUBNET")
    [[ -n "$conf_iface" ]] && DETECTED_IFACE="$conf_iface"
    [[ -n "$conf_ip" ]]    && DETECTED_IP="$conf_ip"
    [[ -n "$conf_subnet" ]] && DETECTED_SUBNET="$conf_subnet"

    CFG_WATCHDOG_EMAIL=$(read_conf "WATCHDOG_EMAIL")
    CFG_WATCHDOG_PASSWORD=$(read_conf "WATCHDOG_PASSWORD")
    CFG_WATCHDOG_TO=$(read_conf "WATCHDOG_TO" "$CFG_WATCHDOG_EMAIL")
    CFG_SMTP_HOST=$(read_conf "SMTP_HOST" "smtp.gmail.com")
    CFG_SMTP_PORT=$(read_conf "SMTP_PORT" "587")
    CFG_ANTHROPIC_API_KEY=$(read_conf "ANTHROPIC_API_KEY")
    CFG_ABUSEIPDB_KEY=$(read_conf "ABUSEIPDB_KEY")
    CFG_IPINFO_TOKEN=$(read_conf "IPINFO_TOKEN")
    CFG_PIHOLE_PASSWORD=$(read_conf "PIHOLE_PASSWORD")
    CFG_ANTHROPIC_INPUT_PRICE=$(read_conf "ANTHROPIC_INPUT_PRICE_PER_MTOK" "3.00")
    CFG_ANTHROPIC_OUTPUT_PRICE=$(read_conf "ANTHROPIC_OUTPUT_PRICE_PER_MTOK" "15.00")

    ok "Configuration loaded from $CONF_FILE"
}

###############################################################################
# WRITE /etc/nemesis.env
###############################################################################

write_env_file() {
    info "Writing /etc/nemesis.env ..."
    cat > /etc/nemesis.env <<EOF
# Nemesis Firewall — Runtime Configuration
# Edit with:  sudo nano /etc/nemesis.env
# After editing, restart all services:
#   sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner

# ── Email Alerts ──────────────────────────────────────────────────────────────
WATCHDOG_EMAIL=${CFG_WATCHDOG_EMAIL}
WATCHDOG_PASSWORD=${CFG_WATCHDOG_PASSWORD}
WATCHDOG_TO=${CFG_WATCHDOG_TO}
SMTP_HOST=${CFG_SMTP_HOST}
SMTP_PORT=${CFG_SMTP_PORT}

# ── Optional API Keys ─────────────────────────────────────────────────────────
ANTHROPIC_API_KEY=${CFG_ANTHROPIC_API_KEY}
ABUSEIPDB_KEY=${CFG_ABUSEIPDB_KEY}
IPINFO_TOKEN=${CFG_IPINFO_TOKEN}
PIHOLE_PASSWORD=${CFG_PIHOLE_PASSWORD}

# ── AI Cost Estimates ─────────────────────────────────────────────────────────
# Update if Anthropic changes pricing — see: claude.com/pricing
ANTHROPIC_INPUT_PRICE_PER_MTOK=${CFG_ANTHROPIC_INPUT_PRICE}
ANTHROPIC_OUTPUT_PRICE_PER_MTOK=${CFG_ANTHROPIC_OUTPUT_PRICE}
EOF
    ok "/etc/nemesis.env written"
}

###############################################################################
# STEP 2/9 — SYSTEM DEPENDENCIES
###############################################################################

install_system_deps() {
    step_header "2/9" "Installing System Dependencies"

    info "Updating package lists..."
    apt-get update -y

    info "Installing core system packages..."
    apt-get install -y git python3 python3-pip python3-venv curl wget lm-sensors ufw

    info "Installing core Python packages..."
    pip3 install --break-system-packages flask requests psutil

    # Inspect dashboard.py for any third-party imports not yet installed
    info "Checking dashboard.py for additional Python requirements..."
    local extra_pkgs
    extra_pkgs=$(DASHBOARD_PY="$DASHBOARD_DIR/dashboard.py" python3 - <<'PYEOF'
import ast, sys, os, importlib.util

# Packages already handled above or that are stdlib
already_covered = {
    'flask', 'requests', 'psutil',
    # stdlib — not exhaustive but covers common ones
    'json', 'os', 'sys', 're', 'io', 'math', 'time', 'datetime', 'threading',
    'subprocess', 'collections', 'functools', 'pathlib', 'socket', 'struct',
    'hashlib', 'base64', 'logging', 'signal', 'traceback', 'configparser',
    'shutil', 'glob', 'stat', 'copy', 'queue', 'random', 'string', 'textwrap',
    'uuid', 'platform', 'abc', 'typing', 'dataclasses', 'contextlib', 'weakref',
    'enum', 'itertools', 'operator', 'fnmatch', 'tempfile', 'atexit', 'ssl',
    'http', 'urllib', 'email', 'smtplib', 'html', 'sqlite3', 'csv', 'pickle',
    'shelve', 'zlib', 'gzip', 'zipfile', 'tarfile', 'xml', 'pprint', 'inspect',
    'warnings', 'decimal', 'fractions', 'statistics', 'asyncio', 'concurrent',
    'multiprocessing', 'unittest', 'cgi', 'wsgiref', 'webbrowser',
}

dashboard_path = os.environ.get('DASHBOARD_PY', '')
if not dashboard_path or not os.path.exists(dashboard_path):
    sys.exit(0)

try:
    with open(dashboard_path) as f:
        tree = ast.parse(f.read())
except Exception as e:
    print(f"# parse error: {e}", file=sys.stderr)
    sys.exit(0)

imports = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            imports.add(alias.name.split('.')[0])
    elif isinstance(node, ast.ImportFrom):
        if node.module:
            imports.add(node.module.split('.')[0])

stdlib = getattr(sys, 'stdlib_module_names', set())
missing = []
for pkg in sorted(imports - already_covered - stdlib):
    if pkg.startswith('_'):
        continue
    if importlib.util.find_spec(pkg) is None:
        missing.append(pkg)

print(' '.join(missing))
PYEOF
    )

    if [[ -n "$extra_pkgs" ]]; then
        info "Installing additional Python packages: $extra_pkgs"
        # shellcheck disable=SC2086
        pip3 install --break-system-packages $extra_pkgs \
            || warn "Some extra packages failed — check manually if the dashboard misbehaves."
    else
        ok "No additional Python packages needed"
    fi

    ok "System dependencies installed"
}

###############################################################################
# STEP 3/9 — PI-HOLE
###############################################################################

install_pihole() {
    step_header "3/9" "Installing Pi-hole"

    if systemctl is-active --quiet pihole-FTL 2>/dev/null; then
        ok "Pi-hole is already installed and running — skipping"
        return 0
    fi

    echo ""
    echo -e "  ${YELLOW}${BOLD}Pi-hole will now install.${NC}"
    echo "  Follow its prompts — when it finishes, this script will continue automatically."
    echo "  When asked to choose a network interface, select:  ${BOLD}$DETECTED_IFACE${NC}"
    echo ""

    curl -sSL https://install.pi-hole.net | bash

    ok "Pi-hole installation complete"
}

###############################################################################
# STEP 4/9 — SURICATA
###############################################################################

install_suricata() {
    step_header "4/9" "Installing Suricata (Network Intrusion Detection)"

    apt-get install -y suricata

    local yaml_file="/etc/suricata/suricata.yaml"
    if [[ -f "$yaml_file" ]]; then
        info "Configuring Suricata to monitor interface: $DETECTED_IFACE"
        # Replace any interface name under the af-packet section
        sed -i -E "s|(  - interface: )[^ ]+|\1$DETECTED_IFACE|g" "$yaml_file"
        ok "Suricata configured for interface $DETECTED_IFACE"
    else
        warn "/etc/suricata/suricata.yaml not found — configure the interface manually:"
        warn "  sudo nano /etc/suricata/suricata.yaml  (look for 'af-packet')"
    fi

    systemctl enable suricata
    systemctl restart suricata

    if systemctl is-active --quiet suricata; then
        ok "Suricata is running"
    else
        warn "Suricata failed to start — check: sudo journalctl -u suricata -n 20"
    fi
}

###############################################################################
# STEP 5/9 — CLAMAV
###############################################################################

install_clamav() {
    step_header "5/9" "Installing ClamAV (Antivirus)"

    apt-get install -y clamav clamav-daemon

    info "Updating virus definitions — this may take a few minutes..."
    # Stop the daemon first to avoid freshclam database lock conflicts
    systemctl stop clamav-daemon 2>/dev/null || true
    freshclam || warn "freshclam update returned an error — definitions will update on the next scheduled run."

    systemctl enable clamav-daemon
    systemctl start clamav-daemon

    if systemctl is-active --quiet clamav-daemon; then
        ok "ClamAV is running"
    else
        warn "ClamAV daemon failed to start — check: sudo journalctl -u clamav-daemon -n 20"
    fi
}

###############################################################################
# STEP 6/9 — NEMESIS GROUP & PERMISSIONS
###############################################################################

setup_nemesis_group() {
    step_header "6/9" "Nemesis Group & Permissions"

    groupadd nemesis 2>/dev/null || true
    ok "Group 'nemesis' ready"

    usermod -aG nemesis "$SUDO_USER"
    ok "Added $SUDO_USER to nemesis group"

    write_env_file

    chown root:nemesis /etc/nemesis.env
    chmod 640 /etc/nemesis.env
    ok "Permissions set: root:nemesis 640 on /etc/nemesis.env"

    # Sudoers rule — allows the Nemesis user to manage services and run
    # runtime commands (ufw, nmap, tail on logs) without a password prompt.
    local sudoers_file="/etc/sudoers.d/nemesis"
    cat > "$sudoers_file" <<EOF
# Nemesis Firewall — passwordless access for service management and runtime ops
# Generated by install.sh — safe to delete if Nemesis is uninstalled
$SUDO_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl, /usr/bin/tail, /usr/sbin/ufw, /usr/bin/nmap
EOF
    chmod 440 "$sudoers_file"
    if visudo -c -f "$sudoers_file" &>/dev/null; then
        ok "Sudoers rule installed: $SUDO_USER can manage services without a password"
    else
        rm -f "$sudoers_file"
        warn "Sudoers syntax check failed — rule not installed. Service management will prompt for password."
    fi

    echo ""
    echo "  Note: Group membership takes effect on next login."
    echo "  To apply it now in your current terminal:  newgrp nemesis"
}

###############################################################################
# STEP 7/9 — HARDWARE DISCOVERY
###############################################################################

hardware_discovery() {
    step_header "7/9" "Hardware Discovery"

    local discover_script="$DASHBOARD_DIR/alert_manager/hw_discover.py"

    if [[ ! -f "$discover_script" ]]; then
        warn "hw_discover.py not found at $discover_script — skipping."
        warn "Run it manually later from Settings → Hardware → Re-run hardware discovery."
        return 0
    fi

    info "Running hardware discovery — takes about 30 seconds..."
    if sudo -u "$SUDO_USER" python3 "$discover_script"; then
        ok "Hardware discovery complete"
        local hw_map="$DASHBOARD_DIR/alert_manager/hw_map.json"
        if [[ -f "$hw_map" ]]; then
            ok "Sensor map saved to alert_manager/hw_map.json"
        fi
    else
        warn "Hardware discovery returned an error."
        warn "You can re-run it from Settings → Hardware → Re-run hardware discovery."
    fi
}

###############################################################################
# STEP 8/9 — DEPLOY SERVICES
###############################################################################

deploy_services() {
    step_header "8/9" "Deploying Systemd Services"

    local svc_src="$DASHBOARD_DIR/alert_manager"
    local svc_names=("dashboard" "watchdog" "hw-monitor" "alert-watcher" "device-scanner")
    local deployed=0

    for svc in "${svc_names[@]}"; do
        local src="$svc_src/${svc}.service"
        if [[ ! -f "$src" ]]; then
            warn "Service file not found: $src — skipping $svc"
            continue
        fi

        # Replace hardcoded paths and non-root User= fields.
        # User=root and Group=root lines are left unchanged (some services need root).
        sed \
            -e "s|/home/[^/]*/dashboard|/home/$SUDO_USER/dashboard|g" \
            -e "/User=root/b; /Group=root/b; s|^User=.*|User=$SUDO_USER|" \
            "$src" > "/etc/systemd/system/${svc}.service"

        ok "Deployed /etc/systemd/system/${svc}.service"
        deployed=$((deployed + 1))
    done

    if [[ $deployed -eq 0 ]]; then
        warn "No service files were found in $svc_src — services not deployed."
        return 0
    fi

    systemctl daemon-reload
    ok "systemd configuration reloaded"

    for svc in "${svc_names[@]}"; do
        if [[ ! -f "/etc/systemd/system/${svc}.service" ]]; then
            continue
        fi
        if systemctl enable "$svc" 2>/dev/null; then
            ok "Enabled $svc"
        else
            warn "Could not enable $svc"
        fi
        if systemctl start "$svc" 2>/dev/null; then
            ok "Started $svc"
        else
            warn "Could not start $svc — check: sudo journalctl -u $svc -n 20"
        fi
    done
}

###############################################################################
# STEP 9/9 — UFW FIREWALL & COMPLETION
###############################################################################

ufw_and_finish() {
    step_header "9/9" "Firewall Rules & Final Checks"

    info "Configuring UFW firewall..."
    ufw allow from "$DETECTED_SUBNET" to any port 80   comment "Nemesis Dashboard"  2>/dev/null || true
    ufw allow from "$DETECTED_SUBNET" to any port 53   comment "Pi-hole DNS"        2>/dev/null || true
    ufw allow from "$DETECTED_SUBNET" to any port 8080 comment "Pi-hole Admin"      2>/dev/null || true
    ufw allow from "$DETECTED_SUBNET" to any port 22   comment "SSH"                2>/dev/null || true
    ufw --force enable
    ok "UFW enabled with local-network-only rules"

    # Port redirect: Flask runs on 5000 as a non-root user; redirect port 80 → 5000
    # so the dashboard is reachable at http://<ip> without a reverse proxy.
    info "Redirecting port 80 → 5000 for dashboard access..."
    iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000 2>/dev/null \
        || iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000
    iptables -t nat -C OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 5000 2>/dev/null \
        || iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 5000
    if apt-get install -y iptables-persistent 2>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
        ok "Port redirect 80 → 5000 saved (persists across reboots)"
    else
        warn "iptables-persistent not available — port redirect will not survive reboot"
        warn "Re-run:  sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000"
    fi

    # ── Pi-hole password ─────────────────────────────────────────────────────
    if [[ -z "$CFG_PIHOLE_PASSWORD" ]]; then
        echo ""
        echo -e "  ${BOLD}── Pi-hole Admin Password ───────────────────────────────────────────${NC}"
        echo "  Pi-hole is now installed. The Nemesis dashboard reads Pi-hole stats"
        echo "  via its admin API, which requires your Pi-hole admin password."
        echo ""
        prompt_secret CFG_PIHOLE_PASSWORD "Pi-hole admin password (or Enter to skip)"
        if [[ -n "$CFG_PIHOLE_PASSWORD" ]]; then
            sed -i "s|^PIHOLE_PASSWORD=.*|PIHOLE_PASSWORD=$CFG_PIHOLE_PASSWORD|" /etc/nemesis.env
            ok "Pi-hole password saved to /etc/nemesis.env"
        else
            info "Skipped — add it later with:  sudo nano /etc/nemesis.env"
        fi
    fi

    # ── Service status table ─────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}Service Status${NC}"
    echo "  ───────────────────────────────────────────────"
    local all_ok=true
    for svc in dashboard watchdog hw-monitor alert-watcher device-scanner; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            printf "  %-28s ${GREEN}running${NC}\n" "$svc"
        else
            printf "  %-28s ${RED}not running${NC}\n" "$svc"
            all_ok=false
        fi
    done
    echo "  ───────────────────────────────────────────────"

    # ── Final summary ────────────────────────────────────────────────────────
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  Nemesis Firewall — Installation Complete${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Dashboard URL:${NC}    http://$DETECTED_IP"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo ""
    echo "  1. Activate Pi-hole network-wide DNS blocking:"
    echo "     → Log into your router (usually 192.168.1.1 or 192.168.0.1)"
    echo "     → Find DNS settings (under LAN, DHCP, or Advanced)"
    echo "     → Set Primary DNS to: $DETECTED_IP"
    echo ""
    echo "  2. Set a static IP for this machine so its address never changes:"
    echo "     → Find this machine's MAC address:"
    echo "          ip link show $DETECTED_IFACE | grep 'link/ether'"
    echo "     → In your router, create a DHCP reservation for that MAC → $DETECTED_IP"
    echo ""
    echo "  3. Apply the nemesis group to your current terminal session:"
    echo "     → Run:  newgrp nemesis"
    echo "     → Or log out and back in"
    echo ""
    echo -e "  ${BOLD}Your configuration has been saved to /etc/nemesis.env${NC}"
    echo "  To change any setting later, edit that file with:"
    echo "    sudo nano /etc/nemesis.env"
    echo "  Then restart services with:"
    echo "    sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner"
    echo ""

    if [[ "$all_ok" == "false" ]]; then
        echo -e "  ${YELLOW}${BOLD}Some services are not running.${NC} Check logs with:"
        echo "    sudo journalctl -u <service-name> -n 50"
        echo ""
    fi

    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

###############################################################################
# MAIN
###############################################################################

main() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗"
    echo "  ████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝"
    echo "  ██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗"
    echo "  ██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║"
    echo "  ██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║"
    echo "  ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}Firewall — Linux Install Script${NC}"
    echo ""
    echo -e "  ${BOLD}This script will install:${NC}"
    echo "    • Pi-hole       (network-wide DNS-based ad and malware blocking)"
    echo "    • Suricata      (network intrusion detection)"
    echo "    • ClamAV        (antivirus scanning)"
    echo "    • Nemesis       (dashboard and all background services)"
    echo ""
    echo -e "  ${YELLOW}Installation takes approximately 10-15 minutes${NC}"
    echo "  (Pi-hole and Suricata have large downloads)"
    echo ""

    # ── Mode selection ────────────────────────────────────────────────────────
    echo -e "  ${BOLD}Choose a setup mode:${NC}"
    echo ""
    echo "    [1]  Guided Setup  (recommended for first-time installs)"
    echo "         I'll ask each question one at a time with plain-English"
    echo "         explanations. Good if you want to understand what each"
    echo "         setting does as you go."
    echo ""
    echo "    [2]  Config-First Setup"
    echo "         A config file is generated with all options and comments."
    echo "         Edit everything at once in a text editor, then the install"
    echo "         runs automatically. Good if you prefer to review it all"
    echo "         before committing."
    echo ""
    local mode_choice
    echo -ne "  ${BOLD}Enter 1 or 2 [default: 1]:${NC} "
    read -r mode_choice
    mode_choice="${mode_choice:-1}"

    # Preflight always runs first — it populates DETECTED_* vars
    preflight_checks

    case "$mode_choice" in
        1) guided_mode ;;
        2) config_first_mode ;;
        *)
            warn "Unrecognised choice '$mode_choice' — defaulting to Guided Setup."
            guided_mode
            ;;
    esac

    # Install steps — identical regardless of which config mode was used
    install_system_deps
    install_pihole
    install_suricata
    install_clamav
    setup_nemesis_group   # writes /etc/nemesis.env and sets permissions
    hardware_discovery
    deploy_services
    ufw_and_finish
}

main "$@"
