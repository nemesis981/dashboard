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
CFG_DASHBOARD_PASSWORD=""

# Auto-detected in preflight
DETECTED_IFACE=""
DETECTED_IP=""
DETECTED_SUBNET=""
DASHBOARD_DIR=""

# Set by check_for_backup if user wants to restore after install
RESTORE_BACKUP_FILE=""

# Config file path used by config-first mode.
# Anchored to the script's own directory so it works regardless of CWD
# when invoked as 'sudo bash ~/dashboard/install.sh'.
CONF_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nemesis-install.conf"

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

    # Detect if running inside a virtual machine
    INSTALL_MODE="linux_native"
    VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
    if echo "$VIRT" | grep -qiE "oracle|vmware|kvm|virtualbox"; then
        INSTALL_MODE="windows_vm"
        warn "Virtual machine detected ($VIRT) — configuring for Windows/VM mode"
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

    # Install location. Nemesis lives at /opt/nemesis (FHS: add-on application
    # package) with variable state under /var/lib/nemesis, NOT under a user's
    # home. A home-directory install cannot work with de-privileged services:
    # /home/<user> is 0750, so a dedicated service user cannot even traverse it
    # to reach the code, and ProtectHome=yes would hide the app from itself.
    DASHBOARD_DIR="/opt/nemesis"
    if [[ ! -f "$DASHBOARD_DIR/dashboard.py" ]]; then
        # Accept a pre-relocation clone and point the operator at the migration.
        if [[ -f "/home/$SUDO_USER/dashboard/dashboard.py" ]]; then
            die "found an older install at /home/$SUDO_USER/dashboard" \
                "— run scripts/migrate_to_opt.sh to relocate it to $DASHBOARD_DIR first"
        fi
        die "dashboard.py not found at $DASHBOARD_DIR/dashboard.py" \
            "— is the repo cloned to $DASHBOARD_DIR?"
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
    echo "  You will be asked for your sudo password once at the start."
    echo "  After that, the install runs automatically."
    echo ""

    # ── Dashboard login password ─────────────────────────────────────────────
    echo -e "  ${BOLD}── Dashboard Login ──────────────────────────────────────────────────${NC}"
    echo "  The dashboard is protected by HTTP basic auth (username: nemesis)."
    echo "  Choose a password you'll use to log in at http://<your-ip>"
    echo ""
    while [[ -z "$CFG_DASHBOARD_PASSWORD" ]]; do
        prompt_secret CFG_DASHBOARD_PASSWORD "Dashboard login password"
        if [[ -z "$CFG_DASHBOARD_PASSWORD" ]]; then
            warn "Dashboard password cannot be empty."
        fi
    done
    ok "Dashboard password set"
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
    echo "  Enables the AI Engine module — powers Teaching Mode (step-by-step terminal"
    echo "  guidance), Automated Mode (AI executes actions with your approval), automatic"
    echo "  anomaly incident analysis, and 'Get AI Advice' on P1/P2 alerts."
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
    printf "  %-28s %s\n" "Dashboard login:"       "nemesis / <password set>"
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

    # If the config file already exists and has content, skip template generation
    # and nano so the install can be driven non-interactively (CI/automated use).
    if [[ -s "$CONF_FILE" ]]; then
        info "Found existing config: $CONF_FILE — skipping editor"
    else

    info "Generating $CONF_FILE ..."

    cat > "$CONF_FILE" <<EOF
# ══════════════════════════════════════════════════════════════════════════════
#  Nemesis Firewall — Install Configuration
#  Edit values below, then save (Ctrl+O, Enter) and exit (Ctrl+X).
#  Lines beginning with # are comments — they are ignored.
# ══════════════════════════════════════════════════════════════════════════════

# ── Dashboard Login ───────────────────────────────────────────────────────────
# Password for the web dashboard login (username is always 'nemesis').
# This protects the dashboard via nginx HTTP basic auth.
DASHBOARD_PASSWORD=

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

# Anthropic API key — enables the AI Engine module: Teaching Mode, Automated Mode,
# anomaly incident analysis, and "Get AI Advice" on P1/P2 alerts.
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

    fi  # end of "no pre-existing config" block

    # Read values back from the file
    info "Reading configuration from $CONF_FILE ..."

    local conf_iface conf_ip conf_subnet
    conf_iface=$(read_conf "DETECTED_IFACE" "$DETECTED_IFACE")
    conf_ip=$(read_conf "DETECTED_IP" "$DETECTED_IP")
    conf_subnet=$(read_conf "DETECTED_SUBNET" "$DETECTED_SUBNET")
    [[ -n "$conf_iface" ]] && DETECTED_IFACE="$conf_iface"
    [[ -n "$conf_ip" ]]    && DETECTED_IP="$conf_ip"
    [[ -n "$conf_subnet" ]] && DETECTED_SUBNET="$conf_subnet"

    CFG_DASHBOARD_PASSWORD=$(read_conf "DASHBOARD_PASSWORD")
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

# ── Never-Block Exceptions (optional) ─────────────────────────────────────────
# Comma-separated addresses Nemesis must NEVER add a firewall block against,
# however severe the alert. Ships EMPTY on purpose — you probably do not need it.
#
# You do NOT need to list this machine's own addresses or your router/gateway.
# Those are detected automatically every time a block is attempted, from the live
# interface list and the kernel routing table, so they stay correct even when your
# LAN address or gateway changes. Listing them here would add nothing and would go
# stale the moment DHCP moved them.
#
# This is for addresses automation cannot work out on its own — something that
# would break your network if it were ever blocked, but that this machine has no
# way to recognise. For example an internal DNS server, a NAS, or a management
# host on another subnet.
#
# Example:  NEMESIS_NEVER_BLOCK=10.0.0.5,10.0.0.6
NEMESIS_NEVER_BLOCK=

# ── Gateway Mode — OFF, and left off by this installer ───────────────────────
#
# Gateway Mode is when Nemesis sits inline as your network's router rather than
# as a device on it. It is a deliberate, per-deployment choice, not a default:
# it means taking your existing router out of routing duty, and a mistake here
# takes the whole network offline rather than degrading one feature.
#
# BOTH values below must be set for anything to happen. Leaving either blank
# means no source-NAT rule is generated at all -- the safe state is "the rule
# does not exist", not "the rule exists and matches nothing".
#
# ⚠ THESE LIVE HERE, AND NOT IN A SERVICE ENVIRONMENT, FOR A MEASURED REASON.
# The firewall watcher re-renders the ruleset on its own whenever ufw changes,
# in its own environment. Anything passed as a one-off environment variable is
# silently dropped at the next re-render -- observed on the test rig: the rule
# was correct, loaded, and gone within seconds, with traffic then leaving
# un-translated while every status surface reported success. Persisted here, the
# renderer reproduces it on every invocation, including the ones nobody ran.
#
#   NEMESIS_GW_LAN_IFACE  the interface facing your LAN (the side NOT translated)
#   NEMESIS_GW_LAN_CIDR   that LAN's subnet, e.g. 192.168.10.0/24
#
# Example:  NEMESIS_GW_LAN_IFACE=eth1
#           NEMESIS_GW_LAN_CIDR=192.168.10.0/24
NEMESIS_GW_LAN_IFACE=
NEMESIS_GW_LAN_CIDR=
EOF
    ok "/etc/nemesis.env written"
}


verify_gateway_config_path() {
    # PROVE THE RENDERER READS PERSISTED CONFIG -- known-good AND known-bad.
    #
    # This exists because the failure it guards against is silent: if the renderer
    # cannot reproduce gateway config from /etc/nemesis.env, the NAT rule appears
    # once and then disappears at the watcher's next re-render, and every surface
    # still reports success. A check that only confirmed "the file exists" would
    # not catch that, so this renders BOTH ways and requires the answers to differ.
    #
    # Non-fatal: Gateway Mode is optional and off. A failure here means the mode
    # cannot be switched on safely later, which is worth a loud warning at install
    # time rather than a discovery during a network cutover.
    local render="$DASHBOARD_DIR/scripts/nemesis-fw-render"
    [ -x "$render" ] || { warn "nemesis-fw-render not executable — skipping gateway config check"; return 0; }

    local tmp_on tmp_off out_on out_off
    tmp_on="$(mktemp)"; tmp_off="$(mktemp)"
    printf 'NEMESIS_GW_LAN_IFACE=probe0\nNEMESIS_GW_LAN_CIDR=198.51.100.0/24\n' > "$tmp_on"
    : > "$tmp_off"

    out_on="$(NEMESIS_ENV_FILE="$tmp_on" NEMESIS_FW_ENFORCE=0 "$render" render 2>/dev/null | grep -c 'nemesis:nat:gateway-snat' || true)"
    out_off="$(NEMESIS_ENV_FILE="$tmp_off" NEMESIS_FW_ENFORCE=0 "$render" render 2>/dev/null | grep -c 'nemesis:nat:gateway-snat' || true)"
    rm -f "$tmp_on" "$tmp_off"

    if [ "$out_on" = "1" ] && [ "$out_off" = "0" ]; then
        ok "Gateway Mode config path verified (renderer reads /etc/nemesis.env)"
    else
        warn "Gateway Mode config path NOT verified (configured=$out_on, unconfigured=$out_off; expected 1 and 0)."
        warn "  Gateway Mode would not survive a firewall re-render. Do not enable it until this is fixed."
    fi
}

###############################################################################
# STEP 2/9 — SYSTEM DEPENDENCIES
###############################################################################

install_system_deps() {
    step_header "2/9" "Installing System Dependencies"

    info "Updating package lists..."
    apt-get update -y

    info "Installing core system packages..."
    # `acl` provides setfacl, used to grant nemesis-canary traverse-only access to
    # the install user's home so the ransomware canary can see its bait. Usually
    # present on Ubuntu, but the canary silently fails without it — declare it.
    #
    # `nmap` is a HARD dependency of device-scanner: scan_network()
    # (core_module/device_scanner/device_scanner.py:131) shells out to
    # `nmap -sn <subnet>` to sweep the LAN, then reads the MAC addresses the sweep
    # left in /proc/net/arp. It is NOT installed by default on Ubuntu Server and was
    # missing from this list until 2026-08-28 — same class of omission as flask-login
    # below. Without it every scan cycle takes scan_network()'s `except OSError`
    # branch, logs "could not execute nmap", and returns [] — so LAN device discovery
    # silently finds nothing and the devices table stays empty, with no indication in
    # the UI that a package is missing rather than the network being quiet. Confirmed
    # live on a fleet VM that had run this installer: 26 days of 5-minute failures.
    # NOTE: it is used UNPRIVILEGED and needs no sudo grant — see the sudoers block
    # in main() for why `sudo nmap` must not come back.
    apt-get install -y git python3 python3-pip python3-venv curl wget lm-sensors ufw acl nmap

    # HTTP/2 stack for the L3 Tier 2 delivery gate (2026-08-17). Declared here
    # rather than pip-installed for the same reason flask-login is (see below):
    # a `pip install --user` lands in a home directory no service account can
    # read, so the component works for whoever ran it and fails everywhere else.
    #
    # Distro packages specifically: Python on 26.04 is externally-managed
    # (PEP 668), and an appliance wants a dependency that receives distro
    # security updates rather than one pinned at install time.
    #
    # WHY A DEPENDENCY AT ALL, rather than hand-rolling: the gate must DECODE
    # and RE-ENCODE HPACK to inspect HTTP/2 headers -- it cannot forward frames
    # it has not decoded without desynchronising the connection-wide compression
    # state. HPACK is a stateful Huffman-coded codec with its own attack surface
    # (compression bombs, dynamic-table desync). Writing one to sit in a security
    # gate's data path is a large surface to get wrong, and the gate's value is
    # in its holding semantics, not in reimplementing HTTP/2 internals.
    #
    # Without these the gate still runs, but ALPN will not offer h2 and every
    # HTTP/2-capable client silently falls back to HTTP/1.1 -- working, but not
    # what the deployment thinks it is running.
    apt-get install -y python3-h2 python3-hpack python3-hyperframe

    info "Installing core Python packages..."
    # flask-login is a HARD dependency of dashboard.py (module-scope import at
    # dashboard.py:109) and was missing from this list until 2026-07-29 — on this
    # box it only ever existed because someone ran `pip install --user` as the
    # dashboard user, which puts it in ~/.local where no service account can see
    # it. A fresh install would therefore produce a dashboard that cannot start,
    # and it silently broke auto-ticketing for watchdog, hw-monitor and
    # malware-canary (see modules/tickets/module.py). Installed system-wide here
    # so every account that runs Nemesis code can import it.
    pip3 install --break-system-packages flask flask-login requests psutil

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

# Add the project's own directories to sys.path so local modules
# (database, firewall, hw_monitor, etc.) are found and not flagged as missing.
sys.path.insert(0, os.path.join(os.path.dirname(dashboard_path), 'alert_manager'))
sys.path.insert(0, os.path.dirname(dashboard_path))

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
    echo ""

    local pihole_script
    pihole_script=$(mktemp /tmp/pihole-install-XXXXXX.sh)
    info "Downloading Pi-hole installer..."
    if ! curl -sSL https://install.pi-hole.net -o "$pihole_script"; then
        rm -f "$pihole_script"
        die "Failed to download Pi-hole installer. Check your internet connection."
    fi

    if [ -t 1 ]; then
        # Interactive terminal — show Pi-hole's full dialog UI
        echo "  Follow its prompts — when it finishes, this script will continue automatically."
        echo "  When asked to choose a network interface, select:  ${BOLD}$DETECTED_IFACE${NC}"
        echo ""
        bash "$pihole_script"
    else
        # Non-interactive (SSH pipe, CI, etc.) — install with defaults, no dialogs.
        # TERM=xterm is required: Pi-hole uses ncurses even in --unattended mode
        # for a "static IP" notice, and it aborts if $TERM is unset or "unknown".
        info "Non-interactive session detected — installing Pi-hole with defaults."
        info "DNS: Google (8.8.8.8) — change via Pi-hole admin UI at http://$DETECTED_IP:8080"
        echo ""
        TERM=xterm bash "$pihole_script" --unattended
    fi
    rm -f "$pihole_script"

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

        # ── Extended DHCP eve logging (modules/lan_integrity) ────────────────
        # Added 2026-08-30. The `- dhcp:` eve logger is already enabled by
        # default, so rogue-DHCP detection works without this -- server identity
        # comes from the eve record's top-level src_ip. `extended: yes` adds the
        # ADVERTISED routers/dns_servers, which is what separates "an unexpected
        # server answered" from "an unexpected server tried to become your
        # gateway and resolver".
        #
        # It ALSO widens coverage — corrected 2026-08-30 after measurement: with
        # extended off, Suricata logs the ACK only and drops the OFFER entirely,
        # so a rogue server that offers and loses the race is invisible. Detection
        # still functions without this (on ACKs), which is why a failure here is a
        # warning rather than a fatal install error — but it is narrower coverage,
        # not merely less detail.
        #
        # Scoped to the `- dhcp:` block with awk rather than a global sed:
        # several eve loggers carry their own `extended:` key, and a file-wide
        # substitution would silently flip all of them.
        local dhcp_tmp
        dhcp_tmp="$(mktemp)"
        if awk '
            /^[[:space:]]*-[[:space:]]*dhcp:[[:space:]]*$/ { in_dhcp=1; print; next }
            in_dhcp && /^[[:space:]]*-[[:space:]]*[a-z0-9_-]+:[[:space:]]*$/ { in_dhcp=0 }
            in_dhcp && !done && /^[[:space:]]*extended:/ {
                match($0, /^[[:space:]]*/); indent=substr($0, 1, RLENGTH)
                print indent "extended: yes"; done=1; next
            }
            { print }
        ' "$yaml_file" > "$dhcp_tmp" && [[ -s "$dhcp_tmp" ]]; then
            cp -a "$dhcp_tmp" "$yaml_file"
            # VERIFY THE EDIT TOOK. An awk that matched nothing exits 0 and
            # produces a valid file -- indistinguishable from success.
            if grep -A6 -E '^[[:space:]]*-[[:space:]]*dhcp:[[:space:]]*$' "$yaml_file" \
                 | grep -qE '^[[:space:]]*extended:[[:space:]]*yes'; then
                ok "Suricata extended DHCP logging enabled"
            else
                warn "Could not enable Suricata extended DHCP logging — rogue-DHCP"
                warn "detection still works, but advertised gateway/DNS will not be recorded."
                warn "  Fix later with: $DASHBOARD_DIR/scripts/enable-suricata-dhcp-extended.sh"
            fi
        else
            warn "Could not rewrite $yaml_file for extended DHCP logging — skipping"
        fi
        rm -f "$dhcp_tmp"
    else
        warn "/etc/suricata/suricata.yaml not found — configure the interface manually:"
        warn "  sudo nano /etc/suricata/suricata.yaml  (look for 'af-packet')"
    fi

    # ── Host-defence rules ───────────────────────────────────────────────────
    # Added 2026-08-06. Until now this installer set Suricata up and stopped, so
    # every fresh install shipped with ZERO host-defence rules — the rules existed
    # only as a hand-placed file on the development box. The adversarial test that
    # motivated them (full port scans against the Nemesis host running four hours
    # undetected) therefore still applied to every real deployment.
    local rules_src="$DASHBOARD_DIR/config/suricata/local.rules"
    local rules_dest="/etc/suricata/rules/local.rules"

    if [[ -f "$rules_src" ]]; then
        mkdir -p /etc/suricata/rules

        # BOTH halves are required. Deploying the file without registering it in
        # rule-files: leaves it on disk and never loaded — indistinguishable from
        # a working install until something scans the box and nothing alerts.
        if ! grep -q "^[[:space:]]*-[[:space:]]*$rules_dest" "$yaml_file" 2>/dev/null; then
            # Absolute path deliberately: default-rule-path is suricata-update's
            # territory and it rewrites that directory.
            sed -i "\|^rule-files:|a\\  - $rules_dest" "$yaml_file"
            ok "Registered host-defence rules in $yaml_file"
        else
            info "Host-defence rules already registered in $yaml_file"
        fi

        # deploy-suricata-rules.sh resolves @NEMESIS_HOST@, VALIDATES with
        # `suricata -T`, and refuses to install a ruleset that does not parse.
        # That refusal matters more than it looks: a rule that fails to parse does
        # not error at runtime, it simply never loads, and host-defence detection
        # is silently off.
        if "$DASHBOARD_DIR/scripts/deploy-suricata-rules.sh" >/dev/null 2>&1; then
            ok "Host-defence rules deployed and validated"
        else
            # Non-fatal: a box without these rules is the pre-2026-08-06 status
            # quo, not a broken install. But it must be SAID, not swallowed.
            warn "Host-defence rules FAILED to deploy — Suricata is running WITHOUT"
            warn "  them. Re-run manually to see why:"
            warn "  $DASHBOARD_DIR/scripts/deploy-suricata-rules.sh --check"
        fi
    else
        warn "config/suricata/local.rules not found — skipping host-defence rules"
    fi

    systemctl enable suricata
    systemctl restart suricata

    if systemctl is-active --quiet suricata; then
        ok "Suricata is running"
    else
        warn "Suricata failed to start — check: sudo journalctl -u suricata -n 20"
    fi

    # ── QUIC static-policy block (Piece K) ───────────────────────────────────
    # Added 2026-08-06, closing the same gap the host-defence rules had: the
    # roadmap treats the QUIC block as the safe universal counterpart to
    # profile-gated UDP deny ("ship it everywhere"), but it existed only as a
    # hand-placed table on one box. Every fresh install shipped without it.
    #
    # Deployed here rather than in a firewall step on purpose: this is a protocol
    # fingerprint, not access control. It gets its OWN nft table — never ufw, and
    # never `nemesis_enforce`, whose single-authority constraint forbids anything
    # else populating it.
    local quic_src="$DASHBOARD_DIR/config/nftables/nemesis-quic-block.nft"

    if [[ -f "$quic_src" ]]; then
        if ! command -v nft >/dev/null 2>&1; then
            apt-get install -y nftables >/dev/null 2>&1 || true
        fi

        # deploy-quic-block.sh validates with `nft -c -f` BEFORE installing, then
        # verifies the table actually EXISTS afterwards and was not narrowed to a
        # single address family. Both checks matter: an nft ruleset that fails to
        # parse leaves no table at all and the counter reads 0 — which is
        # indistinguishable from "no QUIC has crossed this box yet".
        if "$DASHBOARD_DIR/scripts/deploy-quic-block.sh" >/dev/null 2>&1; then
            ok "QUIC block deployed, enabled and verified"
        else
            # Non-fatal, same judgement as the Suricata rules: a box without this
            # is the pre-2026-08-06 status quo, not a broken install. But say so.
            warn "QUIC block FAILED to deploy — QUIC is NOT being blocked."
            warn "  Re-run to see why:"
            warn "  sudo $DASHBOARD_DIR/scripts/deploy-quic-block.sh --check"
        fi
    else
        warn "config/nftables/nemesis-quic-block.nft not found — skipping QUIC block"
    fi
}

###############################################################################
# STEP 5/9 — CLAMAV
###############################################################################

# ── Memory placement for scan staging and /tmp ────────────────────────────────
#
# MEASURED 2026-08-04, not assumed: this box is RAM-bound, NOT disk-bound.
# CPU iowait 0.0%, ~240 KB/s average writes, and no Nemesis process appears in
# the top disk writers at all (the write load is journald/systemd). Meanwhile
# RAM is the constraint — clamd alone is the single largest RSS consumer.
#
# Two defaults were quietly working against that, both inherited rather than
# chosen:
#
#   1. systemd's tmp.mount ships with size=50%, so /tmp can claim half of RAM.
#      Observed real usage is ~3 MB.
#   2. ClamAV has no TemporaryDirectory by default, so archive extraction
#      stages into /tmp — i.e. into RAM — bounded per scan by MaxScanSize
#      (100M) but unbounded across concurrent scans.
#
# Together that is an unarbitrated claim on the scarce resource, on a box about
# to gain a memory-inspection feature that needs transient RAM headroom and has
# no fallback (you cannot scan memory from disk; temp files can go to an idle
# disk perfectly well).
#
# NOTE: the sizing here is PROVISIONAL. It should be revisited by the RAM
# budget model, which is a shared prerequisite for the memory-injection work
# AND a direct input to the appliance hardware profile (ADR 0014's open
# baseline item) — the hardware spec is a placeholder expected to converge from
# real measurement, which is why the bound below is a PERCENTAGE and not an
# absolute: it must scale with whatever hardware actually lands.
configure_memory_bounds() {
    info "Bounding /tmp and giving ClamAV an explicit scan-staging directory..."

    # -- 1. Bound /tmp -------------------------------------------------------
    # Options= REPLACES the unit's option list wholesale. Every option below is
    # copied verbatim from the shipped unit; ONLY size= differs. Dropping
    # mode=1777 here would break /tmp for every non-root process on the box.
    # `%%` is systemd's escape for a literal percent — not a typo.
    local dropin=/etc/systemd/system/tmp.mount.d
    install -d -m 0755 "$dropin"
    cat > "$dropin/nemesis-size.conf" <<'EOF'
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,size=25%%,nr_inodes=1m,x-systemd.graceful-option=usrquota
EOF
    systemctl daemon-reload

    # A tmpfs remount is non-destructive — it changes the limit, contents
    # survive. Refuses (harmlessly) if current usage already exceeds the new
    # cap, in which case the boot-time value applies instead.
    if mount -o remount,size=25% /tmp 2>/dev/null; then
        ok "/tmp bounded to 25% of RAM (was 50%)"
    else
        warn "/tmp bound written but live remount refused — applies at next boot."
    fi

    # -- 2. Explicit ClamAV scan-staging directory ---------------------------
    # Disk-backed on purpose: disk is the idle resource, RAM is the contended
    # one. Reversible in one line if a future measurement shows scan latency
    # matters more than the RAM this frees.
    local clamav_tmp=/var/tmp/nemesis-clamav
    install -d -o clamav -g clamav -m 0750 "$clamav_tmp" 2>/dev/null \
        || install -d -m 0750 "$clamav_tmp"
    if [ -f /etc/clamav/clamd.conf ]; then
        if grep -qE '^[[:space:]]*TemporaryDirectory' /etc/clamav/clamd.conf; then
            sed -i "s|^[[:space:]]*TemporaryDirectory.*|TemporaryDirectory $clamav_tmp|" \
                /etc/clamav/clamd.conf
        else
            printf 'TemporaryDirectory %s\n' "$clamav_tmp" >> /etc/clamav/clamd.conf
        fi
        ok "ClamAV scan staging set to $clamav_tmp (off tmpfs)"
    else
        warn "clamd.conf not found — ClamAV scan staging left at its default (/tmp)."
    fi

    # -- 3. AppArmor MUST be told about the new path -------------------------
    # NOT optional, and the reason is worth stating: Ubuntu's clamd profile
    # permits /tmp/ and /tmp/** but nothing under /var/tmp. Without this,
    # clamd is DENIED mknod in the staging directory and archive extraction
    # fails — and clamdscan then reports "Infected files: 0" for an archive it
    # never opened. Verified live 2026-08-04: the denial presents as a CLEAN
    # SCAN, not as an error, so every archive would have been silently passed.
    # A config change that turns the scanner off while it keeps saying "clean"
    # is a security regression, so this step fails loudly rather than warning.
    if [ -d /etc/apparmor.d ] && [ -f /etc/apparmor.d/usr.sbin.clamd ]; then
        install -d -m 0755 /etc/apparmor.d/local
        touch /etc/apparmor.d/local/usr.sbin.clamd
        if ! grep -q "nemesis-clamav" /etc/apparmor.d/local/usr.sbin.clamd; then
            printf '  %s/ rw,\n  %s/** krw,\n' "$clamav_tmp" "$clamav_tmp" \
                >> /etc/apparmor.d/local/usr.sbin.clamd
        fi
        if apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd 2>/dev/null; then
            ok "AppArmor updated to allow ClamAV staging in $clamav_tmp"
        else
            # Reverting is safer than shipping a scanner that reports clean
            # because it cannot open anything.
            sed -i "s|^[[:space:]]*TemporaryDirectory.*|TemporaryDirectory /tmp|" \
                /etc/clamav/clamd.conf
            warn "AppArmor reload FAILED — reverted ClamAV staging to /tmp so archive scanning keeps working."
        fi
    fi
}

install_clamav() {
    step_header "5/9" "Installing ClamAV + Malware Detection Dependencies"

    apt-get install -y clamav clamav-daemon

    info "Updating virus definitions — this may take a few minutes..."
    # Stop the daemon first to avoid freshclam database lock conflicts
    systemctl stop clamav-daemon 2>/dev/null || true
    freshclam || warn "freshclam update returned an error — definitions will update on the next scheduled run."

    # Must run BEFORE the daemon starts, or clamd comes up with the old config
    # and keeps staging into tmpfs until something restarts it.
    configure_memory_bounds

    systemctl enable clamav-daemon
    systemctl start clamav-daemon

    if systemctl is-active --quiet clamav-daemon; then
        ok "ClamAV is running"
    else
        warn "ClamAV daemon failed to start — check: sudo journalctl -u clamav-daemon -n 20"
    fi

    # YARA + PE heuristics — required by malware_detection Layer A.
    # yara / python3-yara via apt (avoids needing libyara-dev headers for pip build);
    # pefile has no apt package so pip is the only option.
    info "Installing YARA and PE analysis libraries for malware_detection module..."
    apt-get install -y yara python3-yara \
        || warn "yara apt packages unavailable — trying pip fallback..."  \
        && pip3 install --break-system-packages yara-python 2>/dev/null || true
    pip3 install --break-system-packages pefile \
        || warn "pefile pip install failed — PE heuristics will be disabled."
    ok "Malware detection Python dependencies installed"

    # ── ISO builder — REQUIRED by the detonation sandbox ────────────────────
    #
    # `sandbox.py::_build_iso` puts the suspicious sample on a READ-ONLY ISO and
    # attaches that to the throwaway VM. The read-only ISO is not a convenience:
    # it is the one-way door. A shared folder would let the guest write back to
    # the host, which is exactly what a detonation sandbox must never allow. So
    # with no ISO builder present, detonation does not degrade — it REFUSES, and
    # the whole tier is unavailable.
    #
    # This went undeclared until 2026-08-21. The M3 live proof passed because
    # that session happened to have a copy on PATH from a scratchpad directory;
    # on any fresh install the first real detonation would have failed with
    # "no ISO builder (genisoimage/mkisofs/xorrisofs) available". Same shape as
    # the undeclared `cryptography` dependency found in the agent the same week:
    # a hard requirement that nothing installed and nothing declared.
    info "Installing an ISO builder for the detonation sandbox..."
    apt-get install -y genisoimage \
        || apt-get install -y xorriso \
        || warn "no ISO builder installed — the detonation sandbox will REFUSE to run"
    if command -v genisoimage >/dev/null 2>&1 || command -v mkisofs >/dev/null 2>&1 \
       || command -v xorrisofs >/dev/null 2>&1; then
        ok "ISO builder present (detonation sandbox can stage samples)"
    else
        warn "ISO builder MISSING — detonation will refuse until one is installed"
    fi
}

###############################################################################
# MODULE DEPENDENCY INSTALLER
# Reads apt_deps / pip_deps from every modules/*/manifest.json and installs
# anything declared.  Supplements the hand-coded installs above so new modules
# can declare their own deps without touching install.sh.
###############################################################################

install_module_deps() {
    step_header "" "Installing module-declared dependencies"

    local modules_dir="$DASHBOARD_DIR/modules"

    if [[ ! -d "$modules_dir" ]]; then
        warn "Modules directory not found — skipping manifest dep scan"
        return
    fi

    # Collect all apt and pip deps from every manifest.json
    local apt_deps pip_deps
    apt_deps=$(python3 - "$modules_dir" <<'PYEOF'
import sys, json, os, glob
modules_dir = sys.argv[1]
apt = []
for mf in sorted(glob.glob(os.path.join(modules_dir, "*", "manifest.json"))):
    try:
        m = json.load(open(mf))
        apt.extend(m.get("apt_deps", []))
    except Exception:
        pass
# Deduplicate, preserve order
seen = set()
out = []
for x in apt:
    if x not in seen:
        seen.add(x)
        out.append(x)
print("\n".join(out))
PYEOF
)

    pip_deps=$(python3 - "$modules_dir" <<'PYEOF'
import sys, json, os, glob
modules_dir = sys.argv[1]
pip = []
for mf in sorted(glob.glob(os.path.join(modules_dir, "*", "manifest.json"))):
    try:
        m = json.load(open(mf))
        pip.extend(m.get("pip_deps", []))
    except Exception:
        pass
seen = set()
out = []
for x in pip:
    if x not in seen:
        seen.add(x)
        out.append(x)
print("\n".join(out))
PYEOF
)

    if [[ -n "$apt_deps" ]]; then
        info "apt packages from manifests: $(echo "$apt_deps" | tr '\n' ' ')"
        # shellcheck disable=SC2086
        apt-get install -y $apt_deps \
            || warn "One or more manifest apt deps failed — check output above"
        ok "Manifest apt deps installed"
    else
        info "No apt deps declared in module manifests"
    fi

    if [[ -n "$pip_deps" ]]; then
        info "pip packages from manifests: $(echo "$pip_deps" | tr '\n' ' ')"
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            pip3 install --break-system-packages "$pkg" \
                || warn "pip install failed for $pkg"
        done <<< "$pip_deps"
        ok "Manifest pip deps installed"
    else
        info "No pip deps declared in module manifests"
    fi
}

###############################################################################
# STEP 6/9 — NEMESIS GROUP & PERMISSIONS
###############################################################################

setup_nemesis_group() {
    step_header "6/9" "Nemesis Group & Permissions"

    groupadd nemesis 2>/dev/null || true

    # De-privileging (2026-07-27): a dedicated system group for shared-DB access
    # and one static system user per service. Distinct users, not a shared one,
    # so a compromise of the network-facing hw-monitor inherits nothing belonging
    # to any other service. These users are deliberately NOT added to the
    # 'nemesis' group — that group grants read of /etc/nemesis.env and its 16
    # secrets, which the services receive via systemd EnvironmentFile (read by
    # the manager as root) and therefore do not need directly.
    #
    # NAMED EXCEPTION — nemesis-dash (added 2026-07-31, effective at Cutover B).
    # The dashboard account IS a member of 'nemesis', and it is the only service
    # account that is. Stated explicitly rather than added silently, because it
    # is a real exception to the principle directly above, not an oversight.
    #
    # Why it cannot follow the rule: the principle holds only for services whose
    # ONLY need for the file is at startup, where systemd reads EnvironmentFile
    # as root and hands the values over. Dashboard additionally reads
    # /etc/nemesis.env at RUNTIME — _read_nemesis_env() backs the Settings config
    # UI, which displays and edits those values long after startup. No
    # EnvironmentFile mechanism can satisfy a read that happens on request.
    #
    # Scope of the exception: read-only membership in 'nemesis' (the file is
    # 0640 root:nemesis). It grants no write path — config WRITES go through the
    # privileged helper, never through this group. Do not widen it to other
    # service accounts; none of them read the file at runtime.
    groupadd --system nemesis-db 2>/dev/null || true
    # Socket group for nemesis-fwd. BOTH authorised peers must be members or
    # they cannot open /run/nemesis/fwd.sock (mode 0660 root:nemesis-fw) at all —
    # the helper never even sees the connection to refuse it.
    groupadd --system nemesis-fw 2>/dev/null || true
    local _svc_user
    # nemesis-scan and nemesis-dash added 2026-07-31 (Cutover A/B). Before this,
    # device-scanner and dashboard ran as the INSTALL USER — an account with a
    # real shell, a home directory, and (on any normal install) sudo. A dashboard
    # compromise therefore landed straight on an administrative identity. These
    # two accounts exist so it lands on nothing.
    for _svc_user in nemesis-diag nemesis-hwmon nemesis-alertw \
                     nemesis-vpndns nemesis-canary nemesis-watchdog \
                     nemesis-scan nemesis-dash; do
        if ! id "$_svc_user" &>/dev/null; then
            useradd --system --no-create-home --shell /usr/sbin/nologin \
                    --gid nemesis-db "$_svc_user" 2>/dev/null || true
        fi
    done
    # nemesis-f2b — fail2ban's peer identity. Created SEPARATELY, not in the loop
    # above, because its primary group is nemesis-fw rather than nemesis-db: it
    # never touches the database. nemesis_fwd writes the quarantine row itself,
    # server-side, as root; this account exists only to OPEN the helper socket, so
    # nemesis-db would be an unnecessary grant.
    #
    # Why it needs its own identity at all: nemesis_fwd authorises by SO_PEERCRED,
    # so a ban is authorised by WHICH ACCOUNT connected. fail2ban itself runs as
    # root and drops to this account (`runuser -u nemesis-f2b`) precisely so the
    # ban arrives as the narrow fail2ban peer — allowed block_ip/deny_ip and
    # nothing else — instead of as root.
    #
    # SCOPE (2026-07-31): this creates the ACCOUNT only. The fail2ban integration
    # that uses it — jail.local, action.d/nemesis-fwd.conf and the nemesis-f2b-ban
    # shim — is NOT yet shipped in this repo, so on a fresh install the account is
    # correct but inert. That is deliberate and pending a separate Rule 10
    # disclosure review, not an oversight.
    if ! id nemesis-f2b &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --gid nemesis-fw nemesis-f2b 2>/dev/null || true
    fi

    # nemesis-dash is the ONLY service account needing more than nemesis-db.
    # Both memberships trace to an audited capability, and nothing else was
    # granted: 'nemesis' for the RUNTIME read of /etc/nemesis.env behind the
    # Settings UI (see the named exception above), 'nemesis-fw' to open the
    # firewall helper's socket. Not folded into the loop above because no other
    # account gets either.
    usermod -a -G nemesis nemesis-dash 2>/dev/null || true
    usermod -a -G nemesis-fw nemesis-dash 2>/dev/null || true
    # Grant socket access to the two peers the firewall helper authorises.
    usermod -a -G nemesis-fw "$SUDO_USER" 2>/dev/null || true
    usermod -a -G nemesis-fw nemesis-alertw 2>/dev/null || true
    ok "Service users created (nemesis-db + nemesis-fw groups, 6 per-service accounts)"

    # ── canary visibility (2026-07-29) ───────────────────────────────────────
    # The ransomware canary plants bait in the install user's home and polls it
    # from malware-canary.service, which runs as nemesis-canary. Two things must
    # be true or the poll reports every bait file as "deleted / encrypted-in-
    # place" forever:
    #
    #   1. malware-canary.service must NOT have ProtectHome=yes — that masks
    #      /home inside its mount namespace. Handled in scripts/gen_units.py,
    #      which sets ProtectHome=read-only for that unit only.
    #   2. nemesis-canary must be able to TRAVERSE the install user's home. Home
    #      directories are commonly 0750, and nemesis-canary is not in the user's
    #      group, so without this it cannot stat anything beneath it.
    #
    # A traverse-only ACL is used rather than `chmod o+x`: it grants exactly one
    # account exactly x (no read, no listing) instead of opening traversal to
    # every local account, including the other service users.
    #
    # This is not cosmetic. Both conditions were missing between 2026-07-25 and
    # 2026-07-29 and the canary produced ~33,500 false CRITICAL findings, opened
    # no tickets, and exhausted the outbound mail rate limit — while never once
    # detecting anything. Losing this on a rebuild silently reproduces all of it.
    if command -v setfacl >/dev/null 2>&1; then
        if setfacl -m "u:nemesis-canary:--x" "/home/$SUDO_USER" 2>/dev/null; then
            ok "Canary traverse ACL set on /home/$SUDO_USER (u:nemesis-canary:--x)"
        else
            warn "Could not set canary traverse ACL on /home/$SUDO_USER — the ransomware
     canary will report all bait as deleted until this is granted manually:
       setfacl -m u:nemesis-canary:--x /home/$SUDO_USER"
        fi
    else
        warn "setfacl not found (install 'acl'). Canary bait under /home/$SUDO_USER will be
     invisible to malware-canary.service until nemesis-canary can traverse it."
    fi
    ok "Group 'nemesis' ready"

    usermod -aG nemesis "$SUDO_USER"
    ok "Added $SUDO_USER to nemesis group"

    write_env_file
    verify_gateway_config_path

    chown root:nemesis /etc/nemesis.env
    chmod 640 /etc/nemesis.env
    ok "Permissions set: root:nemesis 640 on /etc/nemesis.env"

    # Sudoers rule is installed early in main() — immediately after preflight_checks()
    echo ""
    echo "  Note: Group membership takes effect on next login."
    echo "  To apply it now in your current terminal:  newgrp nemesis"
}

###############################################################################
# STEP 7/9 — HARDWARE DISCOVERY
###############################################################################

hardware_discovery() {
    step_header "7/9" "Hardware Discovery"

    local hw_map="$DASHBOARD_DIR/alert_manager/hw_map.json"

    if [[ "$INSTALL_MODE" == "windows_vm" ]]; then
        info "VM mode: skipping lm-sensors — hardware data will come from the Windows agent running on your host PC"
        mkdir -p "$DASHBOARD_DIR/alert_manager"
        echo '{"source": "windows_agent", "nemesis_vm_port": 5001}' > "$hw_map"
        chown "$SUDO_USER" "$hw_map" 2>/dev/null || true
        ok "Hardware map set to Windows agent mode (alert_manager/hw_map.json)"
        return 0
    fi

    local discover_script="$DASHBOARD_DIR/alert_manager/hw_discover.py"

    if [[ ! -f "$discover_script" ]]; then
        warn "hw_discover.py not found at $discover_script — skipping."
        warn "Run it manually later from Settings → Hardware → Re-run hardware discovery."
        return 0
    fi

    info "Running hardware discovery — takes about 30 seconds..."
    if sudo -u "$SUDO_USER" python3 "$discover_script"; then
        ok "Hardware discovery complete"
        if [[ -f "$hw_map" ]]; then
            ok "Sensor map saved to alert_manager/hw_map.json"
        fi
    else
        warn "Hardware discovery returned an error."
        warn "You can re-run it from Settings → Hardware → Re-run hardware discovery."
        info "Note: No sensors found is normal on virtual machines. On physical hardware, sensors are detected automatically."
    fi
}

###############################################################################
# STEP 8/9 — DEPLOY SERVICES
###############################################################################

deploy_services() {
    step_header "8/9" "Deploying Systemd Services"

    # Dated directory holding the units as they were before this run overwrote
    # them. Referenced by migrate_to_opt.sh --rollback.
    local UNIT_BACKUP_DIR="/var/backups/nemesis/units-$(date +%Y%m%d-%H%M%S)"

    # Units live in THREE places now: the six core_module daemons ship from
    # core_module/<module>/<name>.service, vpn-dns-guard from core/, and
    # dashboard + nemesis-fwd from alert_manager/. core_module/*/ is searched
    # FIRST and by glob (not a hardcoded list) for two reasons:
    #  * FIRST — a migrated service may still have a STALE alert_manager/<name>.service
    #    on disk until its Commit B removes it; the core_module unit is the correct
    #    one and must win, so a fresh install never deploys the old path.
    #  * GLOB — install.sh should not have to track WHICH services are migrated.
    #    Any service whose unit is under core_module/<x>/ is found automatically,
    #    so this needs no edit when hw_monitor's or future moves finalize. (The
    #    glob harmlessly also lists core_module/template/ etc., which carry no
    #    <name>.service and so match nothing.)
    local svc_dirs=("$DASHBOARD_DIR"/core_module/*/ "$DASHBOARD_DIR/alert_manager" "$DASHBOARD_DIR/core")
    # nemesis-fwd FIRST, deliberately. It was missing from this list entirely
    # until 2026-07-31: gen_units.py generates NINE units, this deployed EIGHT,
    # so every fresh install shipped without the privileged firewall helper —
    # no block, no unblock, no quarantine, no fail2ban ban path. The installer
    # created the nemesis-fw group and all three peer accounts and then never
    # deployed the helper they exist for. Found by the first end-to-end VM
    # install test; no amount of reading install.sh in isolation had caught it,
    # because nothing here referenced the service by name to be noticed missing.
    #
    # Ordered first because the loop below starts services in list order and
    # every other peer depends on this one being up to reach the firewall.
    local svc_names=("nemesis-fwd" \
                     "dashboard" "watchdog" "hw-monitor" "alert-watcher" \
                     "device-scanner" "malware-canary" "diagnostics-watcher" \
                     "vpn-dns-guard")
    local deployed=0

    for svc in "${svc_names[@]}"; do
        local src=""
        local d
        for d in "${svc_dirs[@]}"; do
            [[ -f "$d/${svc}.service" ]] && { src="$d/${svc}.service"; break; }
        done
        if [[ -z "$src" ]]; then
            warn "Service file not found for $svc in ${svc_dirs[*]} — skipping"
            continue
        fi

        # Back up any existing unit BEFORE overwriting it. Previously this
        # clobbered the installed unit with no copy kept, so a reinstall or a
        # relocation left no way back to the previous service definitions —
        # and migrate_to_opt.sh --rollback pointed operators at a snapshot
        # directory nothing ever created. This makes that path real.
        if [[ -f "/etc/systemd/system/${svc}.service" ]]; then
            install -d -m 0755 "$UNIT_BACKUP_DIR"
            cp -a "/etc/systemd/system/${svc}.service" "$UNIT_BACKUP_DIR/"
        fi

        # Units carry absolute /opt/nemesis paths and their own static User=.
        # As of 2026-07-31 ALL EIGHT services run as dedicated system users —
        # Cutover A/B moved the last two (dashboard, device-scanner) off the
        # install account. The __INSTALL_USER__ substitution below is therefore
        # now a no-op on the shipped templates; it is kept so a locally-modified
        # unit that still uses the placeholder keeps working, not because any
        # shipped unit needs it.
        sed -e "s|__INSTALL_USER__|$SUDO_USER|g" \
            "$src" > "/etc/systemd/system/${svc}.service"
        chmod 0644 "/etc/systemd/system/${svc}.service"

        ok "Deployed /etc/systemd/system/${svc}.service (from ${src#$DASHBOARD_DIR/})"
        deployed=$((deployed + 1))
    done

    if [[ -d "$UNIT_BACKUP_DIR" ]]; then
        ok "Previous unit files backed up to $UNIT_BACKUP_DIR"
    fi

    # Polkit rule granting the de-privileged watchdog its restart authority.
    # Without this it cannot restart the services it supervises, since it no
    # longer runs as root. Scoped to 7 named units and the restart/try-restart
    # verbs only — verified on the test VM that every other unit, every other
    # verb, and every other service user is denied.
    local _polkit_src="$DASHBOARD_DIR/alert_manager/10-nemesis-watchdog.rules"
    if [[ -f "$_polkit_src" ]]; then
        install -d -m 0755 /etc/polkit-1/rules.d
        install -m 0644 -o root -g root "$_polkit_src" /etc/polkit-1/rules.d/
        systemctl reload polkit 2>/dev/null || systemctl restart polkit 2>/dev/null || true
        ok "Deployed polkit rule for watchdog restart authority"
    else
        warn "Polkit rule not found at $_polkit_src — watchdog will be unable to restart services"
    fi

    if [[ $deployed -eq 0 ]]; then
        warn "No service files were found in $svc_src — services not deployed."
        return 0
    fi

    systemctl daemon-reload
    ok "systemd configuration reloaded"

    # Pre-create alerts.db in the data directory, group-owned by nemesis-db so
    # every de-privileged service can reach it. 0770 on the DIRECTORY is required
    # (not 0750): SQLite in WAL mode creates -wal/-shm siblings there, so the
    # group needs directory write or every service opens the DB read-only.
    local _data_dir="/var/lib/nemesis"
    local _db="$_data_dir/alerts.db"
    # 2770, not 0770: the setgid bit. Without it, a file created here by a
    # process whose PRIMARY group is not nemesis-db lands with the wrong group —
    # and SQLite's WAL sidecars are created by whichever process opens the DB
    # first. That locked every de-privileged service out of the database on the
    # dev box (2026-07-31). setgid makes correct group ownership structural
    # rather than dependent on which service happens to start first.
    install -d -m 2770 -o "$SUDO_USER" -g nemesis-db "$_data_dir"
    [[ -f "$_db" ]] || touch "$_db"
    chown "$SUDO_USER" "$_db"
    chgrp nemesis-db "$_db"
    chmod 0660 "$_db"
    ok "alerts.db at $_db (owner $SUDO_USER, group nemesis-db, 0660)"

    # ── Ransomware canary: ON for a real install, OFF everywhere else ─────────
    #
    # The module ships canary_autoplant=0 DELIBERATELY (2026-08-26). Planting
    # writes real bait files into a real user's home, and a stray import — a
    # test, a page render — must never be able to do that. A dashboard
    # page-render test did exactly that: it pointed the DB at a throwaway file
    # while the canary still resolved the operator's REAL home, planted and
    # deleted bait among live user files, and fired a false ransomware alert.
    #
    # But a security product should ship PROTECTED, not unprotected. So a real
    # install opts in explicitly, right here, and only here. Default-off plus
    # installer-on gives both properties; neither alone does.
    #
    # ⚠ RUN AS "$SUDO_USER", NOT ROOT. SQLite creates -wal/-shm siblings owned by
    # the writing process, so a root write here would leave root-owned sidecars
    # and lock every de-privileged service out of the database — precisely the
    # failure the setgid bit above exists to prevent.
    #
    # Uses the module's OWN _init_db()/_set_setting() rather than an inline
    # CREATE+INSERT, so the canonical DDL stays in exactly one place (ADR 0001).
    if sudo -u "$SUDO_USER" NEMESIS_DB_PATH="$_db" python3 - <<'PYEOF' 2>/dev/null
import sys
sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")
import modules
import nemesis_paths
modules.set_shared_db_path(nemesis_paths.db_path())
from modules.malware_detection import module as _md
_md._init_db()
_md._set_setting("canary_autoplant", "1")
assert _md._get_setting("canary_autoplant", "0") == "1", "setting did not persist"
PYEOF
    then
        ok "canary auto-plant enabled for this install (canary_autoplant=1)"
    else
        warn "could not enable canary auto-plant — the canary layer will poll" \
             "zero bait until you set canary_autoplant=1 in the dashboard"
    fi

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

configure_forkb_nat() {
    # ── ADR-0009 Fork B Piece 2 — source-NAT for tunnel-routed inspection ──────
    #
    # Fork B forwards tailnet-sourced flows out to the internet so a central
    # Suricata can inspect them. That needs source-NAT, because the destination
    # cannot route 100.64.0.0/10 back. This installs the masquerade rule ONLY.
    #
    # net.ipv4.ip_forward IS DELIBERATELY LEFT AT 0 HERE. Read this before
    # "fixing" that:
    #
    #   ⚠ CORRECTED 2026-08-30. THE PARAGRAPH THIS REPLACES WAS STALE FROM
    #   2026-07-30 AND ITS STALENESS WAS EXPENSIVE: it declared a production-grade
    #   FORWARD gate "an unresolved design question (ufw is the mandated
    #   chokepoint, but Tailscale pre-empts it)", which made Gateway Mode look far
    #   costlier than it was for roughly a month. The premise had already been
    #   fixed the same day it was written.
    #
    #   WHAT IT USED TO SAY, and why it was true when written: Tailscale owned the
    #   head of the FORWARD chain (`-A FORWARD -j ts-forward` FIRST, ahead of every
    #   ufw chain), and ts-forward's terminating ACCEPT meant a forwarded packet
    #   arriving on tailscale0 was accepted before ufw ever saw it. `ufw route`
    #   rules genuinely could not gate that traffic.
    #
    #   WHAT CHANGED: `configure_tailnet_enforcement()` has set
    #   `tailscale set --netfilter-mode=nodivert` since 2026-07-30, which stops
    #   Tailscale jumping to its own chains at all. ts-forward is still MAINTAINED
    #   but is never jumped from FORWARD, so it pre-empts nothing. **ufw IS the
    #   reachable chokepoint for tailnet-sourced forwarded traffic.**
    #
    #   ⚠ AND THAT REACHABILITY IS NOT FREE — DO NOT READ THIS AS "ufw route rules
    #   just work now". nodivert disabled Tailscale's OWN protective rules along
    #   with its ACCEPTs. Two of them were load-bearing and are replicated by this
    #   installer precisely because they no longer apply:
    #     * the tailnet ANTI-SPOOF DROP (ts-input's sibling), which ADR 0011's
    #       unforgeable-source-IP guarantee depends on — replicated into
    #       before.rules above ufw's conntrack RELATED,ESTABLISHED accept;
    #     * the tailnet LOOP-PREVENTION DROP (ts-forward's own), emitted by
    #       `scripts/nemesis-fw-render`, form taken from Tailscale's source
    #       (util/linuxfw addBase4) rather than inferred from a running box.
    #   ufw being reachable is a consequence of removing Tailscale's rules; the
    #   replicas are what keep that safe. Removing either replica re-opens what
    #   nodivert turned off, and it will not look like a firewall failure.
    #
    #   ip_forward=0 therefore remains the installed default, but it is no longer
    #   "the ONLY thing" standing between this box and open forwarding — a real
    #   ufw FORWARD gate is now buildable. Fork B validation still enables
    #   ip_forward per-run and restores it.
    #
    #   Verified 2026-08-30 from the commit record (`d72cda8`'s measured live test
    #   against an enrolled agent, and `7f28d16`'s replicated DROP), NOT from a
    #   live iptables read — `sudo -n` was unavailable in that session, and an
    #   empty `iptables -S` is the instrument failing rather than evidence. Worth
    #   one live confirmation by whoever next has root.
    #
    # EGRESS INTERFACE IS DERIVED, NOT PINNED. A hardcoded interface silently
    # stops matching whenever egress changes. We ask vpn_dns_guard for the
    # main-table default-route interface whose kernel kind is not a tunnel
    # (kind-matched, never name-matched — vendor WireGuard builds use arbitrary
    # device names).
    #
    #   *** VERIFIED ON PIA ONLY *** — same caveat ADR 0002 states for that
    #   module. Correct for PIA-style SPLIT-TUNNEL VPNs. For redirect-gateway
    #   VPNs (OpenVPN `redirect-gateway`, WireGuard AllowedIPs=0.0.0.0/0) the
    #   derivation finds no non-tunnel egress, exits non-zero, and we install NO
    #   rule rather than guess. That refusal is the required behaviour.
    #
    # KNOWN GAP — FORK B IS PIA-DOWN-ONLY (2026-07-29):
    #
    #   ⚠ STILL UNFALSIFIED AS OF 2026-08-30, AND NOT CONFIRMED EITHER — read this
    #   before "correcting" the straddle claim below. A reconciliation observed no
    #   0.0.0.0/1/128.0.0.0/1 routes in any routing table and it was proposed as
    #   evidence the claim is stale. IT IS NOT. The claim below is explicitly about
    #   the PIA-CONNECTED state; the observation was taken PIA-DISCONNECTED
    #   (verified: zero tunnel interfaces present), which is exactly what the claim
    #   predicts for that state. Absence of the straddle while PIA is down is
    #   CONSISTENT with the claim, not contrary to it.
    #
    #   Falsifying it requires observing the routing table with PIA UP — which
    #   cannot be done here, because PIA is deliberately disabled on this
    #   deployment (PUNCHLIST "[FUTURE] PIA VPN deliberately disabled"). So this
    #   paragraph stands as WRITTEN-BUT-UNRETESTED since 2026-07-29, and that is
    #   the honest status: neither re-confirmed nor disproven. Do not upgrade it to
    #   "verified" and do not delete it as stale without a PIA-up observation.
    #
    #   PIA does not replace the main default route; it straddles it with
    #   0.0.0.0/1 and 128.0.0.0/1 via the tunnel. Those are MORE SPECIFIC than
    #   `default`, so when PIA is connected, forwarded traffic actually leaves via
    #   tun0 while this derivation still (correctly) reports the physical NIC. The
    #   `-o <iface>` rule below therefore does not match, and traffic would exit
    #   the tunnel un-NATed. Fork B is consequently scoped PIA-DOWN-ONLY.
    #
    #   This was accepted deliberately rather than papered over. The alternatives
    #   were: masquerade without `-o` (works in both states, but sends inspected
    #   traffic through the user's VPN — a security posture decision that should
    #   not be made as a side effect of a NAT rule), or add a policy route pinning
    #   Fork B traffic to the non-tunnel egress (deliberately bypasses the VPN,
    #   and is more than Piece 2 was scoped for).
    #
    #   PIA is currently disabled on this deployment anyway, for unrelated and
    #   still-undiagnosed Nemesis errors — see PUNCHLIST.md, "[FUTURE] PIA VPN
    #   deliberately disabled". Fork B's PIA-up support is gated on that item.
    #   Whoever picks it up: fixing the PIA compatibility issue does NOT by itself
    #   make Fork B work with PIA up. This rule needs revisiting too, and Layer 3
    #   measurements taken PIA-down do not transfer (different egress, different
    #   TTL, tun0 MTU 1441 vs 1500).
    #
    # STATIC CONFIG: the derived interface is baked into before.rules at install
    # time. If the physical NIC is replaced or renamed, re-run install.sh or edit
    # /etc/ufw/before.rules by hand.
    local _egress
    if ! _egress=$(python3 "$DASHBOARD_DIR/core/vpn_dns_guard.py" --egress-iface 2>/dev/null) \
       || [[ -z "$_egress" ]]; then
        warn "Fork B NAT skipped: no non-tunnel default egress found."
        warn "  This is expected on redirect-gateway VPNs (OpenVPN redirect-gateway,"
        warn "  WireGuard AllowedIPs=0.0.0.0/0). Refusing to guess an interface."
        return 0
    fi

    if grep -q "NEMESIS-FORKB-NAT" /etc/ufw/before.rules 2>/dev/null; then
        ok "Fork B NAT rule already present in before.rules (egress: $_egress)"
        return 0
    fi

    cp /etc/ufw/before.rules "/etc/ufw/before.rules.pre-nemesis-forkb.$(date +%Y%m%d-%H%M%S)"
    # ufw's before.rules starts with a *filter table; a *nat table must precede it.
    cat > /tmp/.nemesis-forkb-nat <<EOF
# NEMESIS-FORKB-NAT (ADR-0009 Fork B Piece 2, added by install.sh)
# Source-NAT tailnet-originated forwarded traffic. Inert while
# net.ipv4.ip_forward=0, which is the installed default — see configure_forkb_nat()
# in install.sh for why, and for the PIA-up limitation.
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 100.64.0.0/10 -o $_egress -j MASQUERADE
COMMIT

EOF
    cat /etc/ufw/before.rules >> /tmp/.nemesis-forkb-nat
    mv /tmp/.nemesis-forkb-nat /etc/ufw/before.rules
    chmod 0640 /etc/ufw/before.rules
    ok "Fork B NAT rule installed (masquerade 100.64.0.0/10 out $_egress)"
    info "  net.ipv4.ip_forward left at 0 — Fork B validation enables it per-run"
}


configure_tailnet_enforcement() {
    # ── Make ufw the real enforcement point for tunnel traffic ────────────────
    #
    # VERIFIED DEFECT (2026-07-30, live test against an enrolled agent):
    # Tailscale's default netfilter mode inserts `-A INPUT -j ts-input` AHEAD of
    # every ufw chain, and ts-input ends with `-i tailscale0 -j ACCEPT`. ACCEPT
    # is terminating, so EVERY ufw rule — including per-IP denies written by
    # nemesis_fwd on a Suricata alert — is unreachable for tunnel traffic.
    # Measured: a block was accepted, reported "Rule inserted", and the blocked
    # peer still completed a TCP connection to this box.
    #
    # `--netfilter-mode=nodivert` keeps Tailscale MAINTAINING its chains but
    # stops it jumping to them, so ufw is reached. We deliberately do NOT re-add
    # a jump to ts-input: that chain carries the blanket ACCEPT, so jumping to it
    # would reinstate the defect.
    #
    # Not jumping to ts-input means WE must provide the one rule in it that is
    # load-bearing for security: the tailnet anti-spoof DROP. ADR 0011's
    # enrollment trust rests on "the server-observed tailnet source IP cannot be
    # forged" — that guarantee IS this rule. It must sit ABOVE ufw's conntrack
    # RELATED,ESTABLISHED accept, or a spoofed packet matching an existing flow
    # is accepted before it is checked.
    #
    # NOT a substitute for the deterministic enforcement table (ADR 0019): under
    # nodivert WE place the jumps, which is still insertion-order, not priority.
    # This closes a live hole; ADR 0019 remains the durable answer.

    if ! command -v tailscale >/dev/null 2>&1; then
        info "Tailscale not installed — skipping tailnet enforcement setup"
        return 0
    fi

    if grep -q "NEMESIS-TAILNET-ANTISPOOF" /etc/ufw/before.rules 2>/dev/null; then
        ok "Tailnet anti-spoof guard already present in before.rules"
    else
        cp /etc/ufw/before.rules "/etc/ufw/before.rules.pre-nemesis-tailnet.$(date +%Y%m%d-%H%M%S)"
        # Insert immediately after the loopback ACCEPT: after it so the box's own
        # tailnet-sourced loopback traffic is unaffected, before the conntrack
        # accept so spoofed packets cannot ride an existing flow.
        python3 - <<'EOF'
import re
p = "/etc/ufw/before.rules"
s = open(p).read()
anchor = "-A ufw-before-input -i lo -j ACCEPT"
rule = (anchor + "\n\n"
        "# NEMESIS-TAILNET-ANTISPOOF — replaces the DROP that ts-input provided\n"
        "# before --netfilter-mode=nodivert. ADR 0011 enrollment trust depends on\n"
        "# this. MUST stay above the conntrack RELATED,ESTABLISHED accept below.\n"
        "-A ufw-before-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP")
if anchor in s:
    open(p, "w").write(s.replace(anchor, rule, 1))
EOF
        chmod 0640 /etc/ufw/before.rules
        ok "Tailnet anti-spoof guard added to before.rules (IPv4)"
    fi

    if grep -q "NEMESIS-TAILNET-ANTISPOOF" /etc/ufw/before6.rules 2>/dev/null; then
        ok "Tailnet anti-spoof guard already present in before6.rules"
    else
        cp /etc/ufw/before6.rules "/etc/ufw/before6.rules.pre-nemesis-tailnet.$(date +%Y%m%d-%H%M%S)"
        python3 - <<'EOF'
p = "/etc/ufw/before6.rules"
s = open(p).read()
anchor = "-A ufw6-before-input -i lo -j ACCEPT"
rule = (anchor + "\n\n"
        "# NEMESIS-TAILNET-ANTISPOOF (IPv6) — omitting this would leave the v6\n"
        "# path spoofable while v4 is protected.\n"
        "-A ufw6-before-input -s fd7a:115c:a1e0::/48 ! -i tailscale0 -j DROP")
if anchor in s:
    open(p, "w").write(s.replace(anchor, rule, 1))
EOF
        chmod 0640 /etc/ufw/before6.rules
        ok "Tailnet anti-spoof guard added to before6.rules (IPv6)"
    fi

    # Guards must be LIVE before removing what they replace. Reload, verify, and
    # only then change the netfilter mode — never the other way round.
    ufw reload >/dev/null 2>&1 || true

    if ! iptables -S ufw-before-input 2>/dev/null | grep -q "100.64.0.0/10"; then
        warn "Tailnet anti-spoof guard is NOT live after reload — NOT changing netfilter mode"
        warn "  ufw would be reachable but the spoofing guarantee would be gone. Fix first."
        return 0
    fi

    tailscale set --netfilter-mode=nodivert 2>/dev/null ||         warn "Could not set netfilter-mode=nodivert (is tailscaled running?)"

    if iptables -S INPUT 2>/dev/null | grep -q "j ts-input"; then
        warn "ts-input is still jumped from INPUT — tunnel traffic still bypasses ufw"
    else
        ok "Tunnel traffic now governed by ufw (netfilter-mode=nodivert)"
    fi
    info "  ts-forward is also unjumped: replicate its loop-prevention DROP and the"
    info "  nat-table SNAT before enabling ip_forward for subnet routing or Fork B"
}


local_connected_subnets() {
    # Every directly-connected IPv4 network on this host, loopback excluded, as
    # CIDR strings on stdout. Used to scope agent-channel rules to networks this
    # machine is actually attached to instead of `from any`.
    #
    # Prints nothing on failure. Callers MUST treat empty as an explicit failure
    # state and refuse to fall back to a permissive rule — an empty enumeration
    # and "this host has no networks" are the same output here, and neither is a
    # licence to open the port to the world.
    # Two exclusions, both verified against live output on the dev box:
    #   - tailscale0 — the tunnel is not a VM adapter. Its remote path is the
    #     CGNAT range written by configure_tailnet_allow_rules(), not a rule
    #     derived from whatever address this node happens to hold.
    #   - /32 prefixes — a host route describes one address, not a network a
    #     peer can be reached from, so it can never be the host PC's path in.
    ip -o -f inet addr show scope global 2>/dev/null \
        | awk '$2 != "tailscale0" {print $4}' \
        | while read -r cidr; do
            [[ -z "$cidr" ]] && continue
            [[ "$cidr" == */32 ]] && continue
            python3 -c \
                "import ipaddress,sys; print(str(ipaddress.ip_interface(sys.argv[1]).network))" \
                "$cidr" 2>/dev/null || true
          done \
        | sort -u
}


vm_agent_ufw_rules() {
    # ── GAP 1 (2026-08-16): replaces `ufw allow from any to any port 5001` ─────
    #
    # The rule this replaces was a genuine world-open allow on the agent
    # enrollment/heartbeat port, mitigated only by a printed warning asking the
    # user to narrow it by hand afterwards. Two things make that worse than it
    # reads:
    #
    #   1. INSTALL_MODE=windows_vm is set by `systemd-detect-virt` matching
    #      oracle|vmware|kvm|virtualbox (see the OS-check step), so it is not the
    #      niche "Windows host + agent" path — it is EVERY virtual-machine
    #      install.
    #   2. The final tiering model requires that the server refuse any remote
    #      connection not arriving over the VPN. A `from any` rule contradicts
    #      that outright.
    #
    # What the host PC actually needs is reachability from whichever adapter it
    # talks to the guest on. Bridged installs are already covered by the
    # $DETECTED_SUBNET rule above; host-only and NAT adapters are not, which is
    # the real gap the blanket rule was papering over. So: allow 5001 from every
    # network this box is directly attached to. Strictly narrower than `from
    # any` in every topology, and self-configuring.
    local override cidr count=0
    override=$(read_conf "AGENT_HOST_CIDR" "")

    if [[ -n "$override" ]]; then
        if ! python3 -c \
            "import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)" \
            "$override" 2>/dev/null; then
            die "AGENT_HOST_CIDR in $CONF_FILE is not a valid network: $override"
        fi
        ufw allow from "$override" to any port 5001 comment "Nemesis Agent (configured host)" 2>/dev/null || true
        ok "UFW: port 5001 allowed from $override (AGENT_HOST_CIDR)"
        return 0
    fi

    while read -r cidr; do
        [[ -z "$cidr" ]] && continue
        ufw allow from "$cidr" to any port 5001 comment "Nemesis Agent (VM adapter)" 2>/dev/null || true
        ok "UFW: port 5001 allowed from $cidr"
        count=$((count + 1))
    done < <(local_connected_subnets)

    if (( count == 0 )); then
        # Fail closed and loud. Opening the port to the world because we could
        # not enumerate is exactly the "a failed read became a permissive
        # default" shape this codebase treats as a defect class.
        warn "Could not enumerate this machine's networks — NO port 5001 rule added."
        warn "  The Windows agent will not be able to reach this VM until you add one:"
        warn "    sudo ufw allow from <host-pc-subnet> to any port 5001"
        warn "  Or set AGENT_HOST_CIDR=<host-pc-subnet> in $CONF_FILE and re-run."
    fi
}


configure_tailnet_allow_rules() {
    # ── GAP 2 (2026-08-16): the installer created no tailnet rules at all ──────
    #
    # Before this, ufw_and_finish() wrote rules ONLY for $DETECTED_SUBNET. With
    # default-deny incoming, that means a fresh install had NO remote path
    # whatsoever — the 100.64.0.0/10 rules on the development box had been added
    # by hand and were never what a new user got.
    #
    # This is the inverse of the expected problem: out of the box remote access
    # was too CLOSED, not too open. Under the current model the VPN is *the*
    # remote path, so these rules are a first-class install step, not something
    # to be discovered.
    #
    # configure_tailnet_enforcement() below already does the hard part
    # (netfilter-mode=nodivert, so ufw governs tunnel traffic rather than being
    # bypassed by Tailscale's own chains, plus the anti-spoof DROP that ADR
    # 0011's enrollment trust rests on). The enforcement plumbing existed; only
    # the allow rules were missing.
    #
    # Gated on Tailscale actually being present, deliberately: 100.64.0.0/10 is
    # the shared CGNAT range, not Tailscale's exclusively, and an ISP can hand a
    # WAN interface an address inside it. Writing the rule on a box with no
    # tunnel would widen the allowed source set for no gain. Re-running the
    # installer after installing Tailscale adds them (ufw allow is idempotent).
    if ! command -v tailscale >/dev/null 2>&1; then
        info "Tailscale not installed — no tailnet allow rules written"
        info "  Remote access requires the VPN. After installing Tailscale, either"
        info "  re-run this installer or add the rules by hand:"
        info "    sudo ufw allow from 100.64.0.0/10 to any port 80"
        info "    sudo ufw allow from 100.64.0.0/10 to any port 5001"
        return 0
    fi

    ufw allow from 100.64.0.0/10 to any port 80   comment "Nemesis Dashboard (tailnet)"  2>/dev/null || true
    ufw allow from 100.64.0.0/10 to any port 5001 comment "Nemesis Enrollment (tailnet)" 2>/dev/null || true
    ok "UFW: tailnet (100.64.0.0/10) allowed on ports 80 and 5001"
}


ufw_and_finish() {
    step_header "9/9" "Firewall Rules & Final Checks"

    info "Configuring UFW firewall..."
    ufw allow from "$DETECTED_SUBNET" to any port 80   comment "Nemesis Dashboard"  2>/dev/null || true
    ufw allow from "$DETECTED_SUBNET" to any port 53   comment "Pi-hole DNS"        2>/dev/null || true
    ufw allow from "$DETECTED_SUBNET" to any port 8080 comment "Pi-hole Admin"      2>/dev/null || true
    ufw allow from "$DETECTED_SUBNET" to any port 22   comment "SSH"                2>/dev/null || true
    ufw allow from "$DETECTED_SUBNET" to any port 5001 comment "Nemesis Enrollment" 2>/dev/null || true
    if [[ "$INSTALL_MODE" == "windows_vm" ]]; then
        vm_agent_ufw_rules
    fi
    configure_forkb_nat
    ufw --force enable
    configure_tailnet_allow_rules
    configure_tailnet_enforcement
    ok "UFW enabled — LAN rules plus the tailnet remote path"

    # nginx reverse proxy: Flask runs on 5000; nginx on 80 reverse-proxies to it
    # with HTTP basic auth so the dashboard is not open to the local network unauthenticated.
    info "Installing nginx reverse proxy with HTTP basic auth..."
    apt-get install -y nginx apache2-utils

    # Generate a random dashboard password if one was not set during config
    if [[ -z "$CFG_DASHBOARD_PASSWORD" ]]; then
        CFG_DASHBOARD_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=')
        warn "No dashboard password was set — generated a random one (shown at completion)"
    fi

    # Create htpasswd file (bcrypt, nginx user readable only)
    htpasswd -bcB /etc/nginx/.nemesis_htpasswd nemesis "$CFG_DASHBOARD_PASSWORD" 2>/dev/null
    chmod 640 /etc/nginx/.nemesis_htpasswd
    chown root:www-data /etc/nginx/.nemesis_htpasswd
    ok "Created /etc/nginx/.nemesis_htpasswd (user: nemesis)"

    # Write nginx site config
    cat > /etc/nginx/sites-available/nemesis <<'NGINXEOF'
server {
    listen 80;
    server_name _;

    # Increase body size limit for dashboard file uploads (backups, etc.)
    client_max_body_size 100M;

    # Auth-exempt (token-credentialed installer download + the reachability probe).
    # Matched before `location /`, so these skip HTTP Basic auth.
    location ~ ^/(install/windows/|api/health) {
        auth_basic off;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        auth_basic "Nemesis Firewall";
        auth_basic_user_file /etc/nginx/.nemesis_htpasswd;

        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_connect_timeout 10s;
        proxy_send_timeout 300s;
    }
}
NGINXEOF

    # Enable the Nemesis site; disable nginx's default placeholder
    ln -sf /etc/nginx/sites-available/nemesis /etc/nginx/sites-enabled/nemesis
    rm -f /etc/nginx/sites-enabled/default

    systemctl enable nginx 2>/dev/null
    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || systemctl start nginx
        ok "nginx reverse proxy configured and enabled (port 80 → Flask :5000)"
    else
        warn "nginx config test failed — check: sudo nginx -t"
        warn "Dashboard may not be accessible on port 80 until nginx config is fixed."
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
    for svc in dashboard watchdog hw-monitor alert-watcher device-scanner malware-canary diagnostics-watcher; do
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
    echo -e "  ${BOLD}Login:${NC}            Username: nemesis"
    echo -e "  ${BOLD}Password:${NC}         $CFG_DASHBOARD_PASSWORD"
    echo ""
    echo "  Save this password — it is stored in /etc/nginx/.nemesis_htpasswd"
    echo "  To change it later:  sudo htpasswd /etc/nginx/.nemesis_htpasswd nemesis"
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
    if [[ "$INSTALL_MODE" == "windows_vm" ]]; then
        echo "  4. Install the Windows agent on your host PC:"
        echo "     → See windows_agent/README.md for instructions"
        echo "     → Your dashboard will show hardware data once the Windows agent is running and connected"
        echo ""
    fi
    if [[ -n "$CFG_ANTHROPIC_API_KEY" ]]; then
        echo "  AI Engine: Look for the AI ● indicator in the dashboard header — green means AI is active and ready."
        echo ""
    fi

    echo -e "  ${BOLD}Your configuration has been saved to /etc/nemesis.env${NC}"
    echo "  To change any setting later, edit that file with:"
    echo "    sudo nano /etc/nemesis.env"
    echo "  Then restart services with:"
    echo "    sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner malware-canary diagnostics-watcher"
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
# BACKUP RESTORE (Parts 4 of 4 — check before install, restore after deploy)
###############################################################################

check_for_backup() {
    local backup_dir="/home/$SUDO_USER/nemesis-backup"
    [[ -d "$backup_dir" ]] || return 0

    local latest
    latest=$(ls -t "$backup_dir"/nemesis-backup-*.tar.gz 2>/dev/null | head -1)
    [[ -n "$latest" ]] || return 0

    echo ""
    echo -e "  ${GREEN}${BOLD}A Nemesis backup was found:${NC}"
    echo "    $(basename "$latest")  (in $backup_dir)"
    echo ""
    echo "  Your alerts history, tickets, and configuration can be restored"
    echo "  automatically after installation completes."
    echo ""
    echo -ne "  ${BOLD}Restore data from this backup after install? [y/N]:${NC} "
    local resp
    read -r resp
    if [[ "${resp,,}" == "y" || "${resp,,}" == "yes" ]]; then
        RESTORE_BACKUP_FILE="$latest"
        ok "Restore scheduled — will run after services are deployed."
    else
        info "Skipping restore — starting with a clean configuration."
    fi
}

restore_from_backup() {
    [[ -n "$RESTORE_BACKUP_FILE" ]] || return 0

    step_header "Restore" "Restoring Data from Backup"

    info "Archive: $RESTORE_BACKUP_FILE"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    if ! tar -xzf "$RESTORE_BACKUP_FILE" -C "$tmp_dir" 2>/dev/null; then
        warn "Failed to extract backup archive — skipping restore."
        rm -rf "$tmp_dir"
        return 0
    fi

    # alerts.db
    if [[ -f "$tmp_dir/alerts.db" ]]; then
        # 2770 — setgid, same reason as the fresh-install path above. Both sites
        # must carry it or the repair path silently re-creates the old hazard.
        install -d -m 2770 -o "$SUDO_USER" -g nemesis-db /var/lib/nemesis
        cp "$tmp_dir/alerts.db" /var/lib/nemesis/alerts.db
        chown "$SUDO_USER" /var/lib/nemesis/alerts.db 2>/dev/null || true
        chgrp nemesis-db /var/lib/nemesis/alerts.db 2>/dev/null || true
        chmod 0660 /var/lib/nemesis/alerts.db 2>/dev/null || true
        ok "Restored: /var/lib/nemesis/alerts.db"
    fi

    # ADR 0001 Stage 6: the old per-module tickets.db has been retired — tickets data
    # now lives in the shared alerts.db (restored above). No separate restore step.

    # hw_map.json
    if [[ -f "$tmp_dir/alert_manager/hw_map.json" ]]; then
        cp "$tmp_dir/alert_manager/hw_map.json" "$DASHBOARD_DIR/alert_manager/hw_map.json"
        chown "$SUDO_USER" "$DASHBOARD_DIR/alert_manager/hw_map.json" 2>/dev/null || true
        ok "Restored: alert_manager/hw_map.json"
    fi

    # anomaly detection DBs
    if [[ -d "$tmp_dir/modules/anomaly_detection" ]]; then
        mkdir -p "$DASHBOARD_DIR/modules/anomaly_detection"
        for db in "$tmp_dir/modules/anomaly_detection/"*.db; do
            [[ -f "$db" ]] || continue
            cp "$db" "$DASHBOARD_DIR/modules/anomaly_detection/$(basename "$db")"
            chown "$SUDO_USER" "$DASHBOARD_DIR/modules/anomaly_detection/$(basename "$db")" 2>/dev/null || true
            ok "Restored: modules/anomaly_detection/$(basename "$db")"
        done
    fi

    # /etc/nemesis.env — restores API keys and all configuration
    if [[ -f "$tmp_dir/etc_nemesis.env" ]]; then
        cp "$tmp_dir/etc_nemesis.env" /etc/nemesis.env
        chown root:nemesis /etc/nemesis.env
        chmod 640 /etc/nemesis.env
        ok "Restored: /etc/nemesis.env (API keys and configuration)"
        warn "Review /etc/nemesis.env if your IP address or email settings changed since the backup."
        warn "Edit with:  sudo nano /etc/nemesis.env"
    fi

    rm -rf "$tmp_dir"

    info "Restarting services to load restored data..."
    systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner malware-canary diagnostics-watcher 2>/dev/null || true
    ok "Services restarted"
    echo ""
    ok "Data restored from: $(basename "$RESTORE_BACKUP_FILE")"
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
    # --mode=1 or --mode=2 on the command line bypasses the interactive prompt
    # (useful for CI, automated deploys, and SSH-driven installs).
    local mode_choice=""
    for _a in "$@"; do
        [[ "$_a" == --mode=* ]] && mode_choice="${_a#--mode=}"
    done

    if [[ -z "$mode_choice" ]]; then
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
        echo -ne "  ${BOLD}Enter 1 or 2 [default: 1]:${NC} "
        read -r mode_choice
        mode_choice="${mode_choice:-1}"
    else
        info "Mode set via --mode flag: $mode_choice"
    fi

    # Preflight always runs first — it populates DETECTED_* vars
    preflight_checks

    # Set up passwordless sudo early so subsequent steps don't prompt
    #
    # ⛔ DO NOT ADD /usr/bin/nmap BACK (removed 2026-08-28). It was granted here
    # because device_scanner once ran `sudo nmap`. It no longer does, and cannot:
    # its unit sets NoNewPrivileges=yes, which makes the kernel ignore setuid, so
    # the sudo could never elevate anyway — every scan silently returned nothing
    # until that was found and fixed on 2026-07-29 (see scan_network()'s docstring
    # in core_module/device_scanner/device_scanner.py for the full measurement).
    # Scanning is now fully unprivileged: `nmap -sn` plus a read of /proc/net/arp,
    # which needs no grant at all. A 2026-07-31 audit flagged the leftover grant as
    # blast radius with zero function — `sudo nmap` yields a root shell via
    # GTFOBins' --script — but this template was missed, so every install kept
    # shipping it. If a scan is failing, the cause is a missing nmap PACKAGE, never
    # a missing sudo grant.
    echo "Setting up passwordless service management..."
    local sudoers_file="/etc/sudoers.d/nemesis"
    cat > "$sudoers_file" <<EOF
# Nemesis Firewall — passwordless access for service management and runtime ops
# Generated by install.sh — safe to delete if Nemesis is uninstalled
$SUDO_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl, /usr/bin/tail, /usr/sbin/ufw
EOF
    chmod 440 "$sudoers_file"
    if visudo -c -f "$sudoers_file" &>/dev/null; then
        ok "Sudoers rule installed: $SUDO_USER can manage services without a password"
    else
        rm -f "$sudoers_file"
        warn "Sudoers syntax check failed — rule not installed. Service management will prompt for password."
    fi

    check_for_backup

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
    install_module_deps
    setup_nemesis_group   # writes /etc/nemesis.env and sets permissions
    hardware_discovery
    deploy_services
    restore_from_backup
    ufw_and_finish
}

main "$@"
