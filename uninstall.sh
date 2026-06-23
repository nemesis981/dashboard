#!/usr/bin/env bash
# Nemesis Firewall — Uninstall Script
# Removes everything installed by install.sh.
# Usage: sudo bash uninstall.sh

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
skipped() { echo -e "     ${BOLD}(skipped — not found)${NC}  $*"; }

step_header() {
    local step="$1" desc="$2"
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  [$step]  $desc${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ask_yes_no <question>  — returns 0 for yes, 1 for no
ask_yes_no() {
    local _resp
    echo -ne "  ${BOLD}$1${NC} [y/N]: "
    read -r _resp
    [[ "${_resp,,}" == "y" || "${_resp,,}" == "yes" ]]
}

###############################################################################
# PREFLIGHT
###############################################################################

if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root.  Use:  sudo bash uninstall.sh"
    exit 1
fi

if [[ -z "${SUDO_USER:-}" ]]; then
    fail "Could not determine the real user. Run with: sudo bash uninstall.sh  (not 'sudo su' then bash)"
    exit 1
fi

REAL_USER="$SUDO_USER"

###############################################################################
# WARNING BANNER & CONFIRMATION
###############################################################################

clear
echo ""
echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}${BOLD}  Nemesis Firewall — Uninstall${NC}"
echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  This will remove Nemesis Firewall from this system."
echo ""
echo -e "  ${GREEN}${BOLD}Will NOT be deleted:${NC}"
echo "    ~/dashboard          (your data, logs, and configuration)"
echo "    /etc/suricata        (your Suricata rules and config)"
echo ""
echo -e "  ${RED}${BOLD}Will be removed:${NC}"
echo "    All 5 Nemesis systemd services"
echo "    /etc/nemesis.env     (runtime configuration)"
echo "    /etc/sudoers.d/nemesis"
echo "    iptables port-80 redirect rule"
echo "    nemesis system group"
echo ""
echo "  You will be asked individually about Pi-hole, Suricata, and ClamAV."
echo ""
echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -ne "  Type ${BOLD}YES${NC} to confirm and proceed, or anything else to cancel: "
read -r CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
    echo ""
    info "Cancelled — nothing was changed."
    exit 0
fi
echo ""

###############################################################################
# TRACKING
###############################################################################

REMOVED=()
KEPT=()
SKIPPED=()

###############################################################################
# STEP 1 — STOP & DISABLE SERVICES
###############################################################################

step_header "1/7" "Stopping and Disabling Services"

SERVICES=(dashboard watchdog hw-monitor alert-watcher device-scanner)

for svc in "${SERVICES[@]}"; do
    if systemctl list-units --full -all 2>/dev/null | grep -q "${svc}.service"; then
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null
            ok "Stopped $svc"
        else
            info "$svc was not running"
        fi
        systemctl disable "$svc" 2>/dev/null
        ok "Disabled $svc"
    else
        skipped "$svc (not installed)"
    fi
done

###############################################################################
# STEP 2 — REMOVE SERVICE FILES
###############################################################################

step_header "2/7" "Removing Service Files"

any_removed=false
for svc in "${SERVICES[@]}"; do
    f="/etc/systemd/system/${svc}.service"
    if [[ -f "$f" ]]; then
        rm -f "$f"
        ok "Removed $f"
        any_removed=true
    else
        skipped "$f"
    fi
done

if [[ "$any_removed" == true ]]; then
    systemctl daemon-reload
    ok "systemd configuration reloaded"
    REMOVED+=("systemd services")
else
    SKIPPED+=("systemd services (none found)")
fi

###############################################################################
# STEP 3 — REMOVE CONFIG & PERMISSIONS
###############################################################################

step_header "3/7" "Removing Config and Permissions"

# /etc/nemesis.env
if [[ -f /etc/nemesis.env ]]; then
    rm -f /etc/nemesis.env
    ok "Removed /etc/nemesis.env"
    REMOVED+=("/etc/nemesis.env")
else
    skipped "/etc/nemesis.env"
    SKIPPED+=("/etc/nemesis.env")
fi

# /etc/sudoers.d/nemesis
if [[ -f /etc/sudoers.d/nemesis ]]; then
    rm -f /etc/sudoers.d/nemesis
    ok "Removed /etc/sudoers.d/nemesis"
    REMOVED+=("/etc/sudoers.d/nemesis")
else
    skipped "/etc/sudoers.d/nemesis"
    SKIPPED+=("/etc/sudoers.d/nemesis")
fi

# nemesis group
if getent group nemesis &>/dev/null; then
    # Remove user from group first
    if id -nG "$REAL_USER" 2>/dev/null | grep -qw nemesis; then
        gpasswd -d "$REAL_USER" nemesis &>/dev/null
        ok "Removed $REAL_USER from nemesis group"
    fi
    groupdel nemesis 2>/dev/null
    ok "Removed nemesis group"
    REMOVED+=("nemesis group")
else
    skipped "nemesis group (not found)"
    SKIPPED+=("nemesis group")
fi

###############################################################################
# STEP 4 — REMOVE IPTABLES PORT REDIRECT
###############################################################################

step_header "4/7" "Removing iptables Port Redirect (80 → 5000)"

_removed_ipt=false

# PREROUTING rule
if iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000 2>/dev/null; then
    iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000
    ok "Removed PREROUTING rule (port 80 → 5000)"
    _removed_ipt=true
else
    skipped "PREROUTING rule (not present)"
fi

# OUTPUT rule (localhost redirect)
if iptables -t nat -C OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 5000 2>/dev/null; then
    iptables -t nat -D OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 5000
    ok "Removed OUTPUT rule (localhost port 80 → 5000)"
    _removed_ipt=true
else
    skipped "OUTPUT rule (not present)"
fi

# Persist the removal so it survives reboot
if [[ "$_removed_ipt" == true ]]; then
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null
        ok "Saved updated iptables rules (iptables-persistent)"
    fi
    REMOVED+=("iptables port-80 redirect")
else
    SKIPPED+=("iptables port-80 redirect")
fi

###############################################################################
# STEP 5 — OPTIONAL: PI-HOLE
###############################################################################

step_header "5/7" "Optional Component — Pi-hole"

if command -v pihole &>/dev/null || systemctl is-active --quiet pihole-FTL 2>/dev/null; then
    if ask_yes_no "Remove Pi-hole?"; then
        info "Running Pi-hole uninstaller..."
        if pihole uninstall --unattended 2>/dev/null; then
            ok "Pi-hole removed"
            REMOVED+=("Pi-hole")
        else
            warn "Pi-hole uninstaller returned an error — it may be partially removed."
            warn "To remove manually:  pihole uninstall"
        fi
    else
        ok "Keeping Pi-hole"
        KEPT+=("Pi-hole")
    fi
else
    skipped "Pi-hole (not installed)"
    SKIPPED+=("Pi-hole")
fi

###############################################################################
# STEP 6 — OPTIONAL: SURICATA
###############################################################################

step_header "6/7" "Optional Component — Suricata"

if dpkg -l suricata &>/dev/null 2>&1 | grep -q '^ii'; then
    echo "  Note: /etc/suricata (your rules and config) will NOT be deleted."
    echo ""
    if ask_yes_no "Remove Suricata packages?"; then
        systemctl stop suricata 2>/dev/null
        systemctl disable suricata 2>/dev/null
        apt-get purge -y suricata 2>/dev/null
        ok "Suricata removed"
        REMOVED+=("Suricata")
        KEPT+=("/etc/suricata config (preserved)")
    else
        ok "Keeping Suricata"
        KEPT+=("Suricata")
    fi
else
    skipped "Suricata (not installed)"
    SKIPPED+=("Suricata")
fi

###############################################################################
# STEP 7 — OPTIONAL: CLAMAV
###############################################################################

step_header "7/7" "Optional Component — ClamAV"

if dpkg -l clamav &>/dev/null 2>&1 | grep -q '^ii'; then
    if ask_yes_no "Remove ClamAV?"; then
        systemctl stop clamav-daemon 2>/dev/null
        systemctl disable clamav-daemon 2>/dev/null
        apt-get purge -y clamav clamav-daemon 2>/dev/null
        ok "ClamAV removed"
        REMOVED+=("ClamAV")
    else
        ok "Keeping ClamAV"
        KEPT+=("ClamAV")
    fi
else
    skipped "ClamAV (not installed)"
    SKIPPED+=("ClamAV")
fi

###############################################################################
# SUMMARY
###############################################################################

echo ""
echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}${BOLD}  Nemesis Firewall — Uninstall Complete${NC}"
echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

if [[ ${#REMOVED[@]} -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}Removed:${NC}"
    for item in "${REMOVED[@]}"; do
        echo "    •  $item"
    done
    echo ""
fi

if [[ ${#KEPT[@]} -gt 0 ]]; then
    echo -e "  ${GREEN}${BOLD}Kept:${NC}"
    for item in "${KEPT[@]}"; do
        echo "    •  $item"
    done
    echo ""
fi

if [[ ${#SKIPPED[@]} -gt 0 ]]; then
    echo -e "  ${BOLD}Not found (skipped):${NC}"
    for item in "${SKIPPED[@]}"; do
        echo "    •  $item"
    done
    echo ""
fi

echo -e "  ${BOLD}Your ~/dashboard directory and data were not touched.${NC}"
echo ""
echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""
