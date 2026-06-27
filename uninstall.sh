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

ok()      { echo -e "${GREEN}  ✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}  ⚠${NC}  $*"; }
info()    { echo -e "${BLUE}  →${NC}  $*"; }
fail()    { echo -e "${RED}  ✗  ERROR:${NC}  $*" >&2; }
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

# --yes flag: skip interactive confirmation (used by the dashboard /api/uninstall endpoint)
NON_INTERACTIVE=false
for _arg in "$@"; do
    [[ "$_arg" == "--yes" ]] && NON_INTERACTIVE=true
done

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
echo "    All Nemesis systemd services"
echo "    /etc/nemesis.env     (runtime configuration)"
echo "    /etc/sudoers.d/nemesis, nemesis-restart"
echo "    nginx site config (/etc/nginx/sites-*/nemesis) + htpasswd"
echo "    UFW rules added by Nemesis"
echo "    nemesis system group"
echo "    Legacy: nemesis-port-redirect.service + iptables rules (if present)"
echo ""
echo "  You will be asked individually about Pi-hole, Suricata, and ClamAV."
echo ""
echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$NON_INTERACTIVE" == true ]]; then
    echo "  Running in non-interactive mode (--yes) — skipping confirmation prompt."
    CONFIRM="YES"
else
    echo -ne "  Type ${BOLD}YES${NC} to confirm and proceed, or anything else to cancel: "
    read -r CONFIRM
fi

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
# STEP 1/8 — STOP & DISABLE SERVICES
###############################################################################

step_header "1/8" "Stopping and Disabling Services"

SERVICES=(dashboard watchdog hw-monitor alert-watcher device-scanner malware-canary)

for svc in "${SERVICES[@]}"; do
    if systemctl list-units --full --all 2>/dev/null | grep -q "${svc}.service"; then
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null || true
            ok "Stopped $svc"
        else
            info "$svc was not running"
        fi
        systemctl disable "$svc" 2>/dev/null || true
        ok "Disabled $svc"
    else
        skipped "$svc (not installed)"
    fi
done

###############################################################################
# STEP 2/8 — REMOVE SERVICE FILES
###############################################################################

step_header "2/8" "Removing Service Files"

_any_removed=false
for svc in "${SERVICES[@]}"; do
    f="/etc/systemd/system/${svc}.service"
    if [[ -f "$f" ]]; then
        rm -f "$f"
        ok "Removed $f"
        _any_removed=true
    else
        skipped "$f"
    fi
done

if [[ "$_any_removed" == true ]]; then
    systemctl daemon-reload
    ok "systemd configuration reloaded"
    REMOVED+=("systemd services")
else
    SKIPPED+=("systemd services (none found)")
fi

# ── Layer B canary bait files + baselines ────────────────────────────────────
# install plants decoy "bait" files in the user's home dirs and records a tamper
# baseline in alerts.db (malware_canary_files). Remove BOTH together: deleting
# the files while leaving the baseline rows would make a future reinstall's
# canary poll trip on every (now-missing) bait. Paths are read from the DB so
# custom canary_dirs are handled too. (alerts.db itself is preserved otherwise.)
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
CANARY_DB="$REAL_HOME/dashboard/alert_manager/alerts.db"
if [[ -f "$CANARY_DB" ]]; then
    _canary_out="$(python3 - "$CANARY_DB" <<'PYEOF'
import sqlite3, os, sys
db = sys.argv[1]
try:
    c = sqlite3.connect(db)
    rows = c.execute("SELECT path FROM malware_canary_files").fetchall()
except sqlite3.OperationalError:
    print("0 0"); sys.exit(0)
files = 0
for (p,) in rows:
    try:
        if p and os.path.isfile(p):
            os.remove(p); files += 1
    except Exception:
        pass
if rows:
    c.execute("DELETE FROM malware_canary_files"); c.commit()
print(f"{files} {len(rows)}")
PYEOF
)"
    read -r _cf _cr <<< "$_canary_out"
    if [[ "${_cr:-0}" -gt 0 || "${_cf:-0}" -gt 0 ]]; then
        ok "Removed ${_cf:-0} canary bait file(s) and ${_cr:-0} baseline row(s)"
        REMOVED+=("canary bait files + baselines")
    else
        skipped "canary bait files (none planted)"
    fi
else
    skipped "canary cleanup (no alerts.db found)"
fi

###############################################################################
# STEP 3/8 — REMOVE CONFIG & PERMISSIONS
###############################################################################

step_header "3/8" "Removing Config and Permissions"

# /etc/nemesis.env
if [[ -f /etc/nemesis.env ]]; then
    rm -f /etc/nemesis.env
    ok "Removed /etc/nemesis.env"
    REMOVED+=("/etc/nemesis.env")
else
    skipped "/etc/nemesis.env"
    SKIPPED+=("/etc/nemesis.env")
fi

# /etc/sudoers.d/nemesis and nemesis-restart
for _sf in nemesis nemesis-restart; do
    if [[ -f "/etc/sudoers.d/$_sf" ]]; then
        rm -f "/etc/sudoers.d/$_sf"
        ok "Removed /etc/sudoers.d/$_sf"
        REMOVED+=("/etc/sudoers.d/$_sf")
    else
        skipped "/etc/sudoers.d/$_sf"
        SKIPPED+=("/etc/sudoers.d/$_sf")
    fi
done

# nemesis group
if getent group nemesis &>/dev/null; then
    if id -nG "$REAL_USER" 2>/dev/null | grep -qw nemesis; then
        gpasswd -d "$REAL_USER" nemesis &>/dev/null || true
        ok "Removed $REAL_USER from nemesis group"
    fi
    groupdel nemesis 2>/dev/null || true
    ok "Removed nemesis group"
    REMOVED+=("nemesis group")
else
    skipped "nemesis group (not found)"
    SKIPPED+=("nemesis group")
fi

###############################################################################
# STEP 4/8 — REMOVE PORT-80 FRONTEND (nginx + legacy iptables)
###############################################################################

step_header "4/8" "Removing Port-80 Frontend"

# ── nginx (current architecture) ────────────────────────────────────────────
_nginx_removed=false

if [[ -L /etc/nginx/sites-enabled/nemesis || -f /etc/nginx/sites-enabled/nemesis ]]; then
    rm -f /etc/nginx/sites-enabled/nemesis
    ok "Removed /etc/nginx/sites-enabled/nemesis"
    _nginx_removed=true
else
    skipped "/etc/nginx/sites-enabled/nemesis"
fi

if [[ -f /etc/nginx/sites-available/nemesis ]]; then
    rm -f /etc/nginx/sites-available/nemesis
    ok "Removed /etc/nginx/sites-available/nemesis"
    _nginx_removed=true
else
    skipped "/etc/nginx/sites-available/nemesis"
fi

if [[ -f /etc/nginx/.nemesis_htpasswd ]]; then
    rm -f /etc/nginx/.nemesis_htpasswd
    ok "Removed /etc/nginx/.nemesis_htpasswd"
    _nginx_removed=true
else
    skipped "/etc/nginx/.nemesis_htpasswd"
fi

if [[ "$_nginx_removed" == true ]]; then
    if command -v nginx &>/dev/null && systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
        ok "nginx reloaded (Nemesis site removed)"
    fi
    REMOVED+=("nginx reverse proxy config")
else
    SKIPPED+=("nginx config (not found)")
fi

# ── Legacy: nemesis-port-redirect.service + iptables NAT ────────────────────
# Kept as a cleanup fallback for machines installed before the nginx migration.
_legacy_ipt=false

if [[ -f /etc/systemd/system/nemesis-port-redirect.service ]]; then
    systemctl stop    nemesis-port-redirect 2>/dev/null || true
    systemctl disable nemesis-port-redirect 2>/dev/null || true
    rm -f /etc/systemd/system/nemesis-port-redirect.service
    systemctl daemon-reload 2>/dev/null || true
    ok "Removed nemesis-port-redirect.service (legacy)"
    _legacy_ipt=true
else
    skipped "nemesis-port-redirect.service (not found)"
fi

if command -v iptables &>/dev/null; then
    if iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000 2>/dev/null; then
        iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000 2>/dev/null || true
        ok "Removed iptables PREROUTING rule (legacy)"
        _legacy_ipt=true
    else
        skipped "iptables PREROUTING rule (not present)"
    fi

    if iptables -t nat -C OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 5000 2>/dev/null; then
        iptables -t nat -D OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 5000 2>/dev/null || true
        ok "Removed iptables OUTPUT rule (legacy)"
        _legacy_ipt=true
    else
        skipped "iptables OUTPUT rule (not present)"
    fi
fi

if [[ "$_legacy_ipt" == true ]]; then
    REMOVED+=("legacy iptables port-80 redirect")
fi

###############################################################################
# STEP 5/8 — REMOVE UFW RULES
###############################################################################

step_header "5/8" "Removing UFW Rules"

if command -v ufw &>/dev/null; then
    _ufw_count=0

    # Delete rules carrying a "Nemesis" comment (added by install.sh).
    # Loop one-at-a-time: after each delete the remaining rule numbers shift,
    # so we always re-query rather than collecting numbers up-front.
    while true; do
        _line=$(ufw status numbered 2>/dev/null | grep -i "Nemesis" | head -1)
        [[ -z "$_line" ]] && break
        _num=$(echo "$_line" | grep -oP '^\[\s*\K\d+')
        [[ -z "$_num" ]] && break
        echo "y" | ufw delete "$_num" 2>/dev/null || break
        _ufw_count=$((_ufw_count + 1))
    done

    # Best-effort removal of Windows agent port — may not carry a Nemesis comment
    # if the user edited the rule manually. Both tcp-only and any-protocol forms.
    ufw delete allow 5001/tcp 2>/dev/null || true
    ufw delete allow 5001     2>/dev/null || true

    if [[ $_ufw_count -gt 0 ]]; then
        ok "Removed $_ufw_count Nemesis UFW rule(s)"
        REMOVED+=("UFW rules")
    else
        skipped "No Nemesis-tagged UFW rules found"
        SKIPPED+=("UFW rules")
    fi
else
    skipped "UFW not installed"
    SKIPPED+=("UFW rules")
fi

###############################################################################
# STEP 6/8 — OPTIONAL: PI-HOLE
###############################################################################

step_header "6/8" "Optional Component — Pi-hole"

if command -v pihole &>/dev/null || systemctl is-active --quiet pihole-FTL 2>/dev/null; then
    if [[ "$NON_INTERACTIVE" == true ]] || ask_yes_no "Remove Pi-hole?"; then
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
# STEP 7/8 — OPTIONAL: SURICATA
###############################################################################

step_header "7/8" "Optional Component — Suricata"

if dpkg -l suricata 2>/dev/null | grep -q '^ii'; then
    echo "  Note: /etc/suricata (your rules and config) will NOT be deleted."
    echo ""
    if [[ "$NON_INTERACTIVE" == true ]] || ask_yes_no "Remove Suricata packages?"; then
        systemctl stop    suricata 2>/dev/null || true
        systemctl disable suricata 2>/dev/null || true
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
# STEP 8/8 — OPTIONAL: CLAMAV
###############################################################################

step_header "8/8" "Optional Component — ClamAV"

if dpkg -l clamav 2>/dev/null | grep -q '^ii'; then
    if [[ "$NON_INTERACTIVE" == true ]] || ask_yes_no "Remove ClamAV?"; then
        systemctl stop    clamav-daemon 2>/dev/null || true
        systemctl disable clamav-daemon 2>/dev/null || true
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
