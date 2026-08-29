#!/usr/bin/env bash
# =============================================================================
# vpn_dns_livetest.sh  —  VPN/DNS killswitch live test for Nemesis
#
# Runs the WHOLE live window unattended and logs everything to disk, because
# while the VPN+killswitch bug is present THIS MACHINE LOSES DNS and Claude Code
# loses its uplink. Do not rely on any network during the test.
#
# Flow (each step logged):
#   (a) snapshot baseline + back up Pi-hole upstreams
#   (b) bring VPN up, wait for tunnel-ready
#   (c) DIAGNOSE: prove the bug, and capture what actually binds FTL's upstream
#       to the physical NIC (ip route get, ss/lsof on FTL, FTL log, nft, ip rule)
#   (d) APPLY the fix via core/vpn_dns_guard.py --apply
#   (e) VERIFY: probe several uncached domains
#   (f) AUTO-ROLLBACK if verify failed
#   (g) tear the VPN back down, exercise the disconnect path, end DNS-working
#
# Idempotent and safe to re-run. Whatever happens, the EXIT trap restores the
# original Pi-hole upstreams, drops the VPN to its prior state, and confirms DNS.
#
# RUN AS ROOT:   sudo <repo>/scripts/vpn_dns_livetest.sh
# =============================================================================

# Resolve the repo from THIS script's own location rather than hardcoding it —
# same pattern as deploy-suricata-rules.sh and deploy-quic-block.sh.
#
# ⚠ THIS WAS NOT MERELY A COSMETIC LEAK. Both paths below pointed at
# /home/<user>/dashboard/..., the PRE-/opt layout retired on 2026-07-27, so
# GUARD referenced a file that no longer exists and this script was BROKEN AS
# SHIPPED for any user, including the one whose path was baked in. The 2026-06
# hardcoded-home-path cleanup sweep (commit 1630c36) missed this file and
# install_pihole_pwd.sh (the latter deleted 2026-08-29 as dead one-shot
# migration code). Fixed forward 2026-08-29; the string remains in published
# history by explicit operator decision — a bare username did not warrant a
# second history rewrite. Do NOT reintroduce an absolute path here.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG=/tmp/vpn_dns_livetest.log
BAK=/tmp/vpn_dns_livetest.upstreams.bak.json
GUARD="$REPO/core/vpn_dns_guard.py"
ENVFILE=/etc/nemesis.env

# --- never abort the script; we must always reach the cleanup trap -----------
set -u +e

: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

ts()      { date '+%Y-%m-%d %H:%M:%S'; }
log()     { echo "[$(ts)] $*"; }
section() { echo; echo "======================================================================"; echo "[$(ts)] $*"; echo "======================================================================"; }

# -----------------------------------------------------------------------------
# Preconditions
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "This test needs root (FTL logs, ss/lsof, nft, /etc/nemesis.env)."
    echo "Re-run:  sudo $0"
    exit 1
fi

# Load Pi-hole creds from the same env file the services use.
# Read KEY=VALUE *literally* — never `source` this file. The password can contain
# shell metacharacters ( ) ! etc., which systemd's EnvironmentFile reads verbatim
# but bash `source` would try to evaluate (and leak/blow up on).
read_env() {  # $1=key  -> literal value of last matching line, quotes stripped
    local line val
    line="$(grep -E "^$1=" "$ENVFILE" 2>/dev/null | tail -1)" || return 1
    [[ -z "$line" ]] && return 1
    val="${line#*=}"
    val="${val%\"}"; val="${val#\"}"      # strip surrounding "double" quotes
    val="${val%\'}"; val="${val#\'}"      # or 'single' quotes
    printf '%s' "$val"
}
if [[ -r "$ENVFILE" ]]; then
    PIHOLE_IP="$(read_env PIHOLE_IP)"
    PIHOLE_PASSWORD="$(read_env PIHOLE_PASSWORD)"
fi
PIHOLE_IP="${PIHOLE_IP:-127.0.0.1:8080}"
PIHOLE_PASSWORD="${PIHOLE_PASSWORD:-}"
# Export so the guard (child python) inherits creds, exactly as systemd would.
export PIHOLE_IP PIHOLE_PASSWORD

have() { command -v "$1" >/dev/null 2>&1; }

DIGOK=0; have dig && DIGOK=1
if [[ $DIGOK -eq 0 ]]; then log "WARN: 'dig' not found; DNS probes will use getent (less precise)"; fi

# -----------------------------------------------------------------------------
# Pi-hole v6 API helpers (curl + python3 for JSON)
# -----------------------------------------------------------------------------
ph_sid() {
    # Build the JSON body with python (json.dumps escapes any metachar in the
    # password); the password reaches python via the environment, never the
    # command line or a shell-quoted string.
    local body
    body="$(python3 -c 'import os,json;print(json.dumps({"password":os.environ.get("PIHOLE_PASSWORD","")}))')"
    curl -s -m5 "http://$PIHOLE_IP/api/auth" \
        -H 'content-type: application/json' \
        --data "$body" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("session",{}).get("sid",""))' 2>/dev/null
}

ph_get_upstreams() {  # -> JSON array on stdout
    local sid; sid="$(ph_sid)"
    [[ -z "$sid" ]] && { echo "null"; return 1; }
    curl -s -m5 "http://$PIHOLE_IP/api/config/dns/upstreams" -H "sid: $sid" \
    | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["config"]["dns"]["upstreams"]))' 2>/dev/null
}

ph_get_dns_full() {  # -> compact JSON of upstreams/interface/listeningMode
    local sid; sid="$(ph_sid)"
    [[ -z "$sid" ]] && { echo "{}"; return 1; }
    curl -s -m5 "http://$PIHOLE_IP/api/config/dns" -H "sid: $sid" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin)["config"]["dns"];print(json.dumps({"upstreams":d.get("upstreams"),"interface":d.get("interface"),"listeningMode":d.get("listeningMode")}))' 2>/dev/null
}

ph_set_upstreams() { # $1 = JSON array
    local sid; sid="$(ph_sid)"
    [[ -z "$sid" ]] && { log "ERROR: cannot auth to Pi-hole to set upstreams"; return 1; }
    local payload; payload="$(python3 -c 'import sys,json;print(json.dumps({"config":{"dns":{"upstreams":json.loads(sys.argv[1])}}}))' "$1")"
    curl -s -m6 -X PATCH "http://$PIHOLE_IP/api/config" -H "sid: $sid" \
        -H 'content-type: application/json' -d "$payload" >/dev/null
}

# -----------------------------------------------------------------------------
# DNS probe: random label under a real zone -> forces an UPSTREAM lookup.
# PASS on NOERROR/NXDOMAIN (upstream answered), FAIL on SERVFAIL/REFUSED/timeout.
# -----------------------------------------------------------------------------
dns_probe() {
    local zone="${1:-cloudflare.com}"
    local name="probe-$(date +%s)-${RANDOM}.${zone}"
    if [[ $DIGOK -eq 1 ]]; then
        local out; out="$(dig +tries=1 +time=3 @127.0.0.1 "$name" A 2>&1)"
        local status; status="$(echo "$out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
        [[ -z "$status" ]] && status="TIMEOUT"
        echo "$status"
        [[ "$status" == "NOERROR" || "$status" == "NXDOMAIN" ]] && return 0 || return 1
    else
        if getent hosts "$name" >/dev/null 2>&1; then echo "RESOLVED"; return 0; else echo "FAIL"; return 1; fi
    fi
}

probe_n() {  # probe several zones, log each, return 0 if ANY passes
    local ok=1
    for z in cloudflare.com google.com wikipedia.org example.org; do
        local s; s="$(dns_probe "$z")"
        log "    probe $z -> $s"
        [[ "$s" == "NOERROR" || "$s" == "NXDOMAIN" || "$s" == "RESOLVED" ]] && ok=0
    done
    return $ok
}

# -----------------------------------------------------------------------------
# State for cleanup
# -----------------------------------------------------------------------------
PRIOR_VPN_STATE="unknown"
LANIP=""
LANDEV=""
VERIFY_PASSED=0
CLEANED=0

cleanup() {
    [[ $CLEANED -eq 1 ]] && return; CLEANED=1
    section "(g) CLEANUP — restore VPN state, restore upstreams, confirm DNS"

    # 1) Drop the VPN back to its prior state so the box egresses normally again.
    if [[ "$PRIOR_VPN_STATE" != "Connected" ]]; then
        log "Disconnecting VPN (prior state: $PRIOR_VPN_STATE)"
        piactl disconnect >/dev/null 2>&1
        for i in $(seq 1 20); do
            [[ "$(piactl get connectionstate 2>/dev/null)" == "Disconnected" ]] && break
            sleep 1
        done
        log "VPN connectionstate now: $(piactl get connectionstate 2>/dev/null)"
    else
        log "Leaving VPN connected (it was connected before the test)"
    fi

    # 2) Exercise the REAL disconnect path through the guard, then hard-restore
    #    from our own backup as belt-and-suspenders.
    log "Running guard --restore (disconnect transition path)"
    python3 "$GUARD" --restore 2>&1 | sed 's/^/    /'
    if [[ -s "$BAK" ]]; then
        log "Hard-restoring original upstreams from backup: $(cat "$BAK")"
        ph_set_upstreams "$(cat "$BAK")"
    fi

    # 3) Confirm DNS actually works before we let go.
    sleep 2
    log "Post-cleanup Pi-hole upstreams: $(ph_get_upstreams)"
    log "Final DNS check:"
    if probe_n; then log "DNS is WORKING. Box left in known-good state."; else
        log "WARNING: DNS still failing after cleanup — MANUAL CHECK NEEDED."
        log "Manual fix: set Pi-hole upstreams back to: $(cat "$BAK" 2>/dev/null)"
    fi
    section "DONE. Full log at: $LOG"
}
trap cleanup EXIT INT TERM

# =============================================================================
section "(a) BASELINE SNAPSHOT"
# =============================================================================
log "Pi-hole target: $PIHOLE_IP"
PRIOR_VPN_STATE="$(piactl get connectionstate 2>/dev/null || echo unknown)"
log "Prior VPN state: $PRIOR_VPN_STATE"

ORIG_UPSTREAMS="$(ph_get_upstreams)"
log "Original Pi-hole upstreams: $ORIG_UPSTREAMS"
if [[ -z "$ORIG_UPSTREAMS" || "$ORIG_UPSTREAMS" == "null" ]]; then
    log "FATAL: could not read Pi-hole upstreams (auth/API problem). Aborting before any change."
    exit 1
fi
echo "$ORIG_UPSTREAMS" > "$BAK"
log "Backed up upstreams to $BAK"
log "Full dns config (must be UNCHANGED at end except upstreams): $(ph_get_dns_full)"

log "Default route / egress (VPN off):"
ip route show default | sed 's/^/    /'
LANDEV="$(ip -j route show default 2>/dev/null | python3 -c 'import sys,json;r=json.load(sys.stdin);print(r[0]["dev"] if r else "")' 2>/dev/null)"
LANIP="$(ip -4 -o addr show "$LANDEV" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
log "Physical egress iface=$LANDEV  ip=$LANIP"
log "resolvectl status (baseline):"
resolvectl status 2>/dev/null | sed 's/^/    /'
log "Baseline DNS check (should PASS, VPN off):"
probe_n

# =============================================================================
section "(b) BRING VPN UP + capture full VPN-up forensics (unconditional)"
# =============================================================================
log "piactl connect ..."
piactl connect >/dev/null 2>&1
# Readiness = Connected AND the tunnel has an IP (vpnip != Unknown). This does
# NOT gate on our own tunnel detection, so a detection miss still yields data.
for i in $(seq 1 45); do
    st="$(piactl get connectionstate 2>/dev/null)"
    vip="$(piactl get vpnip 2>/dev/null)"
    [[ "$st" == "Connected" && -n "$vip" && "$vip" != "Unknown" ]] && break
    sleep 1
done
sleep 3   # let routes/rules settle after the tunnel gets its IP
log "VPN connectionstate: $(piactl get connectionstate 2>/dev/null)"
log "VPN tunnel ip (vpnip): $(piactl get vpnip 2>/dev/null)"

log "--- ALL interfaces with kernel link kind (find the tunnel by TYPE) ---"
ip -d link show 2>&1 | sed 's/^/      /'
log "--- guard detection (v2: scans main + policy routing tables) ---"
DET="$(python3 "$GUARD" --detect 2>/dev/null)"; echo "$DET" | sed 's/^/      /'
TUN_IFACE="$(echo "$DET" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("iface") or "")' 2>/dev/null)"
TUN_UP="$(echo "$DET" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("up"))' 2>/dev/null)"
log "Detected tunnel iface: ${TUN_IFACE:-<none>}  (up=$TUN_UP)"

log "--- MAIN routing table ---";        ip route show 2>&1 | sed 's/^/      /'
log "--- ALL routing tables (policy tables incl. piavpnrt etc.) ---"
ip route show table all 2>&1 | grep -vE '^\s*(broadcast|local|unreachable) ' | sed 's/^/      /' | head -60
log "--- ip rule (policy routing) ---"; ip rule list 2>&1 | sed 's/^/      /'
log "--- where is the VPN's DNS? resolvectl + resolv.conf ---"
resolvectl status 2>&1 | sed 's/^/      /'
log "  /etc/resolv.conf nameservers:"; grep -E '^\s*nameserver' /etc/resolv.conf 2>/dev/null | sed 's/^/      /'
log "  resolvectl dns (per-link):"; resolvectl dns 2>&1 | sed 's/^/      /'

# =============================================================================
section "(c) DIAGNOSE — prove the bug + capture the bind mechanism"
# =============================================================================
log "Pre-fix DNS probe with VPN UP (expected to FAIL if bug present):"
if probe_n; then
    log ">>> DNS still works with VPN up — bug NOT reproduced this run."
    BUG_REPRO=0
else
    log ">>> DNS FAILS with VPN up — bug reproduced."
    BUG_REPRO=1
fi

log "--- ip route get to public upstream (which iface/src does the kernel pick?) ---"
log "  unspecified source:"
ip route get 1.1.1.1 2>&1 | sed 's/^/      /'
if [[ -n "$LANIP" ]]; then
    log "  FROM physical NIC ip ($LANIP)  <-- if this forces the PHYSICAL iface, PIA source-policy-routing is the cause:"
    ip route get 1.1.1.1 from "$LANIP" 2>&1 | sed 's/^/      /'
fi

log "--- ip rule (policy routing) ---"
ip rule list 2>&1 | sed 's/^/      /'

FTLPID="$(pidof pihole-FTL 2>/dev/null | awk '{print $1}')"
log "--- FTL process / sockets (pid=$FTLPID) — what source addr/iface are upstream sockets bound to? ---"
if [[ -n "$FTLPID" ]]; then
    if have ss;   then ss -tunap 2>/dev/null | grep -E "pid=$FTLPID|:53" | sed 's/^/      /' | head -40; fi
    if have lsof; then
        log "  lsof UDP/TCP for FTL (local bind addresses reveal interface pinning):"
        lsof -p "$FTLPID" -nP -a -i 2>/dev/null | sed 's/^/      /' | head -40
    fi
    log "  Does FTL have any socket SO_BINDTODEVICE? (best-effort via /proc):"
    # Bound-to-device shows in /proc/<pid>/net only indirectly; capture cmdline + any --bind
    tr '\0' ' ' < "/proc/$FTLPID/cmdline" 2>/dev/null | sed 's/^/      cmdline: /'; echo
fi

log "--- Pi-hole FTL log (killswitch EPERM evidence) ---"
for f in /var/log/pihole/FTL.log /var/log/pihole/FTL.log.1; do
    [[ -r "$f" ]] && grep -iE 'not permitted|failed to send|REFUSED|FORWARD' "$f" 2>/dev/null | tail -8 | sed "s|^|      [$f] |"
done

log "--- Pi-hole upstream-binding config (refutes/confirms 'dns.interface pins upstream') ---"
for f in /etc/pihole/pihole.toml; do
    [[ -r "$f" ]] && grep -nE 'bind|interface|listeningMode|upstreams|except' "$f" 2>/dev/null | sed "s|^|      [$f] |" | head -20
done
[[ -d /etc/dnsmasq.d ]] && { log "  /etc/dnsmasq.d custom lines:"; grep -rnE 'bind-interfaces|bind-dynamic|interface=|except-interface' /etc/dnsmasq.d 2>/dev/null | sed 's/^/      /'; }

log "--- Killswitch firewall rule that produces EPERM (read-only; we never modify it) ---"
if have nft; then nft list ruleset 2>/dev/null | grep -iE 'oif|drop|reject|pia|tun|killswitch|53' | sed 's/^/      /' | head -30; fi

# =============================================================================
section "(d) APPLY FIX  (core/vpn_dns_guard.py --apply)"
# =============================================================================
log "Discovered tunnel-reachable DNS + applying via guard ..."
python3 "$GUARD" --apply 2>&1 | sed 's/^/    /'
log "Pi-hole upstreams after apply: $(ph_get_upstreams)"
log "dns config after apply (interface/listeningMode MUST be unchanged): $(ph_get_dns_full)"

# =============================================================================
section "(e) VERIFY"
# =============================================================================
log "Post-fix DNS probes with VPN UP:"
if probe_n; then
    VERIFY_PASSED=1
    log ">>> VERIFY PASSED — DNS resolves through the tunnel with killswitch on."
else
    VERIFY_PASSED=0
    log ">>> VERIFY FAILED — fix did not recover DNS."
fi

log "Confirm resolver is NOT newly exposed on the tunnel ($TUN_IFACE):"
TUNIP="$(ip -4 -o addr show "$TUN_IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
log "  tunnel ip=$TUNIP ; listeningMode still: $(ph_get_dns_full)"

# =============================================================================
section "(f) ROLLBACK IF NEEDED"
# =============================================================================
if [[ $VERIFY_PASSED -eq 0 ]]; then
    log "Verification failed -> restoring original upstreams now."
    ph_set_upstreams "$(cat "$BAK")"
    log "Upstreams restored to: $(ph_get_upstreams)"
else
    log "Verification passed -> keeping fix applied for the rest of the VPN-up window."
fi

log "Live window complete. EXIT trap will now tear down VPN and restore baseline."
# cleanup() runs via trap on exit.
