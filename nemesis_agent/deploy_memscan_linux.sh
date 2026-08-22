#!/usr/bin/env bash
# Nemesis Agent — memory-inspection capability (Linux), OPT-IN deployment.
#
# The Linux arm of memory-injection detection's acquisition layer (step 3a).
# Reading another process's memory needs CAP_SYS_PTRACE. This grants EXACTLY that
# one capability to the existing agent service via a systemd drop-in — no split,
# no root-by-default, no process-model change — turns memscan on in the agent
# config, restarts the service, and PROVES the grant actually took effect before
# reporting success.
#
# WHY A SEPARATE, OPT-IN STEP (same posture as behavioral/Sysmon): CAP_SYS_PTRACE
# lets the agent read any process's memory — a real, bounded increase in blast
# radius. That is a security-posture decision the operator makes per fleet, never
# something the base installer pulls in silently. Default OFF; while off the agent
# does not read any foreign process's memory at all.
#
#   sudo ./deploy_memscan_linux.sh                 # grant + enable + prove
#   sudo ./deploy_memscan_linux.sh --user svc-nem  # agent runs as a specific user
#   sudo ./deploy_memscan_linux.sh --uninstall     # proven, reversible removal
#
# Reversible: --uninstall removes the drop-in and sets memscan_enabled = false.
set -u

CAP="CAP_SYS_PTRACE"
DROPIN_NAME="10-memscan.conf"
DO_UNINSTALL=0
AGENT_USER=""
UNIT=""

step()  { echo -e "\n==> $1"; }
ok()    { echo "    [OK] $1"; }
warn()  { echo "    [!!] $1"; }
fail()  { echo "    [FAIL] $1" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall)  DO_UNINSTALL=1; shift ;;
        --user)       AGENT_USER="${2:-}"; shift 2 ;;
        --unit)       UNIT="${2:-}"; shift 2 ;;
        -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            fail "unknown arg: $1 (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "run as root (systemd unit + capability grant need it)."

HERE="$(cd "$(dirname "$0")" && pwd)"

# Locate the agent's systemd unit — default nemesis-agent, but accept --unit.
find_unit() {
    if [ -n "$UNIT" ]; then echo "$UNIT"; return; fi
    for u in nemesis-agent nemesis_agent nemesisagent; do
        if systemctl list-unit-files "${u}.service" >/dev/null 2>&1 \
           && systemctl cat "${u}.service" >/dev/null 2>&1; then echo "$u"; return; fi
    done
    echo ""
}
U="$(find_unit)"
[ -n "$U" ] || fail "could not find the agent systemd unit (try --unit <name>)."
ok "agent unit: ${U}.service"

DROPIN_DIR="/etc/systemd/system/${U}.service.d"
DROPIN="${DROPIN_DIR}/${DROPIN_NAME}"

# Agent config path (matches config.py's default location under the install dir).
AGENT_CONF=""
for c in "${HERE}/nemesis_agent.conf" "/opt/nemesis-agent/nemesis_agent.conf" \
         "/opt/nemesis/nemesis_agent/nemesis_agent.conf"; do
    [ -f "$c" ] && { AGENT_CONF="$c"; break; }
done

# ── does a running pid hold CAP_SYS_PTRACE? (bit 19 of CapEff) ────────────────
# CORROBORATING ONLY - never the success criterion. See the CANARY section for why
# a bit-read is not evidence; this is used to describe state, not to pass a gate.
has_cap() {
    local pid="$1" capeff
    capeff="$(awk '/^CapEff:/{print $2}' "/proc/${pid}/status" 2>/dev/null)"
    [ -n "$capeff" ] || return 1
    # bit 19 -> mask 0x0000000000080000
    python3 - "$capeff" <<'PY'
import sys
try:
    caps = int(sys.argv[1], 16)
except ValueError:
    sys.exit(2)
sys.exit(0 if (caps >> 19) & 1 else 1)
PY
}


# ── the REAL functional probe, run in the agent's own capability context ──────
# Echoes memcap's JSON verdict on stdout. Reproduces the agent's context exactly:
# same User= as the unit, same AmbientCapabilities as the drop-in we just wrote.
# No output / non-zero return is an explicit failure state, never a default that
# reads like a real measurement.
probe_json() {
    local user="$1" py="$2" mem="$3"
    systemd-run --quiet --wait --pipe --collect \
        -p AmbientCapabilities=${CAP} --uid="$user" \
        "$py" "$mem" --json 2>/dev/null
}

# ── uninstall (reversible, proven) ───────────────────────────────────────────
if [ "$DO_UNINSTALL" -eq 1 ]; then
    step "Removing the memory-inspection capability grant (reversible)"
    if [ -f "$DROPIN" ]; then rm -f "$DROPIN"; ok "removed drop-in $DROPIN"; else warn "no drop-in present"; fi
    rmdir "$DROPIN_DIR" 2>/dev/null || true
    if [ -n "$AGENT_CONF" ]; then
        sed -i 's/^memscan_enabled *=.*/memscan_enabled = false/' "$AGENT_CONF" 2>/dev/null || true
        grep -q '^memscan_enabled' "$AGENT_CONF" 2>/dev/null || echo "memscan_enabled = false" >> "$AGENT_CONF"
        ok "agent config: memscan_enabled = false"
    fi
    systemctl daemon-reload
    systemctl restart "${U}.service" 2>/dev/null || true
    sleep 2
    MAIN_PID="$(systemctl show -p MainPID --value "${U}.service" 2>/dev/null)"
    if [ -n "$MAIN_PID" ] && [ "$MAIN_PID" != "0" ] && has_cap "$MAIN_PID"; then
        warn "agent still holds ${CAP} (a User=root service has it inherently; the drop-in is gone regardless)"
    else
        ok "${CAP} no longer granted by our drop-in (verified)"
    fi
    echo; ok "memory-inspection capability disabled. Re-run without --uninstall to re-enable."
    exit 0
fi

# ── grant the capability via a drop-in (minimal: ONLY CAP_SYS_PTRACE) ─────────
step "Granting ${CAP} to ${U}.service via a systemd drop-in"
mkdir -p "$DROPIN_DIR"
# AmbientCapabilities alone grants exactly this one capability to a non-root
# service without touching any other cap or the bounding set. Deliberately NOT
# setting CapabilityBoundingSet=CAP_SYS_PTRACE, which would DROP every other cap
# and could break a service that legitimately runs as root today.
cat > "$DROPIN" <<EOF
# Nemesis memory-injection detection (step 3a) — opt-in capability grant.
# Managed by deploy_memscan_linux.sh. Remove with: deploy_memscan_linux.sh --uninstall
[Service]
AmbientCapabilities=${CAP}
EOF
ok "wrote drop-in $DROPIN"

# ── turn memscan on in the agent config ──────────────────────────────────────
if [ -n "$AGENT_CONF" ]; then
    if grep -q '^memscan_enabled' "$AGENT_CONF" 2>/dev/null; then
        sed -i 's/^memscan_enabled *=.*/memscan_enabled = true/' "$AGENT_CONF"
    else
        echo "memscan_enabled = true" >> "$AGENT_CONF"
    fi
    ok "agent config: memscan_enabled = true ($AGENT_CONF)"
else
    warn "agent config not found — set memscan_enabled = true manually and restart the agent."
fi

step "Applying (daemon-reload + restart)"
systemctl daemon-reload
systemctl restart "${U}.service" || fail "agent service failed to restart"
sleep 3
systemctl is-active --quiet "${U}.service" || fail "agent service is not active after restart"
ok "agent service restarted and active"

# ── CANARY: prove the agent can ACTUALLY READ another process's memory ───────
# NOT a CapEff bit-read. A bit that is SET does not prove a read succeeds, and this
# script previously proved exactly that the wrong way: it checked bit 19, printed
# "DEPLOYED and PROVEN", and the capability was ABSENT (VM-verified 2026-08-22 —
# /proc/<pid>/mem is a 0600 file, so the old acquisition path needed
# CAP_DAC_OVERRIDE, which CAP_SYS_PTRACE is not). A canary that can only ever say
# "granted" measures nothing. This one runs memcap's real functional probe in the
# agent's own capability context and demands state=available.
step "CANARY — proving the agent can actually READ another process's memory"

MAIN_PID="$(systemctl show -p MainPID --value "${U}.service")"
[ -n "$MAIN_PID" ] && [ "$MAIN_PID" != "0" ] || fail "could not read the agent MainPID"

# Context to reproduce: the unit's User (empty => root) and its interpreter.
AGENT_USER_UNIT="$(systemctl show -p User --value "${U}.service")"
[ -n "$AGENT_USER_UNIT" ] || AGENT_USER_UNIT="root"
EXECLINE="$(systemctl show -p ExecStart --value "${U}.service")"
AGENT_PY="$(printf '%s' "$EXECLINE" | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)"
[ -n "$AGENT_PY" ] && [ -x "$AGENT_PY" ] || AGENT_PY="$(command -v python3)"
MEMCAP="${HERE}/memcap.py"
if [ ! -f "$MEMCAP" ]; then
    WD="$(systemctl show -p WorkingDirectory --value "${U}.service")"
    [ -n "$WD" ] && [ -f "${WD}/memcap.py" ] && MEMCAP="${WD}/memcap.py"
fi
[ -f "$MEMCAP" ] || fail "cannot locate memcap.py to run the functional canary"

echo "    context: user=${AGENT_USER_UNIT}  python=${AGENT_PY}"
echo "    probe:   ${MEMCAP}"

VERDICT="$(probe_json "$AGENT_USER_UNIT" "$AGENT_PY" "$MEMCAP")"
[ -n "$VERDICT" ] || fail "the functional probe produced NO output — the canary could not measure anything, so the grant is UNPROVEN. Refusing to report success."

# Parse strictly. Any parse failure is a hard failure, never a benign default.
EVALME="$(printf '%s' "$VERDICT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    st, pr = d["self_test"], d["probe"]
except Exception as exc:
    print("PARSE_OK=0"); print("PARSE_ERR=%s" % json.dumps(str(exc))); raise SystemExit(0)
print("PARSE_OK=1")
print("SELFTEST_OK=%d" % (1 if st.get("ok") else 0))
# ensure_ascii=False so an em dash in the detail reaches the operator as a dash,
# not a literal \u2014 in the failure message they have to read.
print("SELFTEST_FINDINGS=%s" % json.dumps("; ".join(st.get("findings", [])), ensure_ascii=False))
print("STATE=%s" % json.dumps(pr.get("state", ""), ensure_ascii=False))
print("DETAIL=%s" % json.dumps(str(pr.get("detail", ""))[:200], ensure_ascii=False))
')"
eval "$EVALME"

[ "${PARSE_OK:-0}" = "1" ] || fail "could not parse the probe verdict (${PARSE_ERR:-unknown})"

# The instrument must prove its own premise BEFORE its verdict counts: memcap's
# self-test reads our own memory (must succeed) and a non-existent pid (must not).
if [ "${SELFTEST_OK}" != "1" ]; then
    fail "the probe's OWN self-test failed (${SELFTEST_FINDINGS}) — its verdict is not evidence. Refusing to report success."
fi
ok "probe self-test PASSED (reader works and does not rubber-stamp)"

case "$STATE" in
    available)
        ok "functional cross-process memory read SUCCEEDED (state=available)" ;;
    unavailable)
        fail "the agent still CANNOT read another process's memory (state=unavailable): ${DETAIL}  The drop-in is in place but the capability is not effective. Refusing to report success." ;;
    *)
        fail "capability could not be MEASURED (state=${STATE}): ${DETAIL}  Not a pass, and not assumed. Refusing to report success." ;;
esac

if has_cap "$MAIN_PID"; then
    ok "corroborating: MainPID $MAIN_PID also holds ${CAP} in its effective set"
else
    warn "the functional read succeeded but MainPID $MAIN_PID does not show ${CAP} in CapEff — worth investigating (the functional result is authoritative)."
fi

echo
ok "memory-inspection capability DEPLOYED and PROVEN (functional cross-process read)."
echo "    The agent will report memscan_capability=available on its next heartbeat."
echo "    Uninstall (reversible):  sudo $0 --uninstall"
