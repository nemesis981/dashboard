#!/bin/bash
# Nemesis Agent — Behavioral Monitoring (Falco) deployment, Linux
#
# Malware Layer B, behavioral half: install + configure Falco as the endpoint's
# kernel behavioral monitor, wired to feed the (unprivileged) Nemesis agent.
# Companion to install_linux.sh; kept SEPARATE and OPT-IN on purpose.
#
# ── WHY THIS IS A DISTINCT, OPT-IN STEP (the privileged-daemon decision) ─────
# Falco instruments the kernel and MUST run as root. The Nemesis agent
# deliberately runs UNPRIVILEGED. Enabling behavioral monitoring therefore adds
# a new root daemon to the endpoint footprint — a security-posture decision the
# operator makes per fleet, not a default the agent installer silently inherits.
# So this is its own script: running the agent installer never pulls in Falco;
# an operator runs THIS, knowingly, to opt a fleet in. See docs/CUSTOM_FALCO.md.
#
# ── THE PRIVILEGE SPLIT (load-bearing) ──────────────────────────────────────
# Falco (root) WRITES the event file; the agent (unprivileged) only READS it.
# We grant the agent read access via a POSIX default ACL on the log dir, so
# Falco's freshly-created event file is readable by the agent user WITHOUT the
# agent ever gaining privilege or Falco ever being controlled by the agent.
#
# ── "DEPLOYED" MEANS "DETECTION DEMONSTRABLY WORKS", NOT "apt EXITED 0" ──────
# Per the standing rule that a verification step must prove its own premise:
# after starting Falco this script fires a KNOWN canary event (a sensitive-file
# read) and confirms it actually lands in the event file before declaring
# success. A green systemd unit whose probe never loaded or whose rules never
# matched would otherwise look identical to a working one. Fail closed + loud.
#
#   sudo ./deploy_behavioral_linux.sh                 # install + verify + enable
#   sudo ./deploy_behavioral_linux.sh --uninstall     # proven, reversible removal
#   sudo ./deploy_behavioral_linux.sh --local-deb X.deb   # air-gapped install
#
set -euo pipefail

AGENT_INSTALL_DIR="${NEMESIS_INSTALL_DIR:-/opt/nemesis-agent}"
AGENT_CONF="${AGENT_INSTALL_DIR}/nemesis_agent.conf"
EVENTS_DIR="/var/log/falco"
EVENTS_FILE="${NEMESIS_FALCO_OUTPUT:-${EVENTS_DIR}/events.json}"
MIN_KMAJ=5; MIN_KMIN=8          # modern eBPF (CO-RE) needs kernel >= 5.8
DO_UNINSTALL=0
EXTRA_RULES=0                     # opt-in: broader (noisier) incubating+sandbox rule feeds
LOCAL_DEB=""
AGENT_USER="${NEMESIS_AGENT_USER:-}"

step()  { echo -e "\n==> $1"; }
ok()    { echo "    [OK] $1"; }
warn()  { echo "    [!!] $1"; }
fail()  { echo "    [FAIL] $1" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall)    DO_UNINSTALL=1; shift ;;
        --extra-rules)  EXTRA_RULES=1; shift ;;
        --local-deb)    LOCAL_DEB="${2:-}"; shift 2 ;;
        --user)         AGENT_USER="${2:-}"; shift 2 ;;
        --events-file)  EVENTS_FILE="${2:-}"; EVENTS_DIR="$(dirname "$EVENTS_FILE")"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ "$EUID" -eq 0 ] || fail "Run as root: sudo bash deploy_behavioral_linux.sh"

# The Falco service name differs by driver; the modern-bpf unit is what the
# package's modern-ebpf choice enables. Resolve it, fall back to plain 'falco'.
falco_unit() {
    for u in falco-modern-bpf falco-bpf falco; do
        if systemctl list-unit-files "${u}.service" >/dev/null 2>&1 \
           && systemctl cat "${u}.service" >/dev/null 2>&1; then echo "$u"; return; fi
    done
    echo "falco-modern-bpf"
}

# ── uninstall path (reversible, proven) ─────────────────────────────────────
if [ "$DO_UNINSTALL" -eq 1 ]; then
    step "Uninstalling behavioral monitoring (reversible)"
    U="$(falco_unit)"
    systemctl stop "$U" 2>/dev/null || true
    systemctl disable "$U" 2>/dev/null || true
    rm -f /etc/falco/config.d/zzz-nemesis-behavioral.yaml /etc/falco/config.d/zzz-nemesis-rules.yaml 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    # flip the agent back to behavioral-off so it stops tailing a dead file
    if [ -f "$AGENT_CONF" ]; then
        sed -i 's/^behavioral_enabled *=.*/behavioral_enabled = false/' "$AGENT_CONF" || true
        ok "agent config: behavioral_enabled = false"
    fi
    # prove it: the daemon must be gone
    if systemctl is-active --quiet "$U"; then
        fail "Falco unit '$U' is still active after stop/disable — NOT cleanly removed"
    fi
    ok "Falco unit '$U' stopped and disabled (verified inactive)"
    warn "the falco PACKAGE is left installed (removing it is a separate 'apt purge falco');"
    warn "this makes re-enabling instant and avoids surprising a shared box."
    echo; ok "behavioral monitoring disabled. Re-run without --uninstall to re-enable."
    exit 0
fi

# ── preflight: fail CLOSED on any unmet premise ─────────────────────────────
step "Preflight"

[ -n "$AGENT_USER" ] || AGENT_USER="${SUDO_USER:-root}"
id "$AGENT_USER" >/dev/null 2>&1 || fail "agent user '$AGENT_USER' does not exist (pass --user)"
ok "agent (reader) user: $AGENT_USER"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64|aarch64|arm64) ok "arch: $ARCH" ;;
    *) fail "unsupported arch '$ARCH' for the modern eBPF probe" ;;
esac

KREL="$(uname -r)"; KMAJ="${KREL%%.*}"; REST="${KREL#*.}"; KMIN="${REST%%.*}"
if [ "$KMAJ" -lt "$MIN_KMAJ" ] || { [ "$KMAJ" -eq "$MIN_KMAJ" ] && [ "$KMIN" -lt "$MIN_KMIN" ]; }; then
    fail "kernel $KREL < ${MIN_KMAJ}.${MIN_KMIN}; the modern eBPF probe is unavailable. \
Install a newer kernel or use the kmod/legacy-ebpf driver (not automated here)."
fi
ok "kernel $KREL supports the modern eBPF probe (>= ${MIN_KMAJ}.${MIN_KMIN})"

command -v setfacl >/dev/null 2>&1 || warn "setfacl (acl) absent — will fall back to a group-grant for the reader"

# ── install falco (idempotent) ──────────────────────────────────────────────
if command -v falco >/dev/null 2>&1; then
    step "Falco already installed ($(falco --version 2>&1 | head -1)); skipping package install"
elif [ -n "$LOCAL_DEB" ]; then
    step "Installing Falco from local .deb (air-gapped): $LOCAL_DEB"
    [ -f "$LOCAL_DEB" ] || fail "local deb not found: $LOCAL_DEB"
    DEBIAN_FRONTEND=noninteractive FALCO_FRONTEND=noninteractive \
        FALCO_DRIVER_CHOICE=modern-ebpf apt-get install -y "$LOCAL_DEB" \
        || fail "local .deb install failed"
else
    step "Installing Falco from the falcosecurity apt repo (modern eBPF)"
    # KEY TO FILE, then dearmor from the file. Piping the key straight into
    # `sudo gpg` collides with the sudo password on stdin — a real trap hit
    # during the 2026-08-21 live bring-up.
    KEYRING=/usr/share/keyrings/falco-archive-keyring.gpg
    tmpkey="$(mktemp)"
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc -o "$tmpkey" \
        || fail "could not fetch the Falco repo key (no internet? use --local-deb)"
    head -1 "$tmpkey" | grep -q "BEGIN PGP" || fail "downloaded key is not a PGP block (proxy/redirect page?)"
    gpg --batch --yes --dearmor -o "$KEYRING" "$tmpkey"; rm -f "$tmpkey"
    echo "deb [signed-by=$KEYRING] https://download.falco.org/packages/deb stable main" \
        > /etc/apt/sources.list.d/falcosecurity.list

    # dpkg-lock contention (unattended-upgrades) is common on a fresh box and
    # made a hand install fail on 2026-08-21. Wait for the lock; back off the
    # timers if needed, and RESTORE them afterward.
    stopped_uu=0
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        warn "dpkg lock held (likely unattended-upgrades); pausing it to proceed"
        systemctl stop unattended-upgrades.service apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
        stopped_uu=1
        for _i in $(seq 1 60); do
            fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 2
        done
    fi
    apt-get update -qq || { [ "$stopped_uu" -eq 1 ] && systemctl start unattended-upgrades.service 2>/dev/null || true; fail "apt-get update failed"; }
    DEBIAN_FRONTEND=noninteractive FALCO_FRONTEND=noninteractive \
        FALCO_DRIVER_CHOICE=modern-ebpf apt-get install -y falco \
        || { [ "$stopped_uu" -eq 1 ] && systemctl start unattended-upgrades.service 2>/dev/null || true; fail "falco install failed"; }
    # restore the timers we paused
    [ "$stopped_uu" -eq 1 ] && systemctl start unattended-upgrades.service 2>/dev/null || true
fi
command -v falco >/dev/null 2>&1 || fail "falco not on PATH after install"
ok "falco present: $(falco --version 2>&1 | head -1)"

# Optional: broader rule coverage. The slimmed DEFAULT ruleset only arms a few
# techniques (verified live 2026-08-21: a credential-read fires, but persistence /
# setuid / ptrace / network-tool launches do NOT). The incubating + sandbox feeds
# arm them. Broader = noisier, so this is opt-in for endpoints; the detonation base
# builder passes --extra-rules because a detonation sandbox WANTS to observe
# everything. falcoctl verifies each artifact's digest on install.
if [ "$EXTRA_RULES" -eq 1 ] && command -v falcoctl >/dev/null 2>&1; then
    step "Installing broader Falco rule feeds (incubating + sandbox)"
    falcoctl artifact install falco-incubating-rules >/dev/null 2>&1 \
        && ok "falco-incubating-rules installed" || warn "incubating-rules install failed"
    falcoctl artifact install falco-sandbox-rules >/dev/null 2>&1 \
        && ok "falco-sandbox-rules installed" || warn "sandbox-rules install failed"
    cat > /etc/falco/config.d/zzz-nemesis-rules.yaml <<'YAML'
# managed by deploy_behavioral_linux.sh --extra-rules
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco-incubating_rules.yaml
  - /etc/falco/falco-sandbox_rules.yaml
  - /etc/falco/rules.d
YAML
    ok "wired incubating+sandbox rules into the load list"
fi

# ── configure JSON file output + modern-bpf engine ──────────────────────────
step "Configuring Falco (JSON -> $EVENTS_FILE, modern eBPF engine)"
mkdir -p "$EVENTS_DIR"
# Grant the unprivileged agent READ on the dir, and a DEFAULT acl so Falco's
# newly-created event file inherits reader access without the agent ever
# gaining privilege. Fall back to a group grant if acl is unavailable.
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u:"$AGENT_USER":rx "$EVENTS_DIR"
    setfacl -d -m u:"$AGENT_USER":r "$EVENTS_DIR"
    ok "ACL: $AGENT_USER can read $EVENTS_DIR and files Falco creates there"
else
    chgrp "$(id -gn "$AGENT_USER")" "$EVENTS_DIR" && chmod 750 "$EVENTS_DIR"
    warn "granted via group $(id -gn "$AGENT_USER") (no per-file inheritance; watch new-file perms)"
fi

# Falco config goes in a config.d DROP-IN, not falco.yaml. Modern Falco (0.44)
# loads /etc/falco/config.d/*.yaml lexicographically AFTER falco.yaml and lets
# them override it — so a `zzz-` drop-in cleanly wins for file_output, whereas
# appending to falco.yaml did NOT take effect (proven on the 2026-08-21 live
# bring-up: events went only to stdout, no file). We do NOT set engine.kind:
# the package's falcoctl already committed modern_ebpf to its own drop-in
# (engine-kind-falcoctl.yaml); re-setting it would just fight that. stdout is
# silenced so the daemon's own logging stays clean.
DROPIN="/etc/falco/config.d/zzz-nemesis-behavioral.yaml"
mkdir -p /etc/falco/config.d
cat > "$DROPIN" <<YAML
# managed by deploy_behavioral_linux.sh — behavioral events -> Nemesis agent
json_output: true
json_include_output_property: true
buffered_outputs: false
stdout_output:
  enabled: false
file_output:
  enabled: true
  keep_alive: false
  filename: $EVENTS_FILE
YAML
ok "wrote Falco config drop-in: $DROPIN"

# ── enable + start, then PROVE it works with a canary ───────────────────────
UNIT="$(falco_unit)"
step "Enabling + starting Falco unit: $UNIT"
systemctl daemon-reload
systemctl enable "$UNIT" >/dev/null 2>&1 || true
systemctl restart "$UNIT"
sleep 8
systemctl is-active --quiet "$UNIT" || { journalctl -u "$UNIT" -n 15 --no-pager; fail "Falco unit '$UNIT' is not active"; }
ok "unit active"
journalctl -u "$UNIT" -n 40 --no-pager | grep -qi "modern BPF probe" \
    && ok "modern eBPF probe loaded (from journal)" \
    || warn "could not confirm the modern BPF probe line in the journal (continuing to canary)"

step "CANARY — proving detection actually reaches the event file"
# a KNOWN-good trigger: reading a sensitive file fires the default rule
# 'Read sensitive file untrusted'. If this does NOT appear, the pipeline is
# broken however green the unit looks — fail closed.
cat /etc/shadow >/dev/null 2>&1 || true
found=0
for _i in $(seq 1 10); do
    if grep -q "Read sensitive file" "$EVENTS_FILE" 2>/dev/null; then found=1; break; fi
    sleep 1
done
[ "$found" -eq 1 ] || { warn "event file: $EVENTS_FILE"; tail -3 "$EVENTS_FILE" 2>/dev/null; \
    fail "CANARY FAILED: a known sensitive-file read did not surface in $EVENTS_FILE. \
Detection is NOT working; refusing to report success."; }
ok "canary event observed in $EVENTS_FILE — detection chain proven end to end"
# confirm the unprivileged agent user can actually read it (the privilege split)
if sudo -u "$AGENT_USER" test -r "$EVENTS_FILE"; then
    ok "unprivileged agent user '$AGENT_USER' can read the event file"
else
    fail "agent user '$AGENT_USER' CANNOT read $EVENTS_FILE — the reader grant did not take"
fi

# ── flip the agent on ───────────────────────────────────────────────────────
step "Enabling behavioral monitoring in the agent config"
if [ -f "$AGENT_CONF" ]; then
    if grep -q '^behavioral_enabled *=' "$AGENT_CONF"; then
        sed -i 's/^behavioral_enabled *=.*/behavioral_enabled = true/' "$AGENT_CONF"
    else
        echo "behavioral_enabled = true" >> "$AGENT_CONF"
    fi
    if grep -q '^behavioral_falco_output *=' "$AGENT_CONF"; then
        sed -i "s#^behavioral_falco_output *=.*#behavioral_falco_output = ${EVENTS_FILE}#" "$AGENT_CONF"
    else
        echo "behavioral_falco_output = ${EVENTS_FILE}" >> "$AGENT_CONF"
    fi
    ok "agent config updated (behavioral_enabled = true, output = $EVENTS_FILE)"
    systemctl restart nemesis-agent 2>/dev/null && ok "nemesis-agent restarted" \
        || warn "could not restart nemesis-agent (is it installed here? config is set for next start)"
else
    warn "agent config $AGENT_CONF not found — install the agent, then set:"
    warn "  behavioral_enabled = true"
    warn "  behavioral_falco_output = $EVENTS_FILE"
fi

echo
ok "Behavioral monitoring DEPLOYED and PROVEN. Findings ride the heartbeat as attested claims."
echo "    Uninstall (reversible):  sudo bash $0 --uninstall"
