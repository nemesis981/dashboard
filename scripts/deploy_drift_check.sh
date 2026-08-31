#!/usr/bin/env bash
# Install the netfilter drift checker into a ROOT-OWNED location OUTSIDE the tree it
# reads from. Sibling of deploy_integrity_check.sh and deliberately the same shape.
#
# WHY OUT OF TREE, when this is only DRIFT detection and not tamper detection:
# the reason here is not the verdict's trustworthiness, it is the PRIVILEGE BOUNDARY.
# This unit runs as root on a timer. /opt/nemesis/core is 0664 <user>:<user>, so a root
# unit importing netfilter_drift.py from the repo would execute code an unprivileged
# account can rewrite -- a local privilege-escalation path handed to us by a security
# checker. Installing root-owned copies removes it:
#
#   /usr/local/lib/nemesis-drift/       0500 root:root  checker + its OWN verifier
#   /var/lib/nemesis-drift/status.json  0644 root:root  the fact file
#
# The FACT FILE is deliberately NOT inside $DEST: that directory is 0500 root:root and
# the poller's user (nemesis-diag) cannot traverse it. Root writes the verdict,
# unprivileged reads it, never the reverse.
#
# WHAT THIS DOES NOT DEFEND AGAINST, said plainly: an attacker who already has root
# can rewrite the fact file to say "ok" or stop the timer, and nothing here notices.
# That is the same acknowledged floor integrity_watch carries. This detects DRIFT --
# a reverted Tailscale netfilter mode, a lost anti-spoof rule -- which is the likelier
# real-world trigger and today has no symptom at all.
set -euo pipefail

DEST="/usr/local/lib/nemesis-drift"
REPO="${1:-/opt/nemesis}"
STATUS_DIR="/var/lib/nemesis-drift"
UNIT="/etc/systemd/system/nemesis-drift-check.service"
TIMER="/etc/systemd/system/nemesis-drift-check.timer"

[ "$(id -u)" -eq 0 ] || { echo "ABORT: must run as root" >&2; exit 2; }
[ -d "$REPO" ] || { echo "ABORT: repo not found at $REPO" >&2; exit 2; }
for f in scripts/nemesis-drift-check core/netfilter_drift.py; do
  [ -f "$REPO/$f" ] || { echo "ABORT: missing $REPO/$f" >&2; exit 2; }
done

# Refuse to ship a verifier that cannot prove it distinguishes healthy from reverted.
# Running the self-test BEFORE install means a broken verifier never reaches a root
# unit at all, rather than being discovered by its first silent all-clear.
if ! python3 -c "
import sys; sys.path.insert(0, '$REPO/core')
import netfilter_drift as ND
ok, detail = ND.selftest()
print(('selftest: ' + detail) if ok else ('SELFTEST FAILED: ' + detail))
sys.exit(0 if ok else 1)
"; then
  echo "ABORT: verifier self-test failed -- not installing" >&2
  exit 2
fi

# The unit must be able to CONNECT to tailscaled's local-API socket. Connecting to a
# unix socket requires WRITE access to the inode, and ProtectSystem=strict mounts the
# hierarchy read-only -- so the socket's directory needs an explicit ReadWritePaths
# exception or the netfilter half reports UNDETERMINED forever.
#
# Detected rather than hardcoded: a snap install and a native install put it in
# different places. If none is found we still install (the daemon may start later) and
# say so, because the checker fails CLOSED and will name the missing socket itself.
TS_SOCK=""
for c in /var/run/tailscale/tailscaled.sock /run/tailscale/tailscaled.sock \
         /var/snap/tailscale/common/socket/tailscaled.sock; do
  if [ -S "$c" ]; then TS_SOCK="$c"; break; fi
done
if [ -n "$TS_SOCK" ]; then
  TS_SOCK_DIR="$(dirname "$TS_SOCK")"
  echo "tailscaled socket: $TS_SOCK"
else
  TS_SOCK_DIR=""
  echo "WARNING: no tailscaled socket found. Installing anyway -- the checker fails"
  echo "         CLOSED and will report the exact path it looked for. Re-run this"
  echo "         script once tailscaled is up so the unit gets its socket exception."
fi

install -d -o root -g root -m 0500 "$DEST"
install -d -o root -g root -m 0755 "$STATUS_DIR"

# The checker's OWN copy of the verifier. It must NOT import the repo's copy -- see
# the privilege-escalation note in the header. nemesis-drift-check prefers the copy
# beside itself, so installing it here is what makes that preference take effect.
install -o root -g root -m 0500 "$REPO/scripts/nemesis-drift-check" "$DEST/nemesis-drift-check"
install -o root -g root -m 0400 "$REPO/core/netfilter_drift.py"     "$DEST/netfilter_drift.py"

cat > "$UNIT" <<UNITEOF
[Unit]
Description=Nemesis netfilter security-property drift check (nodivert + anti-spoof)
After=network.target

[Service]
Type=oneshot
# ROOT, deliberately and unavoidably: /etc/ufw/before.rules is 0640 root:root, so the
# anti-spoof half is STRUCTURALLY unreadable to any unprivileged service. That is the
# documented reason this is not a diagnostics/ module.
User=root
ExecStart=$DEST/nemesis-drift-check
# It reads /etc/ufw/before.rules and tailscaled's local-API socket; it writes only the
# fact file.
#
# ⚠ NO PATH= IS SET, AND NONE SHOULD BE. The checker talks to tailscaled's socket
# directly and runs no external binary. An earlier version shelled out to \`tailscale\`,
# which broke on first deployment: that binary is a snap at /snap/bin, absent from
# systemd's default PATH. Adding /snap/bin here would fix the lookup and still be wrong
# -- running a snap requires snap-confine, which refuses to start inside the mount
# namespace these very directives create. The dependency was removed instead.
ProtectSystem=strict
ReadWritePaths=$STATUS_DIR${TS_SOCK_DIR:+ $TS_SOCK_DIR}
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
# Root's file access here is by ownership (before.rules is root-owned and mode 0640),
# so no capability is required. An empty bounding set means a compromised checker
# cannot change the firewall it inspects -- it may only look.
CapabilityBoundingSet=
# A non-zero exit is a REAL FINDING (1 = drift, 2 = cannot verify) and must stay
# visible in the journal and in systemctl status. Do NOT add SuccessExitStatus to
# quieten it -- that converts the entire point of this unit into a no-op.
UNITEOF
chmod 0644 "$UNIT"

cat > "$TIMER" <<TIMEREOF
[Unit]
Description=Periodic Nemesis netfilter drift check

[Timer]
# Both triggers matter and neither replaces the other. OnBootSec catches the likeliest
# real cause -- a Tailscale package upgrade restoring NetfilterMode=on across a reboot.
# OnUnitActiveSec catches a mid-run reversion without waiting for the next boot.
OnBootSec=3min
OnUnitActiveSec=1h
Persistent=true
RandomizedDelaySec=5min
Unit=nemesis-drift-check.service

[Install]
WantedBy=timers.target
TIMEREOF
chmod 0644 "$TIMER"

systemctl daemon-reload
systemctl enable --now nemesis-drift-check.timer

echo
echo "installed: $DEST (0500 root:root), fact file -> $STATUS_DIR/status.json"
echo
echo "VERIFY -- do not accept 'is-active' alone. Run:"
echo "  systemctl start nemesis-drift-check.service"
echo "  systemctl show nemesis-drift-check.service -p ExecMainPID -p ExecMainStatus -p ExecMainExitTimestamp"
echo "  cat $STATUS_DIR/status.json"
echo
echo "Two things to read in that JSON, not just the verdict:"
echo "  * .verifier MUST be $DEST/netfilter_drift.py --"
echo "    /opt/nemesis/core/... means the deploy did not take and root is importing"
echo "    a user-writable file. 'ok' reads identically either way."
echo "  * .checks.netfilter_mode.status MUST be 'ok' or 'drifted', NOT 'undetermined'."
echo "    Undetermined means the socket was unreachable -- a fail-closed non-answer, not"
echo "    a pass. The detail now names the REAL cause (socket missing / permission"
echo "    denied / no answer); read it rather than assuming the daemon is at fault."
if [ -z "$TS_SOCK_DIR" ]; then
  echo "  * NOTE: no socket was found at install time, so the unit has NO socket"
  echo "    exception. Re-run this script once tailscaled is up."
fi
