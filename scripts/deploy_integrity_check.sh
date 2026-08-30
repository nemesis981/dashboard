#!/usr/bin/env bash
# Install the file-integrity checker into a ROOT-OWNED location OUTSIDE the tree
# it verifies. Decision record: 2026-08-29-file-integrity-tamper-detection-RESOLVED.md
#
# THE PRIVILEGE SEPARATION IS THE WHOLE POINT, and it is a property of WHERE
# things live, not of what the code does:
#
#   /usr/local/lib/nemesis-integrity/   0500 root:root   the checker + its OWN integrity.py
#   .../manifest.json                   0400 root:root   signed at release time, offline
#   .../integrity_public.pem            0444 root:root   public half only; no private key, ever
#
# 0500 on the directory means the dashboard user cannot list, read or replace any
# of it. A checker the watched code can rewrite is decoration.
#
# WHAT THIS DOES NOT DEFEND AGAINST, said plainly: an attacker who already has
# root can replace every file above. That is the acknowledged floor (TPM
# attestation, out of scope for v1). This raises the bar; it does not end the
# regress.
set -euo pipefail

DEST="/usr/local/lib/nemesis-integrity"
REPO="${1:-/opt/nemesis}"
STATUS_DIR="/var/lib/nemesis-integrity"
UNIT="/etc/systemd/system/nemesis-integrity.service"
TIMER="/etc/systemd/system/nemesis-integrity.timer"

[ "$(id -u)" -eq 0 ] || { echo "ABORT: must run as root" >&2; exit 2; }
[ -d "$REPO" ] || { echo "ABORT: repo not found at $REPO" >&2; exit 2; }

install -d -o root -g root -m 0500 "$DEST"

# The FACT FILE directory is deliberately NOT $DEST. $DEST is 0500 root:root, which
# the poller's user (nemesis-diag) cannot even traverse. This is root-WRITABLE and
# world-READABLE: root writes the verdict, unprivileged reads it, never the reverse.
install -d -o root -g root -m 0755 "$STATUS_DIR"

# The checker's OWN copy of the verifier. It must NOT import the repo's copy --
# an attacker editing the tree would otherwise be editing the verifier's logic.
install -o root -g root -m 0500 "$REPO/scripts/nemesis-integrity-check" "$DEST/nemesis-integrity-check"
install -o root -g root -m 0400 "$REPO/alert_manager/integrity.py"      "$DEST/integrity.py"

# Public key and manifest are supplied by the release, not generated here. There
# is deliberately no "generate a key" path: a key this box could generate is a key
# an attacker on this box could generate.
for f in manifest.json integrity_public.pem; do
  if [ -f "$REPO/release/$f" ]; then
    mode=0400; [ "$f" = integrity_public.pem ] && mode=0444
    install -o root -g root -m "$mode" "$REPO/release/$f" "$DEST/$f"
  else
    echo "WARNING: $REPO/release/$f not present -- the checker will FAIL CLOSED"
    echo "         (exit 2, 'cannot verify') until the release supplies it."
  fi
done

cat > "$UNIT" <<UNITEOF
[Unit]
Description=Nemesis file-integrity verification (signed manifest)
After=network.target

[Service]
Type=oneshot
# ROOT, deliberately: it must read protected files regardless of their ownership,
# and it must not be killable or rewritable by the services it watches.
User=root
ExecStart=$DEST/nemesis-integrity-check --root $REPO
# The checker reads; it never writes to the tree it verifies.
ProtectSystem=strict
# The one path it may write: the fact file the in-tree poller reads.
ReadWritePaths=$STATUS_DIR
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
# A non-zero exit is a REAL FINDING and must stay visible in the journal and in
# systemctl status. Do NOT add SuccessExitStatus=1 to quieten it -- that would
# convert the entire point of this unit into a no-op.
UNITEOF
chmod 0644 "$UNIT"

cat > "$TIMER" <<TIMEREOF
[Unit]
Description=Periodic Nemesis file-integrity verification

[Timer]
# Hourly plus at boot. Tampering that only persists between reboots is still
# tampering, and a daily check gives a 24-hour window to act in.
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true
RandomizedDelaySec=5min
Unit=nemesis-integrity.service

[Install]
WantedBy=timers.target
TIMEREOF
chmod 0644 "$TIMER"

systemctl daemon-reload
systemctl enable --now nemesis-integrity.timer

echo "installed: $DEST (0500 root:root)"
echo "verify now:  systemctl start nemesis-integrity.service; systemctl status nemesis-integrity.service"
