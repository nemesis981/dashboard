#!/usr/bin/env bash
#
# revert_core_process.sh — revert ONE core_module process to a known-good git ref.
#
#   sudo bash scripts/revert_core_process.sh --process <svc> --ref <git-ref>
#   sudo bash scripts/revert_core_process.sh --process hw-monitor --ref HEAD~1
#
# This works cleanly because directory-per-process keeps a process's code, its
# manifest, AND its unit under one path (core_module/<mod>/), so one
# `git checkout <ref> -- core_module/<mod>/` restores the whole thing — and the
# script then closes the gap the 2026-07-27 incident proved is easy to forget:
# it REDEPLOYS the unit to /etc/systemd/system and daemon-reloads before
# restarting, and verifies health, rolling back if the ref is bad.
#
set -euo pipefail

TREE="/opt/nemesis"
SYSD="/etc/systemd/system"
BACKUP_ROOT="/var/backups/nemesis"

declare -A MEMBERS=(
  [alert-watcher]=alert_watcher [hw-monitor]=hw_monitor [device-scanner]=device_scanner
  [watchdog]=watchdog [malware-canary]=malware_canary [diagnostics-watcher]=diagnostics_watcher
)

RED=$'\033[31m'; GRN=$'\033[32m'; BLD=$'\033[1m'; RST=$'\033[0m'
ok(){ printf "  %sOK%s   %s\n" "$GRN" "$RST" "$*"; }
die(){ printf "\n  %sFAIL%s %s\n\n" "$RED" "$RST" "$*" >&2; exit 1; }
step(){ printf "\n%s== %s ==%s\n" "$BLD" "$*" "$RST"; }

SVC=""; REF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --process) SVC="${2:-}"; shift 2 ;;
    --ref)     REF="${2:-}"; shift 2 ;;
    *) die "usage: $0 --process <svc> --ref <git-ref>" ;;
  esac
done
[ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"
[ -n "$SVC" ] && [ -n "$REF" ] || die "usage: $0 --process <svc> --ref <git-ref>"
mod="${MEMBERS[$SVC]:-}"
[ -n "$mod" ] || die "unknown process: $SVC (must be a core_module member)"
git -C "$TREE" rev-parse --verify "$REF^{commit}" >/dev/null 2>&1 || die "not a valid git ref: $REF"

installed="$SYSD/$SVC.service"
unit_rel="core_module/$mod/$SVC.service"

step "reverting $SVC to $(git -C "$TREE" rev-parse --short "$REF")"

# back up the CURRENTLY-INSTALLED unit so a bad ref can be undone
bdir="$BACKUP_ROOT/revert-$SVC"
mkdir -p "$bdir"
cp -a "$installed" "$bdir/before.service" 2>/dev/null || true

# 1. restore the whole process directory from the ref (code + manifest + unit)
git -C "$TREE" checkout "$REF" -- "core_module/$mod/" 2>/dev/null \
  || die "the ref does not contain core_module/$mod/ — nothing to revert to"
ok "restored core_module/$mod/ from $REF"

# 2. the restored unit must exist and point at a file that exists
[ -f "$TREE/$unit_rel" ] || die "restored ref has no unit at $unit_rel"
newpath="$(grep -oE '/opt/nemesis/[^ ]*\.py' "$TREE/$unit_rel" | head -1)"
[ -n "$newpath" ] && [ -f "$newpath" ] || die "restored unit ExecStart missing on disk: $newpath"
ok "restored unit ExecStart exists: $newpath"

# 3. redeploy the unit (the step the incident skipped) + reload
cp "$TREE/$unit_rel" "$installed"; chmod 0644 "$installed"
systemctl daemon-reload
ok "redeployed unit + daemon-reload"

# 4. restart + verify healthy; roll back to the pre-revert unit on failure
if ! systemctl restart "$SVC"; then
  cp -a "$bdir/before.service" "$installed"; systemctl daemon-reload; systemctl restart "$SVC" || true
  die "$SVC failed to restart on $REF — restored the pre-revert unit"
fi
sleep 6
st="$(systemctl is-active "$SVC" 2>/dev/null || true)"
sub="$(systemctl show -p SubState --value "$SVC")"
if [ "$st" != "active" ] || [ "$sub" != "running" ]; then
  printf "  %sFAIL%s %s is %s/%s on %s\n" "$RED" "$RST" "$SVC" "$st" "$sub" "$REF"
  journalctl -u "$SVC" --since "-30s" --no-pager 2>/dev/null | tail -4 | sed 's/^/         /'
  cp -a "$bdir/before.service" "$installed"; systemctl daemon-reload; systemctl restart "$SVC" || true
  die "$SVC unhealthy on $REF — restored the pre-revert unit and restarted"
fi
ok "$SVC active/running on $REF ($(systemctl show -p ExecStart --value "$SVC" | grep -oE '/opt[^ ]*\.py'))"
printf "\n  %sRevert complete.%s The working tree now holds core_module/$mod/ at $REF —\n" "$BLD" "$RST"
printf "  reconcile it with git (commit or checkout back) when done.\n\n"
