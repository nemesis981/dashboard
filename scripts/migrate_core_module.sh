#!/usr/bin/env bash
#
# migrate_core_module.sh — deploy the core_module layout move for the six
# monitored daemons, one process at a time, with the same discipline as
# deploy_nemesis_fwd.sh: --preflight / --run [--only <svc>] / --verify /
# --rollback [--only <svc>].
#
#   sudo bash scripts/migrate_core_module.sh --preflight
#   sudo bash scripts/migrate_core_module.sh --run --only malware-canary
#   sudo bash scripts/migrate_core_module.sh --verify
#   sudo bash scripts/migrate_core_module.sh --rollback --only malware-canary
#
# SAFETY MODEL (mirrors the plan, built around the 2026-07-27 incident):
#  * COPY-then-delete: the new core_module/<mod>/<mod>.py already exists (authored
#    + committed); the OLD alert_manager/<mod>.py is NOT touched by this script, so
#    a stray restart during the window still finds a valid file at the old path.
#  * The installed unit is BACKED UP before it is replaced, and the new unit's
#    ExecStart path is verified to EXIST on disk BEFORE any restart.
#  * Per process: deploy -> restart -> verify healthy; abort the whole run on the
#    first failure and roll THAT process back. Already-migrated ones stay up.
#
set -euo pipefail

TREE="/opt/nemesis"
SYSD="/etc/systemd/system"
BACKUP_ROOT="/var/backups/nemesis"
STATE="/var/lib/nemesis/.coremodule-migrated"   # records which services are migrated

# service-name -> module directory (the .py and the dir share the module name;
# the unit file keeps the hyphenated service name).
declare -A MEMBERS=(
  [alert-watcher]=alert_watcher
  [hw-monitor]=hw_monitor
  [device-scanner]=device_scanner
  [watchdog]=watchdog
  [malware-canary]=malware_canary
  [diagnostics-watcher]=diagnostics_watcher
)
ORDER=(diagnostics-watcher malware-canary device-scanner watchdog alert-watcher hw-monitor)

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
step(){ printf "\n%s== %s ==%s\n" "$BLD" "$*" "$RST"; }
ok(){ printf "  %sOK%s   %s\n" "$GRN" "$RST" "$*"; }
warn(){ printf "  %sWARN%s %s\n" "$YEL" "$RST" "$*"; }
info(){ printf "       %s\n" "$*"; }
die(){ printf "\n  %sFAIL%s %s\n\n" "$RED" "$RST" "$*" >&2; exit 1; }
need_root(){ [ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"; }

svc_state(){ systemctl is-active "$1" 2>/dev/null || true; }
new_py(){ echo "$TREE/core_module/${MEMBERS[$1]}/${MEMBERS[$1]}.py"; }
new_unit(){ echo "$TREE/core_module/${MEMBERS[$1]}/$1.service"; }
old_py(){ echo "$TREE/alert_manager/${MEMBERS[$1]}.py"; }
installed_execstart(){ systemctl show -p ExecStart --value "$1" 2>/dev/null | grep -oE "/opt[^ ]*\.py" || true; }

# ── health check: active, running (not auto-restart), not crash-looping, and the
# import actually resolved (a crash-looper can flicker 'active' between restarts).
verify_healthy(){
  local svc="$1" settle="${2:-6}"
  sleep "$settle"
  local st sub n
  st="$(svc_state "$svc")"; sub="$(systemctl show -p SubState --value "$svc")"
  n="$(systemctl show -p NRestarts --value "$svc" 2>/dev/null || echo 0)"
  if [ "$st" != "active" ] || [ "$sub" != "running" ]; then
    printf "  %sFAIL%s %s is %s/%s (nrestarts=%s)\n" "$RED" "$RST" "$svc" "$st" "$sub" "$n"
    journalctl -u "$svc" --since "-30s" --no-pager 2>/dev/null | grep -iE "error|traceback|modulenot|no module" | tail -4 | sed 's/^/         /'
    return 1
  fi
  # confirm it is running from core_module, not the old path
  local ex; ex="$(installed_execstart "$svc")"
  case "$ex" in
    *"/core_module/"*) : ;;
    *) printf "  %sFAIL%s %s ExecStart still points at %s\n" "$RED" "$RST" "$svc" "$ex"; return 1 ;;
  esac
  ok "$svc active/running from $(basename "$(dirname "$ex")")/$(basename "$ex") (nrestarts=$n)"
  return 0
}

do_preflight(){
  need_root
  step "1/4 tree + generated artifacts"
  [ -d "$TREE/.git" ] || die "$TREE is not a git repo"
  local svc mod
  for svc in "${ORDER[@]}"; do
    mod="${MEMBERS[$svc]}"
    [ -f "$(new_py "$svc")" ]   || die "missing new file: core_module/$mod/$mod.py (author + commit first)"
    [ -f "$(new_unit "$svc")" ] || die "missing new unit: core_module/$mod/$svc.service (run gen_units.py)"
    [ -f "$(old_py "$svc")" ]   || warn "old file alert_manager/$mod.py already gone — copy-then-delete safety reduced"
  done
  ok "all six new files + units present; old files present (rollback-safe)"

  step "2/4 units match the generator (no drift)"
  if python3 "$TREE/scripts/gen_units.py" --check >/dev/null 2>&1; then
    ok "gen_units.py --check passes"
  else
    python3 "$TREE/scripts/gen_units.py" --check 2>&1 | sed 's/^/       /'
    die "generated units differ from disk — regenerate before deploying"
  fi

  step "3/4 PYTHONPATH present in each new unit (the load-bearing fix)"
  for svc in "${ORDER[@]}"; do
    grep -q "Environment=PYTHONPATH=$TREE/alert_manager:$TREE" "$(new_unit "$svc")" \
      && ok "$svc unit carries PYTHONPATH" \
      || die "$svc unit is MISSING PYTHONPATH — would crash-loop on import"
  done

  step "4/4 current state"
  for svc in "${ORDER[@]}"; do
    info "$(printf '%-22s %-8s from %s' "$svc" "$(svc_state "$svc")" "$(installed_execstart "$svc")")"
  done
  printf "\n  %sPreflight complete.%s Deploy one at a time: --run --only <svc>\n\n" "$BLD" "$RST"
}

deploy_one(){
  local svc="$1" mod="${MEMBERS[$1]}"
  local nunit; nunit="$(new_unit "$svc")"
  local installed="$SYSD/$svc.service"
  local newpath; newpath="$(grep -oE "/opt/nemesis/core_module/$mod/$mod\.py" "$nunit" || true)"

  step "migrating $svc"
  [ -f "$nunit" ] || die "no new unit for $svc"
  [ -n "$newpath" ] && [ -f "$newpath" ] || die "new ExecStart path missing on disk: $newpath"
  ok "new ExecStart path exists: $newpath"

  # back up the installed unit
  local bdir="$BACKUP_ROOT/units-coremodule"
  mkdir -p "$bdir"
  if [ -f "$installed" ] && [ ! -f "$bdir/$svc.service" ]; then
    cp -a "$installed" "$bdir/$svc.service"; ok "backed up installed unit -> $bdir/$svc.service"
  fi

  # gen_units emits User=__INSTALL_USER__ for the install-user services
  # (device-scanner, dashboard); install.sh substitutes it at install time, so
  # the GENERATED unit still carries the raw placeholder. Deploying it verbatim
  # fails with "Unknown user". Substitute it from GROUND TRUTH — the user the
  # service currently runs as — so no install username is hardcoded (Rule 8).
  if grep -q "__INSTALL_USER__" "$nunit"; then
    local realuser; realuser="$(systemctl show -p User --value "$svc" 2>/dev/null)"
    [ -n "$realuser" ] && [ "$realuser" != "__INSTALL_USER__" ] \
      || die "$svc unit has __INSTALL_USER__ but its current User could not be resolved"
    sed "s/__INSTALL_USER__/$realuser/g" "$nunit" > "$installed"
    ok "substituted __INSTALL_USER__ -> $realuser (from the running unit)"
  else
    cp "$nunit" "$installed"
  fi
  chmod 0644 "$installed"
  systemctl daemon-reload
  ok "deployed new unit + daemon-reload"

  if ! systemctl restart "$svc"; then
    warn "restart command failed; rolling back $svc"
    rollback_one "$svc"; die "$svc failed to restart — rolled back"
  fi
  if ! verify_healthy "$svc" 7; then
    warn "post-restart health check failed; rolling back $svc"
    rollback_one "$svc"
    die "$svc unhealthy after migration — rolled back to the old unit; run stopped"
  fi
  grep -q "^$svc\$" "$STATE" 2>/dev/null || echo "$svc" >> "$STATE"
}

rollback_one(){
  local svc="$1"
  local installed="$SYSD/$svc.service"
  local bak="$BACKUP_ROOT/units-coremodule/$svc.service"
  [ -f "$bak" ] || { warn "no backup for $svc — cannot restore its old unit"; return 1; }
  cp -a "$bak" "$installed"; chmod 0644 "$installed"
  systemctl daemon-reload
  systemctl restart "$svc" || true
  sleep 4
  if [ "$(svc_state "$svc")" = "active" ]; then
    ok "$svc rolled back to old unit ($(installed_execstart "$svc"))"
    sed -i "/^$svc\$/d" "$STATE" 2>/dev/null || true
    return 0
  fi
  printf "  %sFAIL%s %s did not recover after rollback — investigate now\n" "$RED" "$RST" "$svc"
  return 1
}

do_run(){
  need_root
  local only="${1:-}"
  if [ -n "$only" ]; then
    [ -n "${MEMBERS[$only]:-}" ] || die "unknown service: $only"
    deploy_one "$only"
    printf "\n  %s%s migrated and healthy.%s Verify others, then continue.\n\n" "$BLD" "$only" "$RST"
    return
  fi
  warn "no --only given: migrating ALL six INCREMENTALLY (abort on first failure)."
  for svc in "${ORDER[@]}"; do deploy_one "$svc"; done
  printf "\n  %sAll six migrated.%s Run --verify.\n\n" "$BLD" "$RST"
}

do_verify(){
  need_root
  step "verify all six"
  local fails=0 svc
  for svc in "${ORDER[@]}"; do
    verify_healthy "$svc" 0 || fails=$((fails+1))
  done
  # import smoke test under each unit's env (catches a lurking import gap)
  for svc in "${ORDER[@]}"; do
    local mod="${MEMBERS[$svc]}"
    if PYTHONPATH="$TREE/alert_manager:$TREE" python3 -c "import ast,sys; ast.parse(open('$(new_py "$svc")').read())" 2>/dev/null; then :; else
      printf "  %sFAIL%s %s: new file does not parse\n" "$RED" "$RST" "$mod"; fails=$((fails+1)); fi
  done
  [ "$fails" -eq 0 ] && printf "\n  %sAll six healthy from core_module.%s\n\n" "$GRN" "$RST" \
    || { printf "\n  %s%d failure(s).%s Consider --rollback.\n\n" "$RED" "$fails" "$RST"; return 1; }
}

do_rollback(){
  need_root
  local only="${1:-}"
  step "rollback"
  if [ -n "$only" ]; then rollback_one "$only"; return; fi
  local svc
  for svc in "${ORDER[@]}"; do rollback_one "$svc" || true; done
  printf "\n  Rollback complete. Note: core_module/ files remain on disk (copy-then-delete);\n"
  printf "  only the installed units were reverted to the old alert_manager paths.\n\n"
}

case "${1:-}" in
  --preflight) do_preflight ;;
  --run)      shift; only=""; [ "${1:-}" = "--only" ] && only="${2:-}"; do_run "$only" ;;
  --verify)   do_verify ;;
  --rollback) shift; only=""; [ "${1:-}" = "--only" ] && only="${2:-}"; do_rollback "$only" ;;
  *) printf "usage: %s --preflight | --run [--only <svc>] | --verify | --rollback [--only <svc>]\n" "$0" >&2; exit 2 ;;
esac
