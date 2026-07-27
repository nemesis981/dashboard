#!/usr/bin/env bash
# Nemesis relocation: <install>/dashboard -> /opt/nemesis, DB -> /var/lib/nemesis
#
# UNTESTED until proven on a throwaway VM. Do not run on a live install.
#
# VM-agnostic: nothing about the source path, install user, or service list is
# hardcoded. Everything is derived or passed in, so the same script runs against
# a test VM and a real install.
#
# Usage:
#   sudo ./migrate_to_opt.sh --dry-run                 # show plan, change nothing
#   sudo ./migrate_to_opt.sh --preflight               # checks only, change nothing
#   sudo ./migrate_to_opt.sh --run                     # perform the migration
#   sudo ./migrate_to_opt.sh --verify                  # post-migration checks only
#   sudo ./migrate_to_opt.sh --rollback                # move everything back
#
#   --src PATH        source tree      (default: autodetected)
#   --user NAME       install user     (default: owner of the source tree)
#
# Behaviour on failure: STOP and report. This script never auto-remediates and
# never continues past a failed verification — a half-migrated tree that reports
# loudly is safer than one that keeps going and hides where it broke.

set -euo pipefail

NEW_ROOT="/opt/nemesis"
DATA_DIR="/var/lib/nemesis"
DB_NAME="alerts.db"
SERVICES=(dashboard watchdog hw-monitor alert-watcher device-scanner
          malware-canary diagnostics-watcher vpn-dns-guard)

MODE=""
SRC=""
INSTALL_USER=""
DB_GROUP="nemesis-db"

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLD=$'\e[1m'; NC=$'\e[0m'
step()  { printf "\n${BLD}==> %s${NC}\n" "$*"; }
ok()    { printf "  ${GRN}ok${NC}    %s\n" "$*"; }
warn()  { printf "  ${YEL}warn${NC}  %s\n" "$*"; }
die()   { printf "\n  ${RED}FAIL${NC}  %s\n\n  Stopping. Nothing further attempted.\n\n" "$*" >&2; exit 1; }
would() { printf "  ${YEL}dry${NC}   %s\n" "$*"; }

run() {   # execute, or narrate under --dry-run
    if [[ "$MODE" == "dry-run" ]]; then would "$*"; else "$@"; fi
}

# Integrity/inspection via python3, NOT the sqlite3 CLI. Nemesis is a Python
# application so python3 is guaranteed present; the sqlite3 CLI is not — it is
# absent on a stock Ubuntu 26.04 install (found on the test VM). Depending on it
# meant the single most important pre-move safety check silently degraded to
# nothing on exactly the machines least likely to have it.
db_integrity() {
    python3 - "$1" 2>&1 <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1]); print(c.execute("PRAGMA integrity_check").fetchone()[0]); c.close()
except Exception as exc:
    print("ERROR: %s" % exc)
PY
}

db_table_count() {
    python3 - "$1" 2>/dev/null <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1])
    print(c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]); c.close()
except Exception:
    print(0)
PY
}

# ── argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   MODE="dry-run" ;;
        --preflight) MODE="preflight" ;;
        --run)       MODE="run" ;;
        --verify)    MODE="verify" ;;
        --rollback)  MODE="rollback" ;;
        --src)       SRC="${2:-}"; shift ;;
        --user)      INSTALL_USER="${2:-}"; shift ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
[[ -n "$MODE" ]] || die "no mode given (--dry-run / --preflight / --run / --verify / --rollback)"
[[ $EUID -eq 0 ]] || die "must run as root (sudo)"

# ── autodetection (keeps the script VM-agnostic) ─────────────────────────────
detect_src() {
    [[ -n "$SRC" ]] && { echo "$SRC"; return; }
    local c
    for c in /opt/nemesis /home/*/dashboard /root/dashboard; do
        [[ -f "$c/dashboard.py" ]] && { echo "$c"; return; }
    done
    return 1
}

# Standalone --verify must NOT re-derive SRC with detect_src(). That helper
# searches /opt/nemesis FIRST, so after a successful migration it returns the NEW
# tree; do_verify would then assert "the old tree is gone" against the new tree,
# which obviously still has dashboard.py, and false-FAIL every time.
#
# The --run path never hit this because it captures SRC once in preflight and
# reuses it — which is also why the VM cycle missed it: the verification exercised
# there was the one chained inside --run, never a separate invocation.
#
# The stamp written at migration time already holds the true pre-migration path,
# so read state rather than guessing. Precedence: explicit --src, then the stamp,
# then the heuristic (no stamp => not migrated, or rollback removed it).
resolve_verify_src() {
    [[ -n "$SRC" ]] && { ok "using --src: $SRC"; return; }
    local stamp="$NEW_ROOT/.nemesis-premigration-mode"
    if [[ -f "$stamp" ]]; then
        SRC="$(sed -n 2p "$stamp")"
        ok "pre-migration path read from stamp: $SRC"
        return
    fi
    SRC="$(detect_src || true)"
    warn "no stamp at $stamp — falling back to autodetection ($SRC)"
}


# ── preflight ────────────────────────────────────────────────────────────────
preflight() {
    step "Preflight"

    SRC="$(detect_src)" || die "could not locate the install tree (pass --src)"
    ok "source tree: $SRC"
    [[ -f "$SRC/dashboard.py" ]] || die "$SRC does not look like a Nemesis install"

    if [[ "$SRC" == "$NEW_ROOT" ]]; then
        warn "source is already $NEW_ROOT — code relocation appears done"
    fi

    [[ -n "$INSTALL_USER" ]] || INSTALL_USER="$(stat -c '%U' "$SRC")"
    id "$INSTALL_USER" &>/dev/null || die "install user $INSTALL_USER does not exist"
    ok "install user: $INSTALL_USER"

    getent group "$DB_GROUP" >/dev/null || die "group $DB_GROUP missing — run the de-privileging user/group creation first"
    ok "group $DB_GROUP present"

    local db="$SRC/alert_manager/$DB_NAME"
    if [[ -f "$db" ]]; then
        local integ; integ="$(db_integrity "$db")"
        [[ "$integ" == "ok" ]] || die "DB integrity_check failed before migration: $integ"
        ok "DB integrity_check: ok (python3)"
    elif [[ -f "$DATA_DIR/$DB_NAME" ]]; then
        warn "DB already at $DATA_DIR/$DB_NAME — data move appears done"
    else
        die "no database found at $db or $DATA_DIR/$DB_NAME"
    fi

    # Uncommitted work would be destroyed by a bad move; refuse to proceed.
    if [[ -d "$SRC/.git" ]]; then
        local dirty
        dirty="$(git -C "$SRC" status --porcelain 2>/dev/null | wc -l)"
        if [[ "$dirty" -ne 0 ]]; then
            die "$dirty uncommitted change(s) in $SRC — commit or stash before migrating"
        fi
        ok "git tree clean ($(git -C "$SRC" rev-parse --short HEAD))"
    else
        warn "$SRC is not a git repo — no clean-tree guarantee"
    fi

    [[ -d "$NEW_ROOT" && "$SRC" != "$NEW_ROOT" ]] && die "$NEW_ROOT already exists; refusing to overwrite"
    ok "target $NEW_ROOT is free"

    df -Pk /opt | awk 'NR==2{print $4}' | {
        read -r avail
        local need; need="$(du -sk "$SRC" | cut -f1)"
        (( avail > need * 2 )) || die "insufficient space on /opt (need ~${need}K, have ${avail}K)"
        ok "space on /opt sufficient (${avail}K free, tree ${need}K)"
    }
}

# ── migration ────────────────────────────────────────────────────────────────
do_migrate() {
    step "Stopping services"
    local s
    for s in "${SERVICES[@]}"; do
        if systemctl list-unit-files "$s.service" &>/dev/null && systemctl is-enabled "$s" &>/dev/null; then
            run systemctl stop "$s" && ok "stopped $s" || warn "could not stop $s (may not be installed)"
        fi
    done

    step "Moving code tree"
    # Record the pre-migration mode so --rollback can restore it byte-exactly.
    # Without this, rollback returned the tree as 0755 when it had been 0775 —
    # functional for the owner, but not a faithful restore (found on the VM).
    local orig_mode; orig_mode="$(stat -c '%a' "$SRC")"
    # mv preserves ownership, modes, and .git — this is the git-preserving move.
    run mv "$SRC" "$NEW_ROOT"
    if [[ "$MODE" != "dry-run" ]]; then
        printf '%s\n' "$orig_mode" > "$NEW_ROOT/.nemesis-premigration-mode"
        printf '%s\n' "$SRC"       >> "$NEW_ROOT/.nemesis-premigration-mode"
    fi
    run chmod 0755 "$NEW_ROOT"
    ok "$SRC -> $NEW_ROOT (original mode $orig_mode recorded for rollback)"

    step "Moving database"
    run mkdir -p "$DATA_DIR"
    # Where the DB files live RIGHT NOW. After a real mv they are under
    # $NEW_ROOT; under --dry-run the tree has not actually moved, so they are
    # still under $SRC. Probing the wrong one silently skipped every mv and made
    # dry-run omit the most data-sensitive step entirely (caught in testing).
    local db_dir="$NEW_ROOT/alert_manager"
    [[ "$MODE" == "dry-run" ]] && db_dir="$SRC/alert_manager"

    # The main DB must be found. A silent skip here would "succeed" while
    # leaving the database behind in the old tree.
    [[ -f "$db_dir/$DB_NAME" ]] || die "database not found at $db_dir/$DB_NAME after the tree move — refusing to continue"

    local f
    for f in "$DB_NAME" "$DB_NAME-wal" "$DB_NAME-shm"; do
        if [[ -f "$db_dir/$f" ]]; then
            run mv "$db_dir/$f" "$DATA_DIR/$f"
            run chown "$INSTALL_USER" "$DATA_DIR/$f"
            run chgrp "$DB_GROUP" "$DATA_DIR/$f"
            run chmod 0660 "$DATA_DIR/$f"
            ok "moved $f"
        else
            [[ "$f" == "$DB_NAME" ]] || ok "no $f (nothing to move)"
        fi
    done
    run chown "$INSTALL_USER" "$DATA_DIR"
    run chgrp "$DB_GROUP" "$DATA_DIR"
    # 0770, NOT 0750. SQLite in WAL mode creates alerts.db-wal and alerts.db-shm
    # *in this directory*, so the service group needs WRITE on the directory, not
    # just traverse. With 0750 every service opens the DB read-only and the first
    # write raises "attempt to write a readonly database" — the same failure that
    # caused the 2026-07-18 fd-exhaustion incident. Caught on the test VM.
    run chmod 0770 "$DATA_DIR"
    ok "$DATA_DIR ready"

    step "Reloading systemd"
    run systemctl daemon-reload
    ok "daemon-reload"

    step "Starting services"
    for s in "${SERVICES[@]}"; do
        if systemctl list-unit-files "$s.service" &>/dev/null; then
            run systemctl start "$s" || warn "$s did not start"
        fi
    done
}

# ── verification ─────────────────────────────────────────────────────────────
do_verify() {
    step "Verification"
    local fail=0

    [[ -f "$NEW_ROOT/dashboard.py" ]] && ok "code at $NEW_ROOT" || { printf "  FAIL code not at %s\n" "$NEW_ROOT"; fail=1; }
    [[ -d "$NEW_ROOT/.git" ]]        && ok "git history preserved" || { printf "  FAIL .git missing\n"; fail=1; }
    [[ -f "$DATA_DIR/$DB_NAME" ]]    && ok "DB at $DATA_DIR" || { printf "  FAIL DB not at %s\n" "$DATA_DIR"; fail=1; }
    if [[ "$SRC" == "$NEW_ROOT" ]]; then
        # Would compare the new tree against itself — the exact false-fail this
        # resolver order exists to prevent. Say so plainly instead of "FAIL".
        printf "  FAIL SRC resolved to %s, the migration TARGET — cannot check whether the old path is gone\n" "$SRC"
        fail=1
    elif [[ -e "$SRC/dashboard.py" ]]; then
        printf "  FAIL old tree still present at %s\n" "$SRC"; fail=1
    else
        ok "old path gone ($SRC)"
    fi

    if [[ -f "$DATA_DIR/$DB_NAME" ]]; then
        local integ; integ="$(db_integrity "$DATA_DIR/$DB_NAME")"
        [[ "$integ" == "ok" ]] && ok "DB integrity_check: ok" || { printf "  FAIL integrity: %s\n" "$integ"; fail=1; }
        ok "tables present: $(db_table_count "$DATA_DIR/$DB_NAME")"
    fi

    printf "  perms: %s\n" "$(stat -c '%n %U:%G %a' "$DATA_DIR/$DB_NAME" 2>/dev/null || echo 'DB missing')"

    step "Service state"
    local s
    for s in "${SERVICES[@]}"; do
        if systemctl list-unit-files "$s.service" &>/dev/null; then
            local st; st="$(systemctl is-active "$s" 2>/dev/null || true)"
            printf "  %-22s %s\n" "$s" "$st"
            [[ "$st" == "active" ]] || fail=1
        fi
    done

    step "Residual path references"
    # Exclude the stamp: it records the pre-migration path BY DESIGN, so matching
    # it is a self-inflicted false positive, not a stale reference to fix.
    if grep -rIl --exclude-dir=.git --exclude=".nemesis-premigration-mode" \
            "$SRC" "$NEW_ROOT" /etc/systemd/system 2>/dev/null | head -5; then
        warn "files above still reference the old path"
    else
        ok "no residual references to $SRC"
    fi

    (( fail == 0 )) || die "verification failed — see FAIL lines above"
    printf "\n  ${GRN}migration verified${NC}\n\n"
}

# ── rollback ─────────────────────────────────────────────────────────────────
do_rollback() {
    step "Rollback"
    local stamp="$NEW_ROOT/.nemesis-premigration-mode" orig_mode=""
    if [[ -f "$stamp" ]]; then
        orig_mode="$(sed -n 1p "$stamp")"
        [[ -n "$SRC" ]] || SRC="$(sed -n 2p "$stamp")"
        ok "recovered pre-migration state from stamp (mode $orig_mode, path $SRC)"
    fi
    [[ -n "$SRC" ]] || die "--src required for rollback (no stamp file found)"
    local s f
    for s in "${SERVICES[@]}"; do systemctl stop "$s" 2>/dev/null || true; done
    for f in "$DB_NAME" "$DB_NAME-wal" "$DB_NAME-shm"; do
        [[ -f "$DATA_DIR/$f" ]] && run mv "$DATA_DIR/$f" "$NEW_ROOT/alert_manager/$f"
    done
    run rm -f "$stamp"
    run mv "$NEW_ROOT" "$SRC"
    [[ -n "$orig_mode" ]] && run chmod "$orig_mode" "$SRC"
    run systemctl daemon-reload
    for s in "${SERVICES[@]}"; do systemctl start "$s" 2>/dev/null || true; done
    ok "rolled back to $SRC${orig_mode:+ (mode $orig_mode restored)}"

    # Units are NOT reverted by this script — it moves code and data, while the
    # units are deployed by install.sh. After a rollback they still point at
    # $NEW_ROOT, which no longer exists, so every service will fail to start.
    # Verified on the test VM. Say so loudly rather than let it be discovered.
    local stale=0 u
    for u in "${SERVICES[@]}"; do
        if grep -qs "$NEW_ROOT" "/etc/systemd/system/${u}.service" 2>/dev/null; then
            stale=$((stale + 1))
        fi
    done
    if (( stale > 0 )); then
        printf "\n  ${YEL}ACTION REQUIRED${NC}  %d unit file(s) still reference %s, which no\n" "$stale" "$NEW_ROOT"
        printf "                   longer exists. Services will fail until the units are\n"
        printf "                   restored to their pre-migration versions.\n\n"

        # Point at a backup that ACTUALLY EXISTS. install.sh copies the previous
        # units into a dated directory before overwriting them; use the newest.
        # An earlier version of this warning named a snapshot path that nothing
        # ever created — actionable-looking guidance that would have failed at
        # the worst possible moment. If no backup is present, say so and give
        # the git route instead of inventing a path.
        local backup
        # `|| true` is load-bearing: this script runs under `set -euo pipefail`,
        # and when the glob matches nothing `ls` exits non-zero, which pipefail
        # propagates and set -e turns into an abort — killing the script partway
        # through printing this very warning. Caught on the VM.
        backup="$(ls -1d /var/backups/nemesis/units-* 2>/dev/null | sort | tail -1 || true)"
        if [[ -n "$backup" && -n "$(ls -1 "$backup"/*.service 2>/dev/null)" ]]; then
            printf "                   Restore from the backup install.sh made:\n\n"
            printf "                     sudo cp %s/*.service /etc/systemd/system/\n" "$backup"
            printf "                     sudo systemctl daemon-reload\n"
            printf "                     sudo systemctl restart %s\n\n" "${SERVICES[*]}"
        else
            printf "                   ${RED}No unit backup found under /var/backups/nemesis/.${NC}\n"
            printf "                   Reconstruct them from git — the pre-relocation units are\n"
            printf "                   the versions before the /opt migration landed:\n\n"
            printf "                     cd %s\n" "$SRC"
            printf "                     git log --oneline -- alert_manager/dashboard.service\n"
            printf "                     git show <commit-before-migration>:alert_manager/<unit>.service\n"
            printf "                   Write each to /etc/systemd/system/, substituting the install\n"
            printf "                   user for __INSTALL_USER__ if present, then daemon-reload.\n\n"
        fi
        printf "                   Code and data rollback itself completed successfully.\n\n"
    fi
}

# ── dispatch ─────────────────────────────────────────────────────────────────
case "$MODE" in
    preflight) preflight ;;
    dry-run)   preflight; do_migrate ;;
    run)       preflight; do_migrate; SRC="$SRC" do_verify ;;
    verify)    resolve_verify_src; do_verify ;;
    rollback)  do_rollback ;;
esac
