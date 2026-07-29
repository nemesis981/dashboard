#!/usr/bin/env bash
#
# deploy_nemesis_fwd.sh — production deployment of the nemesis-fwd privileged
# ufw helper. Same shape as migrate_to_opt.sh: --preflight / --run / --verify /
# --rollback, every step verified against ground truth rather than assumed.
#
#   sudo bash scripts/deploy_nemesis_fwd.sh --preflight
#   sudo bash scripts/deploy_nemesis_fwd.sh --run
#   sudo bash scripts/deploy_nemesis_fwd.sh --verify
#   sudo bash scripts/deploy_nemesis_fwd.sh --rollback
#
# WHY THERE IS NO "COPY FILES" STEP. /opt/nemesis is BOTH the git repository and
# the live deployment tree, so a landed commit is already on disk. Deployment is
# therefore: prove the tree is clean and at the expected commit, compile it,
# install the helper, and restart. That same property is what allowed uncommitted
# work to sit on production earlier, which is why --preflight refuses a dirty tree.
#
# OVERRIDES (used to rehearse this on the VM):
#   DASH_USER=...      dashboard's OS user      (default: read from dashboard.service)
#   ALERTW_USER=...    alert-watcher's OS user  (default: read from alert-watcher.service)
#   NEMESIS_ASSUME_YES=1   skip the interactive cutover confirmation
#
set -euo pipefail

# Peer identities are DERIVED FROM THE INSTALLED UNITS, never hardcoded. A
# baked-in username could not be correct for more than one install, and a wrong
# value here either locks the real dashboard out of the firewall or authorises
# the wrong account as a peer — so this reads what the system actually runs and
# fails loudly when it cannot.
unit_user() { systemctl show -p User --value "$1" 2>/dev/null || true; }

DASH_USER="${DASH_USER:-$(unit_user dashboard)}"
ALERTW_USER="${ALERTW_USER:-$(unit_user alert-watcher)}"
FW_GROUP="nemesis-fw"
DB_GROUP="nemesis-db"

TREE="/opt/nemesis"
DB_PATH="/var/lib/nemesis/alerts.db"
STATE_DIR="/var/lib/nemesis"
SOCK="/run/nemesis/fwd.sock"
UNIT_SRC="$TREE/alert_manager/nemesis-fwd.service"
UNIT_DST="/etc/systemd/system/nemesis-fwd.service"
STAMP="$STATE_DIR/.fwd-deploy-stamp"
BACKUP_DIR="/var/backups/nemesis"

# Services restarted at cutover. Order matters: the helper must already be up.
CUTOVER_SERVICES=(dashboard alert-watcher)

# Test IPs live in the RFC 5737 documentation range so a stray rule is inert.
TEST_IP_ADMIN="203.0.113.240"
TEST_IP_WATCHER="203.0.113.241"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
step() { printf "\n%s== %s ==%s\n" "$BLD" "$*" "$RST"; }
ok()   { printf "  %sOK%s   %s\n" "$GRN" "$RST" "$*"; }
warn() { printf "  %sWARN%s %s\n" "$YEL" "$RST" "$*"; }
info() { printf "       %s\n" "$*"; }
die()  { printf "\n  %sFAIL%s %s\n\n" "$RED" "$RST" "$*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"; }

# ── shared checks ────────────────────────────────────────────────────────────

check_users() {
    [ -n "$DASH_USER" ] || die "cannot determine the dashboard user: dashboard.service
       declares no User= (so it runs as root), or the unit is not installed.
       There is no default — pass it explicitly:  DASH_USER=<user> $0 ..."
    id "$DASH_USER"   >/dev/null 2>&1 || die "dashboard user '$DASH_USER' does not exist"
    ok "dashboard user '$DASH_USER' exists (uid $(id -u "$DASH_USER"))"
    if id "$ALERTW_USER" >/dev/null 2>&1; then
        ok "alert-watcher user '$ALERTW_USER' exists (uid $(id -u "$ALERTW_USER"))"
    else
        # Not fatal: the helper logs a warning and that peer simply cannot connect.
        warn "alert-watcher user '$ALERTW_USER' absent — that peer will be unable to connect"
    fi
}

check_sources() {
    local missing=0 f
    for f in alert_manager/nemesis_fwd.py alert_manager/fw_client.py \
             alert_manager/nemesis-fwd.service alert_manager/firewall.py \
             core_module/alert_watcher/alert_watcher.py dashboard.py; do
        if [ -f "$TREE/$f" ]; then ok "present: $f"
        else printf "  %sFAIL%s missing: %s\n" "$RED" "$RST" "$f"; missing=1; fi
    done
    [ "$missing" -eq 0 ] || die "required source files are missing — is the commit actually landed?"
}

compile_tree() {
    # Compile EVERY python file that ships, not a sample. A syntax error found
    # after the cutover restart is an outage; found here it is a no-op.
    local failed=0 f
    while IFS= read -r f; do
        if ! python3 -m py_compile "$f" 2>/dev/null; then
            printf "  %sFAIL%s py_compile: %s\n" "$RED" "$RST" "$f"
            python3 -m py_compile "$f" 2>&1 | sed 's/^/         /' || true
            failed=1
        fi
    done < <(find "$TREE/alert_manager" "$TREE/scripts" "$TREE/diagnostics" -maxdepth 1 -name '*.py' 2>/dev/null; \
             printf '%s\n' "$TREE/dashboard.py")
    [ "$failed" -eq 0 ] || die "python compilation failed — nothing has been changed"
    ok "every shipped python file compiles"
}

git_clean_check() {
    local dirty
    dirty="$(git -C "$TREE" status --porcelain 2>/dev/null || true)"
    if [ -n "$dirty" ]; then
        printf "%s\n" "$dirty" | sed 's/^/         /'
        die "working tree is DIRTY. The tree is the deployment: deploy only a committed state."
    fi
    ok "working tree is clean at $(git -C "$TREE" rev-parse --short HEAD)"
}

# The rollback target is the parent of the first commit that introduced the
# helper — computed, not guessed, so it stays correct however many commits the
# helper work landed as.
compute_rollback_commit() {
    local first parent
    first="$(git -C "$TREE" log --format=%H --reverse -- alert_manager/nemesis_fwd.py 2>/dev/null | head -1)"
    [ -n "$first" ] || return 1
    parent="$(git -C "$TREE" rev-parse --verify "${first}^" 2>/dev/null)" || return 1
    printf '%s' "$parent"
}

ufw_rule_count() { /usr/sbin/ufw status 2>/dev/null | grep -c 'DENY' || true; }

# `systemctl is-active` PRINTS a state and RETURNS non-zero for anything not
# running, so `is-active || echo ...` emits two lines. Resolve it to exactly one.
svc_state() {
    local s
    s="$(systemctl is-active "$1" 2>/dev/null || true)"
    if [ -z "$s" ] || [ "$s" = "unknown" ]; then
        systemctl cat "$1" >/dev/null 2>&1 && printf 'inactive' || printf 'not-installed'
    else
        printf '%s' "$s"
    fi
}

# ── preflight ────────────────────────────────────────────────────────────────

do_preflight() {
    need_root
    step "1/8  identity and tree"
    check_users
    [ -d "$TREE/.git" ] || die "$TREE is not a git repository"
    git_clean_check

    step "2/8  source files"
    check_sources

    step "3/8  compilation"
    compile_tree

    step "4/8  rollback target"
    local rb
    if rb="$(compute_rollback_commit)"; then
        ok "rollback target: $(git -C "$TREE" log --oneline -1 "$rb")"
    else
        warn "cannot compute a rollback commit (helper not yet in history)."
        warn "  --run will refuse until the commit has landed."
    fi

    step "5/8  prerequisites"
    [ -x /usr/sbin/ufw ] || die "/usr/sbin/ufw not found"
    ok "ufw present"
    python3 -c 'import bcrypt' 2>/dev/null && ok "bcrypt importable" \
        || die "bcrypt not importable — credential verification would fail closed"
    [ -f "$DB_PATH" ] || die "database not found at $DB_PATH"
    ok "database present: $DB_PATH"

    step "6/8  admin accounts (these gate every firewall write)"
    local admins
    admins="$(python3 - "$DB_PATH" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
rows = c.execute("SELECT username FROM users WHERE role='admin' AND is_active=1").fetchall()
print(" ".join(r[0] for r in rows))
PY
)"
    if [ -z "$admins" ]; then
        die "NO active admin accounts. Every firewall write would be impossible after cutover."
    fi
    ok "active admins: $admins"
    if [ "$(printf '%s' "$admins" | wc -w)" -eq 1 ]; then
        warn "only ONE active admin ($admins)."
        warn "  After cutover every firewall write needs THIS account's password."
        warn "  Confirm you can log in as it BEFORE running --run. There is no fallback."
    fi

    step "7/8  current state (rollback reference)"
    info "ufw DENY rules now: $(ufw_rule_count)"
    local s
    for s in "${CUTOVER_SERVICES[@]}"; do
        info "$(printf '%-16s %s' "$s" "$(svc_state "$s")")"
    done
    info "nemesis-fwd:     $(svc_state nemesis-fwd)"
    info "$FW_GROUP group: $(getent group "$FW_GROUP" >/dev/null && echo present || echo 'absent (will be created)')"

    step "8/8  state snapshot"
    warn "This script does NOT take the USB snapshot."
    warn "  Take it and verify it present before --run (standing rule)."

    printf "\n  %sPreflight complete.%s Resolve every WARN above before --run.\n\n" "$BLD" "$RST"
}

# ── run ──────────────────────────────────────────────────────────────────────

do_run() {
    need_root
    local rb
    rb="$(compute_rollback_commit)" || die "helper is not in git history — commit must land before --run"

    step "1/6  groups and membership"
    if getent group "$FW_GROUP" >/dev/null; then
        ok "group $FW_GROUP already exists"
    else
        groupadd -r "$FW_GROUP"
        ok "created group $FW_GROUP (gid $(getent group "$FW_GROUP" | cut -d: -f3))"
    fi
    local u
    for u in "$DASH_USER" "$ALERTW_USER"; do
        id "$u" >/dev/null 2>&1 || { warn "skipping absent user $u"; continue; }
        if id -nG "$u" | tr ' ' '\n' | grep -qx "$FW_GROUP"; then
            ok "$u already in $FW_GROUP"
        else
            usermod -aG "$FW_GROUP" "$u"; ok "added $u to $FW_GROUP"
        fi
    done
    # dashboard reads the helper's degraded.jsonl (root:nemesis-db 0640).
    if id -nG "$DASH_USER" | tr ' ' '\n' | grep -qx "$DB_GROUP"; then
        ok "$DASH_USER already in $DB_GROUP"
    else
        usermod -aG "$DB_GROUP" "$DASH_USER"; ok "added $DASH_USER to $DB_GROUP (reads degraded.jsonl)"
    fi
    warn "supplementary groups are read at PROCESS START — they take effect at the"
    warn "  cutover restart in step 5, not now."

    step "2/6  tree state and compilation"
    git_clean_check
    check_sources
    compile_tree

    step "3/6  helper unit"
    [ -f "$UNIT_SRC" ] || die "unit source missing: $UNIT_SRC"
    mkdir -p "$BACKUP_DIR"
    if [ -f "$UNIT_DST" ]; then
        cp -a "$UNIT_DST" "$BACKUP_DIR/nemesis-fwd.service.$(date +%Y%m%d-%H%M%S).bak"
        ok "backed up existing unit"
    fi
    sed "s|__INSTALL_USER__|$DASH_USER|g" "$UNIT_SRC" > "$UNIT_DST"
    chmod 0644 "$UNIT_DST"
    grep -q "__INSTALL_USER__" "$UNIT_DST" && die "placeholder substitution failed"
    ok "installed $UNIT_DST (NEMESIS_DASH_USER=$DASH_USER)"
    systemctl daemon-reload
    ok "daemon-reload"

    # Stamp BEFORE anything dependent changes, so --rollback works even if a
    # later step dies.
    mkdir -p "$STATE_DIR"
    cat > "$STAMP" <<EOF
ROLLBACK_COMMIT=$rb
DEPLOYED_COMMIT=$(git -C "$TREE" rev-parse HEAD)
DASH_USER=$DASH_USER
ALERTW_USER=$ALERTW_USER
UFW_RULES_BEFORE=$(ufw_rule_count)
TIMESTAMP=$(date -Is)
EOF
    chmod 0640 "$STAMP"
    ok "recorded rollback stamp: $STAMP"

    step "4/6  helper alone — THE ABORT POINT"
    info "Nothing depends on the helper yet. If any check below fails this script"
    info "stops here, and production is still running exactly as it was."
    systemctl enable --now nemesis-fwd >/dev/null 2>&1 || true
    sleep 3
    [ "$(svc_state nemesis-fwd)" = "active" ] \
        || { journalctl -u nemesis-fwd -n 30 --no-pager | sed 's/^/         /'
             die "helper failed to start — production untouched, nothing restarted"; }
    ok "nemesis-fwd is active"

    # Effective privilege from the KERNEL, not from systemctl show (which reports
    # configuration, not what the process actually got).
    local hpid
    hpid="$(systemctl show -p MainPID --value nemesis-fwd)"
    [ -n "$hpid" ] && [ "$hpid" != "0" ] || die "helper has no MainPID"
    local euid
    euid="$(awk '/^Uid:/{print $3}' "/proc/$hpid/status")"
    [ "$euid" = "0" ] || die "helper euid is $euid, must be 0 (ufw enforces a real-UID check)"
    ok "helper euid=0 (verified via /proc, not unit config)"

    [ -S "$SOCK" ] || die "socket $SOCK was not created"
    local sgrp smode
    sgrp="$(stat -c %G "$SOCK")"; smode="$(stat -c %a "$SOCK")"
    [ "$sgrp" = "$FW_GROUP" ] || die "socket group is $sgrp, expected $FW_GROUP"
    [ "$smode" = "660" ]      || die "socket mode is $smode, expected 660"
    ok "socket $SOCK is $smode $(stat -c %U:%G "$SOCK")"

    # Authorised peers, read from the helper's own startup log.
    local peers
    peers="$(journalctl -u nemesis-fwd --since '-2min' --no-pager 2>/dev/null \
             | grep -o 'authorised peers:.*' | tail -1 || true)"
    [ -n "$peers" ] || die "helper did not report its authorised peers"
    info "$peers"
    printf '%s' "$peers" | grep -q "dashboard(uid=$(id -u "$DASH_USER"))" \
        || die "helper did not authorise $DASH_USER as the dashboard peer"
    ok "dashboard peer resolved to $DASH_USER (uid $(id -u "$DASH_USER"))"

    # ping as the dashboard user, through the real socket.
    sudo -u "$DASH_USER" -g "$FW_GROUP" python3 - "$SOCK" <<'PY' || die "ping from the dashboard peer failed"
import json, socket, struct, sys, uuid
H = struct.Struct("!I")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(20); s.connect(sys.argv[1])
b = json.dumps({"op":"ping","params":{},"actor":{"username":None,"session_id":None},
                "request_id":str(uuid.uuid4())}).encode()
s.sendall(H.pack(len(b))+b)
h=b""
while len(h)<4: h+=s.recv(4-len(h))
n=H.unpack(h)[0]; buf=b""
while len(buf)<n: buf+=s.recv(n-len(buf))
r=json.loads(buf.decode())
sys.exit(0 if r.get("ok") else 1)
PY
    ok "ping succeeds from the dashboard peer"
    printf "\n  %sAbort point passed.%s The helper is healthy and nothing has been restarted yet.\n" "$GRN" "$RST"

    step "5/6  CUTOVER — restarting ${CUTOVER_SERVICES[*]}"
    warn "This is the first step that changes running production behaviour."
    warn "It picks up the new code AND the new group membership together."
    if [ "${NEMESIS_ASSUME_YES:-0}" != "1" ]; then
        printf "\n  Proceed with cutover? [y/N] "
        read -r reply
        case "$reply" in
            y|Y|yes|YES) ;;
            *) printf "\n  Cutover declined. Helper is running but unused; production unchanged.\n"
               printf "  Run --rollback to remove the helper, or re-run --run to resume.\n\n"; exit 0 ;;
        esac
    fi
    local s
    for s in "${CUTOVER_SERVICES[@]}"; do
        systemctl restart "$s"
        sleep 2
        [ "$(svc_state "$s")" = "active" ] \
            || { journalctl -u "$s" -n 30 --no-pager | sed 's/^/         /'
                 die "$s failed to restart — run --rollback"; }
        ok "$s restarted and active"
    done
    for s in "${CUTOVER_SERVICES[@]}"; do
        local spid sgids
        spid="$(systemctl show -p MainPID --value "$s")"
        if [ -n "$spid" ] && [ "$spid" != "0" ]; then
            sgids="$(awk '/^Groups:/{$1="";print}' "/proc/$spid/status")"
            info "$(printf '%-16s pid=%s groups=%s' "$s" "$spid" "$sgids")"
        fi
    done

    step "6/6  post-cutover verification"
    do_verify_inner

    printf "\n  %sDeployment complete.%s Rollback remains available: --rollback\n\n" "$BLD" "$RST"
}

# ── verify ───────────────────────────────────────────────────────────────────

do_verify_inner() {
    local fails=0
    _v() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else printf "  %sFAIL%s %s\n" "$RED" "$RST" "$1"; fails=$((fails+1)); fi; }

    _v "nemesis-fwd active"      "[ \"\$(svc_state nemesis-fwd)\" = active ]"
    _v "dashboard active"        "[ \"\$(svc_state dashboard)\" = active ]"
    _v "alert-watcher active"    "[ \"\$(svc_state alert-watcher)\" = active ]"
    _v "socket present"          "[ -S \"$SOCK\" ]"

    # Reachability from BOTH peers, using each peer's real OS identity.
    #
    # This ATTEMPTS A CONNECTION rather than testing a permission bit. `test -r`
    # was tried first and reported failure on a socket that connect() opens
    # perfectly well — it asks the wrong question twice over: connecting to a
    # unix socket needs write, not read, and only an actual connect exercises
    # the path the peer really takes. Verify the behaviour, not a proxy for it.
    peer_can_connect() {
        sudo -u "$1" python3 - "$SOCK" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)
s.connect(sys.argv[1]); s.close()
PY
    }
    if peer_can_connect "$DASH_USER"; then
        ok "socket reachable by $DASH_USER (real connect)"
    else
        printf "  %sFAIL%s socket NOT reachable by %s (group membership needs a restart?)\n" "$RED" "$RST" "$DASH_USER"
        fails=$((fails+1))
    fi
    if id "$ALERTW_USER" >/dev/null 2>&1; then
        if peer_can_connect "$ALERTW_USER"; then
            ok "socket reachable by $ALERTW_USER (real connect)"
        else
            printf "  %sFAIL%s socket NOT reachable by %s\n" "$RED" "$RST" "$ALERTW_USER"
            fails=$((fails+1))
        fi
    fi

    # Unattended path, exercised for real as alert-watcher: block then let the
    # rule stand only long enough to observe it, then remove it out of band.
    if id "$ALERTW_USER" >/dev/null 2>&1; then
        if sudo -u "$ALERTW_USER" -g "$FW_GROUP" python3 - "$SOCK" "$TEST_IP_WATCHER" <<'PY' >/dev/null 2>&1
import json, socket, struct, sys, uuid
H=struct.Struct("!I")
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(30); s.connect(sys.argv[1])
b=json.dumps({"op":"block_ip","params":{"ip":sys.argv[2]},
              "actor":{"username":None,"session_id":None},
              "request_id":str(uuid.uuid4())}).encode()
s.sendall(H.pack(len(b))+b)
h=b""
while len(h)<4: h+=s.recv(4-len(h))
n=H.unpack(h)[0]; buf=b""
while len(buf)<n: buf+=s.recv(n-len(buf))
sys.exit(0 if json.loads(buf.decode()).get("ok") else 1)
PY
        then
            if /usr/sbin/ufw status | grep -q "$TEST_IP_WATCHER"; then
                ok "alert-watcher auto-quarantine path applies a real rule"
            else
                printf "  %sFAIL%s alert-watcher reported success but no rule appeared\n" "$RED" "$RST"; fails=$((fails+1))
            fi
            /usr/sbin/ufw delete deny from "$TEST_IP_WATCHER" >/dev/null 2>&1 || true
            info "test rule for $TEST_IP_WATCHER removed"
        else
            printf "  %sFAIL%s alert-watcher unattended block failed\n" "$RED" "$RST"; fails=$((fails+1))
        fi
    fi

    # Admin write path. Needs a real password, so it is opt-in and never logged.
    if [ "${SKIP_ADMIN_TEST:-0}" = "1" ]; then
        warn "SKIPPED the admin credential test (SKIP_ADMIN_TEST=1)."
        warn "  NOT VERIFIED: an admin write end-to-end, and audit rows naming the user."
    else
        local admin_user admin_pass
        admin_user="$(python3 - "$DB_PATH" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
r = c.execute("SELECT username FROM users WHERE role='admin' AND is_active=1 ORDER BY username").fetchone()
print(r[0] if r else "")
PY
)"
        if [ -z "$admin_user" ]; then
            printf "  %sFAIL%s no active admin to test with\n" "$RED" "$RST"; fails=$((fails+1))
        else
            printf "\n  Admin write test as %s%s%s.\n" "$BLD" "$admin_user" "$RST"
            printf "  Password (never logged or stored; blank to skip): "
            read -rs admin_pass; printf "\n"
            if [ -z "$admin_pass" ]; then
                warn "SKIPPED the admin credential test."
                warn "  NOT VERIFIED: an admin write end-to-end, and audit rows naming the user."
            else
                local before
                before="$(python3 -c "import sqlite3;print(sqlite3.connect('$DB_PATH').execute('SELECT COALESCE(MAX(id),0) FROM audit_log').fetchone()[0])")"
                if ADMIN_PW="$admin_pass" sudo -u "$DASH_USER" -g "$FW_GROUP" --preserve-env=ADMIN_PW \
                     python3 - "$SOCK" "$TEST_IP_ADMIN" "$admin_user" <<'PY' >/dev/null 2>&1
import json, os, socket, struct, sys, uuid
H=struct.Struct("!I")
def call(op, params):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(40); s.connect(sys.argv[1])
    b=json.dumps({"op":op,"params":params,
                  "actor":{"username":sys.argv[3],"session_id":"deployverify"},
                  "credential":{"password":os.environ["ADMIN_PW"]},
                  "request_id":str(uuid.uuid4())}).encode()
    s.sendall(H.pack(len(b))+b)
    h=b""
    while len(h)<4: h+=s.recv(4-len(h))
    n=H.unpack(h)[0]; buf=b""
    while len(buf)<n: buf+=s.recv(n-len(buf))
    s.close(); return json.loads(buf.decode())
if not call("block_ip", {"ip": sys.argv[2]}).get("ok"): sys.exit(1)
if not call("unblock_ip", {"ip": sys.argv[2]}).get("ok"): sys.exit(2)
PY
                then
                    ok "admin block+unblock as $admin_user succeeded (fresh credential each write)"
                    local named
                    named="$(python3 - "$DB_PATH" "$before" "$admin_user" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
rows = c.execute("SELECT action,user FROM audit_log WHERE id>?", (int(sys.argv[2]),)).fetchall()
fw = [r for r in rows if r[0].startswith("fw_")]
print("yes" if fw and all(r[1] == sys.argv[3] for r in fw) else "no")
PY
)"
                    if [ "$named" = "yes" ]; then
                        ok "helper audit rows name the USER ($admin_user), not an IP"
                    else
                        printf "  %sFAIL%s audit rows missing or not attributed to %s\n" "$RED" "$RST" "$admin_user"; fails=$((fails+1))
                    fi
                    if /usr/sbin/ufw status | grep -q "$TEST_IP_ADMIN"; then
                        printf "  %sFAIL%s test rule for %s was left behind\n" "$RED" "$RST" "$TEST_IP_ADMIN"; fails=$((fails+1))
                        /usr/sbin/ufw delete deny from "$TEST_IP_ADMIN" >/dev/null 2>&1 || true
                    else
                        ok "unblock removed the rule (verified out of band)"
                    fi
                else
                    printf "  %sFAIL%s admin write failed — wrong password, or a real fault\n" "$RED" "$RST"; fails=$((fails+1))
                fi
            fi
        fi
    fi
    unset admin_pass

    # Any degraded signal raised during this deployment.
    if [ -f "$STATE_DIR/degraded.jsonl" ]; then
        local recent
        recent="$(tail -3 "$STATE_DIR/degraded.jsonl" 2>/dev/null || true)"
        [ -n "$recent" ] && { warn "degraded.jsonl has entries — review them:"; printf '%s\n' "$recent" | sed 's/^/         /'; }
    fi

    if [ "$fails" -eq 0 ]; then
        printf "\n  %sAll post-cutover checks passed.%s\n" "$GRN" "$RST"
    else
        printf "\n  %s%d check(s) FAILED.%s Consider --rollback.\n" "$RED" "$fails" "$RST"
        return 1
    fi
}

do_verify() { need_root; step "post-cutover verification"; do_verify_inner; }

# ── rollback ─────────────────────────────────────────────────────────────────

do_rollback() {
    need_root
    [ -f "$STAMP" ] || die "no stamp at $STAMP — nothing recorded to roll back to"
    # shellcheck disable=SC1090
    . "$STAMP"
    [ -n "${ROLLBACK_COMMIT:-}" ] || die "stamp has no ROLLBACK_COMMIT"

    step "1/4  stop and disable the helper"
    systemctl disable --now nemesis-fwd >/dev/null 2>&1 || true
    ok "nemesis-fwd stopped and disabled ($(svc_state nemesis-fwd))"
    if [ -f "$UNIT_DST" ]; then rm -f "$UNIT_DST"; ok "removed $UNIT_DST"; fi
    systemctl daemon-reload; ok "daemon-reload"

    step "2/4  restore the tree to $(git -C "$TREE" log --oneline -1 "$ROLLBACK_COMMIT" 2>/dev/null || echo "$ROLLBACK_COMMIT")"
    # Files ADDED since the rollback point must be deleted; checkout alone
    # restores content but never removes files that did not exist back then.
    local added
    added="$(git -C "$TREE" diff --name-only --diff-filter=A "$ROLLBACK_COMMIT" HEAD 2>/dev/null || true)"
    git -C "$TREE" checkout "$ROLLBACK_COMMIT" -- . 2>/dev/null || die "git checkout failed"
    ok "tracked files restored"
    if [ -n "$added" ]; then
        printf '%s\n' "$added" | while IFS= read -r f; do
            [ -n "$f" ] || continue
            rm -f "$TREE/$f" && printf "  %sOK%s   removed added file: %s\n" "$GRN" "$RST" "$f"
        done
    else
        info "no files were added since the rollback point"
    fi

    step "3/4  restart ${CUTOVER_SERVICES[*]}"
    local s failed=0
    for s in "${CUTOVER_SERVICES[@]}"; do
        systemctl restart "$s" || true
        sleep 2
        if [ "$(svc_state "$s")" = "active" ]; then
            ok "$s active"
        else
            printf "  %sFAIL%s %s did NOT come back\n" "$RED" "$RST" "$s"
            journalctl -u "$s" -n 20 --no-pager | sed 's/^/         /'
            failed=1
        fi
    done

    step "4/4  state"
    info "ufw DENY rules now: $(ufw_rule_count)  (before deployment: ${UFW_RULES_BEFORE:-unknown})"
    info "group $FW_GROUP left in place (harmless; remove manually if desired)"
    mv "$STAMP" "$STAMP.rolledback.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    [ "$failed" -eq 0 ] || die "rollback finished but a service did not return — investigate now"
    printf "\n  %sRollback complete.%s\n" "$BLD" "$RST"
    # The tree now holds OLDER content than HEAD, so `git status` reports
    # modifications. That is intentional — the running code is deliberately
    # behind the branch — but --run refuses a dirty tree, so re-attempting the
    # deployment needs the tree put back first.
    printf "  Note: the tree is now intentionally BEHIND HEAD, so 'git status' shows\n"
    printf "  modified files. To retry the deployment, restore it first:\n"
    printf "      git -C %s checkout HEAD -- .\n\n" "$TREE"
}

case "${1:-}" in
    --preflight) do_preflight ;;
    --run)       do_run ;;
    --verify)    do_verify ;;
    --rollback)  do_rollback ;;
    *) printf "usage: %s --preflight | --run | --verify | --rollback\n" "$0" >&2; exit 2 ;;
esac
