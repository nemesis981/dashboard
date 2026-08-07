#!/bin/bash
# nemesis-pihole-password — check or rotate the Pi-hole credential Nemesis uses.
#
# REPLACES alert_manager/install_pihole_pwd.sh, which was a ONE-SHOT MIGRATION for
# moving PIHOLE_PASSWORD out of an inline Environment= line in dashboard.service and
# into /etc/nemesis.env. That migration is complete and verified (2026-08-07: the live
# unit carries three Environment= lines, none of them PIHOLE_PASSWORD), so the old
# script had no remaining job — and it could not run anyway, because its UNIT_SRC
# still pointed at a pre-/opt dev path that no longer exists.
#
# WHAT THIS DOES INSTEAD
#   --check   (default)  Read-only. Does the STORED credential actually authenticate
#                        against Pi-hole right now? Changes nothing.
#   --sync               Prompt for a password, VERIFY it against Pi-hole's API, and
#                        only then persist it to /etc/nemesis.env and restart the
#                        services that consume it. Refuses to store a credential that
#                        does not work.
#
# WHY --sync DOES NOT CALL `pihole setpassword` ITSELF
#   `pihole setpassword <pwd>` puts the secret in argv, where any user on the box can
#   read it from `ps`. Pi-hole's own interactive prompt (`sudo pihole setpassword`
#   with no argument) never exposes it. So a full rotation is deliberately two steps:
#
#       sudo pihole setpassword          # Pi-hole prompts; secret never hits argv
#       sudo /opt/nemesis/scripts/nemesis-pihole-password.sh --sync
#
#   The second step is what makes it safe: it will not write the new value into
#   /etc/nemesis.env unless that value genuinely authenticates. The failure this
#   prevents is storing a password that does not work, which presents later as an
#   unexplained loss of the VPN DNS safety net.
#
# RULE 8: the password is never echoed, never logged, never passed on a command line,
# and never written anywhere but /etc/nemesis.env (mode 640 root:nemesis).
set -euo pipefail

NEMESIS_ENV=/etc/nemesis.env
CONSUMERS=(dashboard vpn-dns-guard)   # the units that read PIHOLE_PASSWORD
MODE=check

case "${1:---check}" in
    --check) MODE=check ;;
    --sync)  MODE=sync ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
esac

# Read KEY=VALUE the way systemd's EnvironmentFile= does — NOT with `source`.
# /etc/nemesis.env is NOT shell-sourceable: at least one value contains an unquoted
# ')' and `source` dies on it with a syntax error. systemd does not shell-parse, so
# the services are fine; anything that sources this file silently gets a truncated
# environment. Confirmed 2026-08-07 — it cost an afternoon, so it is written down here.
read_env() {
    local key="$1" line
    line="$(grep -aE "^${key}=" "$NEMESIS_ENV" 2>/dev/null | tail -1)" || return 1
    [[ -z "$line" ]] && return 1
    local val="${line#*=}"
    val="${val%\"}"; val="${val#\"}"
    val="${val%\'}"; val="${val#\'}"
    printf '%s' "$val"
}

if [[ ! -r "$NEMESIS_ENV" ]]; then
    echo "FAIL: cannot read $NEMESIS_ENV (need root or the 'nemesis' group)." >&2
    exit 1
fi

PIHOLE_IP="$(read_env PIHOLE_IP || true)"
if [[ -z "$PIHOLE_IP" ]]; then
    echo "FAIL: PIHOLE_IP is not set in $NEMESIS_ENV — cannot reach Pi-hole." >&2
    exit 1
fi

# Ask Pi-hole whether a password authenticates. Returns 0 on success.
# The secret goes to curl on STDIN, never in argv (argv is world-readable via ps).
pihole_auth_ok() {
    local pw="$1" body
    body="$(printf '%s' "$pw" | python3 -c 'import json,sys; print(json.dumps({"password": sys.stdin.read()}))')"
    printf '%s' "$body" \
        | curl -s -m 8 -X POST -H 'Content-Type: application/json' \
               --data @- "http://${PIHOLE_IP}/api/auth" 2>/dev/null \
        | python3 -c 'import json,sys
try:
    print("OK" if json.load(sys.stdin).get("session", {}).get("sid") else "NO")
except Exception:
    print("NO")' | grep -q '^OK$'
}

# ---------------------------------------------------------------- check (read-only)
STORED="$(read_env PIHOLE_PASSWORD || true)"
echo "Pi-hole target        : $PIHOLE_IP"
if [[ -z "$STORED" ]]; then
    echo "Stored credential     : NOT SET in $NEMESIS_ENV"
    STORED_OK=no
elif pihole_auth_ok "$STORED"; then
    echo "Stored credential     : set (${#STORED} chars) — AUTHENTICATES OK"
    STORED_OK=yes
else
    echo "Stored credential     : set (${#STORED} chars) — DOES NOT AUTHENTICATE"
    STORED_OK=no
fi

if [[ "$MODE" == check ]]; then
    if [[ "$STORED_OK" == yes ]]; then
        echo "RESULT: healthy — Nemesis can authenticate to Pi-hole."
        exit 0
    fi
    echo "RESULT: BROKEN — Nemesis cannot authenticate to Pi-hole, so vpn-dns-guard"
    echo "        cannot apply or restore the VPN DNS fix. Re-sync with:"
    echo "          sudo pihole setpassword        # if the Pi-hole password changed"
    echo "          sudo $0 --sync"
    exit 1
fi

# ----------------------------------------------------------------------- sync
if [[ "$(id -u)" -ne 0 ]]; then
    echo "FAIL: --sync writes $NEMESIS_ENV and restarts services; run it with sudo." >&2
    exit 1
fi

echo
echo "Enter the CURRENT Pi-hole web password (set it first with 'sudo pihole setpassword')."
read -rsp "New password: " NEWPW; echo
read -rsp "Confirm     : " NEWPW2; echo
if [[ "$NEWPW" != "$NEWPW2" ]]; then
    echo "FAIL: the two entries differ. Nothing written." >&2
    exit 1
fi
if [[ -z "$NEWPW" ]]; then
    echo "FAIL: empty password refused. Nothing written." >&2
    exit 1
fi

# THE GATE. Prove it works BEFORE persisting it — storing an unverified credential is
# the exact failure this script exists to prevent.
if ! pihole_auth_ok "$NEWPW"; then
    echo "FAIL: that password does NOT authenticate against Pi-hole at $PIHOLE_IP." >&2
    echo "      Nothing was written and no service was restarted." >&2
    echo "      If you have just changed it, re-run 'sudo pihole setpassword' and retry." >&2
    exit 1
fi
echo "Verified: the supplied password authenticates against Pi-hole."

BACKUP="${NEMESIS_ENV}.bak-$(date +%Y%m%d-%H%M%S)"
install -m 640 -o root -g nemesis "$NEMESIS_ENV" "$BACKUP"
echo "Backup written: $BACKUP"

# Rewrite in python: it handles arbitrary characters in the value without the
# sed-escaping traps, and takes the secret via the environment rather than argv.
TMP="$(mktemp "${NEMESIS_ENV}.XXXXXX")"
chmod 640 "$TMP"; chown root:nemesis "$TMP"
NEMESIS_NEW_PW="$NEWPW" python3 - "$NEMESIS_ENV" "$TMP" <<'PY'
import os, sys
src, dst = sys.argv[1], sys.argv[2]
pw = os.environ["NEMESIS_NEW_PW"]
out, replaced = [], False
for line in open(src):
    if line.startswith("PIHOLE_PASSWORD="):
        out.append("PIHOLE_PASSWORD=%s\n" % pw); replaced = True
    else:
        out.append(line)
if not replaced:
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n"
    out.append("PIHOLE_PASSWORD=%s\n" % pw)
# Values are written RAW, matching the convention of every other key in this file.
# Do not "helpfully" add quotes here: the file's readers (systemd, and the
# line-parsers in diagnostics/) expect this shape, and changing it for one key only
# would be a silent inconsistency.
open(dst, "w").writelines(out)
PY
mv -f "$TMP" "$NEMESIS_ENV"
echo "Updated $NEMESIS_ENV"

echo "Restarting consumers: ${CONSUMERS[*]}"
for unit in "${CONSUMERS[@]}"; do
    systemctl restart "$unit" || echo "  WARNING: restart of $unit returned non-zero"
done
sleep 2

# Verify the RESULT, not the restart's exit code (Rule 13).
FAILED=0
for unit in "${CONSUMERS[@]}"; do
    state="$(systemctl is-active "$unit" 2>&1 || true)"
    printf '  %-18s %s\n' "$unit" "$state"
    [[ "$state" == active ]] || FAILED=1
done
if ! pihole_auth_ok "$(read_env PIHOLE_PASSWORD)"; then
    echo "FAIL: the stored credential does not authenticate after the write." >&2
    echo "      Restore with: cp $BACKUP $NEMESIS_ENV" >&2
    exit 1
fi
echo "Verified: the stored credential authenticates and consumers are running."
[[ "$FAILED" -eq 0 ]] || { echo "FAIL: a consumer did not come back active." >&2; exit 1; }
echo "RESULT: rotation complete."
