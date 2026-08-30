#!/usr/bin/env bash
# Turn ON Suricata's ARP eve logging, for modules/lan_integrity's ARP detection.
#
#   scripts/enable-suricata-arp-logging.sh          # apply, validate, reload
#   scripts/enable-suricata-arp-logging.sh --check  # report only, change nothing
#
# WHAT THIS CHANGES. The eve `- arp:` logger ships DISABLED (`enabled: no`) with
# Suricata's own comment: "Many events can be logged. Disabled by default."
# Without it, lan_integrity's only ARP source is /proc/net/arp -- this host's own
# resolution cache, which is SELF-REFERENTIAL (an attacker poisoning this
# appliance edits the very table used to detect them) and sees nothing about
# conversations between two other hosts.
#
# ⚠ VOLUME IS A REAL TRADEOFF AND IS NOT MEASURED HERE. Suricata disables this by
# default for a reason: ARP is chatty. On this box eve.json already turns over
# ~89 MB in under 8 hours WITHOUT ARP. Enabling it deliberately, per install, is
# why this is a script rather than a line in install.sh -- it should be a decision
# someone makes with their own network in view, not a default inherited silently.
# Check eve.json growth after enabling.
#
# ⚠ AND IT DOES NOT CLOSE THE VISIBILITY GAP. Broadcast ARP (requests, gratuitous
# ARP) becomes visible. A unicast ARP reply sent attacker-to-victim, where neither
# is this appliance, does NOT -- that is a switched-network topology limit, not a
# logging one. See modules/lan_integrity/arp_watch.py. Enabling this improves
# coverage; it does not make a quiet result mean "no spoofing".
#
# Same gate discipline as enable-suricata-dhcp-extended.sh, including the CONTROL
# validation: `suricata -T` is run against the known-good backup FIRST, because
# without `-l` it fails identically on a good config as on a broken one (measured
# 2026-08-30), and a validator that cannot pass must never be read as a verdict on
# the edit.
#
# STATE-CHANGING: take a State Snapshot first (see CLAUDE.md).
set -euo pipefail

YAML="${NEMESIS_SURICATA_YAML:-/etc/suricata/suricata.yaml}"
CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

die() { echo "FATAL: $*" >&2; exit 1; }
[[ -f "$YAML" ]] || die "$YAML not found"

# Scoped to the `- arp:` eve-log block. Several loggers carry `enabled:`, and a
# file-wide grep would report some other logger's value as this one's.
current_enabled() {
    awk '
        /^[[:space:]]*-[[:space:]]*arp:[[:space:]]*$/ { in_arp=1; next }
        in_arp && /^[[:space:]]*-[[:space:]]*[a-z0-9_-]+:[[:space:]]*$/ { in_arp=0 }
        in_arp && /^[[:space:]]*enabled:/ {
            sub(/^[[:space:]]*enabled:[[:space:]]*/, ""); sub(/[[:space:]]*(#.*)?$/, "");
            print; exit
        }
    ' "$YAML"
}

before="$(current_enabled || true)"
[[ -n "$before" ]] || die "could not find an 'enabled:' key inside the '- arp:' eve-log
block of $YAML. Refusing to guess where to write it."

echo "current: arp logger enabled = $before"
if [[ "$CHECK_ONLY" == "1" ]]; then
    [[ "$before" == "yes" ]] && echo "already enabled; nothing to do" || echo "would set to: yes"
    exit 0
fi
[[ "$before" == "yes" ]] && { echo "already enabled; nothing to do"; exit 0; }

backup="${YAML}.nemesis-bak-$(date +%Y%m%d-%H%M%S)"
cp -a "$YAML" "$backup"
echo "backup: $backup"

tmp="$(mktemp)"; TESTLOG="$(mktemp -d)"
trap 'rm -f "$tmp"; rm -rf "$TESTLOG"' EXIT

awk '
    /^[[:space:]]*-[[:space:]]*arp:[[:space:]]*$/ { in_arp=1; print; next }
    in_arp && /^[[:space:]]*-[[:space:]]*[a-z0-9_-]+:[[:space:]]*$/ { in_arp=0 }
    in_arp && !done && /^[[:space:]]*enabled:/ {
        match($0, /^[[:space:]]*/); indent=substr($0, 1, RLENGTH)
        print indent "enabled: yes"; done=1; next
    }
    { print }
' "$YAML" > "$tmp"
cp -a "$tmp" "$YAML"

# GATE 1 -- the edit took. An awk that matched nothing exits 0 and yields a valid
# file, which is indistinguishable from success.
after="$(current_enabled || true)"
if [[ "$after" != "yes" ]]; then
    cp -a "$backup" "$YAML"; die "edit did not take (still '$after') — restored $backup"
fi

# GATE 2 -- CONTROL FIRST, then the real check.
if ! suricata -T -c "$backup" -l "$TESTLOG" >"$TESTLOG/control.out" 2>&1; then
    cp -a "$backup" "$YAML"
    echo "--- control output ---" >&2; tail -5 "$TESTLOG/control.out" >&2
    die "the VALIDATOR rejects the pre-existing config — this is NOT a problem with
the change. Restored $backup, nothing reloaded. Re-run as root."
fi
if ! suricata -T -c "$YAML" -l "$TESTLOG" >"$TESTLOG/out" 2>&1; then
    cp -a "$backup" "$YAML"
    echo "--- suricata -T output ---" >&2; tail -5 "$TESTLOG/out" >&2
    die "resulting config failed validation (control passed, so this IS the edit) —
restored $backup, nothing reloaded"
fi

systemctl reload suricata || systemctl restart suricata
echo "OK: ARP eve logging enabled and Suricata reloaded"
echo "Verify with REAL OUTPUT -- a config that parsed is not proof events appear:"
echo "  grep -m1 '\"event_type\":\"arp\"' /var/log/suricata/eve.json | python3 -m json.tool"
echo "Then watch volume:  ls -l /var/log/suricata/eve.json  (re-check in an hour)"
