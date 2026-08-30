#!/usr/bin/env bash
# Turn ON Suricata's EXTENDED DHCP eve logging, for modules/lan_integrity.
#
#   scripts/enable-suricata-dhcp-extended.sh          # apply, validate, reload
#   scripts/enable-suricata-dhcp-extended.sh --check  # report only, change nothing
#
# WHAT THIS CHANGES AND WHY IT IS WORTH A SCRIPT RATHER THAN A sed ONE-LINER.
# The `- dhcp:` eve logger already defaults to `enabled: yes`, so rogue-DHCP
# detection WORKS WITHOUT THIS -- server identity comes from the eve record's
# top-level `src_ip`. What `extended: yes` adds is the ADVERTISED `routers` and
# `dns_servers`, which is what separates "an unexpected server answered" (high)
# from "an unexpected server tried to become your gateway and resolver"
# (critical).
#
# ⚠ AND IT WIDENS COVERAGE TOO — corrected 2026-08-30 after measuring it.
# Non-extended mode logs "just enough to map a MAC to an IP", which in practice
# means the ACK ONLY: a crafted pcap with one OFFER and one ACK produced 1 event
# with extended off and 2 with it on. The OFFER is dropped entirely. A rogue
# server that OFFERS and loses the race produces an OFFER and no ACK, so the
# un-flipped state cannot see a rogue that is trying but not yet winning.
#
# WHY VALIDATION IS NOT OPTIONAL, same reasoning as deploy-suricata-rules.sh: a
# Suricata config that fails to parse does not degrade loudly. The service keeps
# running on its LAST GOOD config, or fails to restart -- and either way the
# change silently did not take while every surface still looks healthy. So this
# validates with `suricata -T` BEFORE reloading, and refuses to reload otherwise.
#
# ⚠ IT ALSO VERIFIES THE CHANGE ACTUALLY TOOK, by re-reading the file. An
# idempotent sed that matched nothing exits 0 and prints nothing -- indis-
# tinguishable from a successful edit. That is the exact instrument-shaped
# failure this repo keeps cataloguing, so the read-back is a gate, not a report.
#
# This is a STATE-CHANGING action on live config: take a State Snapshot first
# (see CLAUDE.md) and run it deliberately, not as part of another task.
set -euo pipefail

YAML="${NEMESIS_SURICATA_YAML:-/etc/suricata/suricata.yaml}"
CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

die() { echo "FATAL: $*" >&2; exit 1; }

[[ -f "$YAML" ]] || die "$YAML not found"

# Read the CURRENT value of `extended:` inside the `- dhcp:` eve-log block only.
# Scoped to that block deliberately: several eve loggers have an `extended` key,
# and a file-wide grep would report some other logger's setting as this one's --
# a plausible answer from the wrong place.
current_extended() {
    awk '
        /^[[:space:]]*-[[:space:]]*dhcp:[[:space:]]*$/ { in_dhcp=1; next }
        in_dhcp && /^[[:space:]]*-[[:space:]]*[a-z0-9_-]+:[[:space:]]*$/ { in_dhcp=0 }
        in_dhcp && /^[[:space:]]*extended:/ {
            sub(/^[[:space:]]*extended:[[:space:]]*/, ""); sub(/[[:space:]]*(#.*)?$/, "");
            print; exit
        }
    ' "$YAML"
}

before="$(current_extended || true)"
if [[ -z "$before" ]]; then
    die "could not find an 'extended:' key inside the '- dhcp:' eve-log block of $YAML.
Refusing to guess where to write it -- an unreadable premise is not a reason to edit blind."
fi

echo "current: dhcp extended = $before"
if [[ "$CHECK_ONLY" == "1" ]]; then
    [[ "$before" == "yes" ]] && echo "already enabled; nothing to do" || echo "would set to: yes"
    exit 0
fi

if [[ "$before" == "yes" ]]; then
    echo "already enabled; nothing to do"
    exit 0
fi

backup="${YAML}.nemesis-bak-$(date +%Y%m%d-%H%M%S)"
cp -a "$YAML" "$backup"
echo "backup: $backup"

# Rewrite ONLY the extended: line inside the - dhcp: block.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
awk '
    /^[[:space:]]*-[[:space:]]*dhcp:[[:space:]]*$/ { in_dhcp=1; print; next }
    in_dhcp && /^[[:space:]]*-[[:space:]]*[a-z0-9_-]+:[[:space:]]*$/ { in_dhcp=0 }
    in_dhcp && !done && /^[[:space:]]*extended:/ {
        match($0, /^[[:space:]]*/); indent=substr($0, 1, RLENGTH)
        print indent "extended: yes"; done=1; next
    }
    { print }
' "$YAML" > "$tmp"

# ⚠ NOT `cp -a`. mktemp creates 0600, and -a would copy that mode onto the live
# config -- which is exactly what happened on 2026-08-30, silently changing
# /etc/suricata/suricata.yaml from 0644 to 0600. Plain `cp` to an EXISTING file
# copies content only and leaves the destination's mode and owner alone, which is
# the required behaviour here. (-a stays correct for the BACKUP and the RESTORE
# paths below, where preserving the source's attributes is the point.)
cp "$tmp" "$YAML"

# ── GATE 1: the edit actually took ───────────────────────────────────────────
after="$(current_extended || true)"
if [[ "$after" != "yes" ]]; then
    cp -a "$backup" "$YAML"
    die "edit did not take (still '$after') — restored $backup, nothing reloaded"
fi

# ── GATE 2: the resulting config PARSES ──────────────────────────────────────
#
# `-l "$TESTLOG"` IS LOAD-BEARING. Without it, `suricata -T` inherits
# default-log-dir (/var/log/suricata) and dies with "logging directory ... is not
# writable" for any non-root caller -- MEASURED 2026-08-30 on this box, where an
# UNMODIFIED copy of the live config failed validation exactly as loudly as a
# broken one would. A validator that fails identically on good and bad input is
# not a validator, and its message ("resulting config failed") would have blamed
# the edit for a permission problem. deploy-suricata-rules.sh already passes -l
# for this reason; omitting it here was the bug.
TESTLOG="$(mktemp -d)"
trap 'rm -f "$tmp"; rm -rf "$TESTLOG"' EXIT

# CONTROL FIRST: prove the validator ACCEPTS the known-good config (the backup we
# just took) before trusting its verdict on the modified one. If the control
# fails, the instrument is broken or unprivileged -- that is a DIFFERENT failure
# from a bad edit and must not be reported as one.
if ! suricata -T -c "$backup" -l "$TESTLOG" >"$TESTLOG/control.out" 2>&1; then
    cp -a "$backup" "$YAML"
    echo "--- control output ---" >&2; tail -5 "$TESTLOG/control.out" >&2
    die "the VALIDATOR itself rejects the pre-existing config — this is not a
problem with the change. Restored $backup, nothing reloaded. Re-run as root, or
investigate the validator before drawing any conclusion about the edit."
fi

if ! suricata -T -c "$YAML" -l "$TESTLOG" >"$TESTLOG/out" 2>&1; then
    cp -a "$backup" "$YAML"
    echo "--- suricata -T output ---" >&2; tail -5 "$TESTLOG/out" >&2
    die "resulting config failed 'suricata -T' (control passed, so this IS the
edit) — restored $backup, nothing reloaded"
fi

systemctl reload suricata || systemctl restart suricata
echo "OK: dhcp extended logging enabled and Suricata reloaded"
echo "Verify with real output (a config that parsed is not proof events changed shape):"
echo "  grep -m1 '\"event_type\":\"dhcp\"' /var/log/suricata/eve.json | python3 -m json.tool"
