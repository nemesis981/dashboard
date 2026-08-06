#!/usr/bin/env bash
# Deploy Nemesis host-defence rules to Suricata — validating BEFORE reloading.
#
# Usage:
#   scripts/deploy-suricata-rules.sh              # detect host address, deploy, reload
#   scripts/deploy-suricata-rules.sh --host <ip>  # override the detected address
#   scripts/deploy-suricata-rules.sh --check      # validate only, change nothing
#
# WHY VALIDATION IS NOT OPTIONAL HERE. A Suricata rule that fails to parse does
# not degrade loudly — it simply never loads, and the engine runs with that
# detection silently OFF. This exact failure nearly shipped on 2026-08-06, when a
# Snort-syntax `portvar` stopped BOTH sweep rules from loading while the
# false-positive test still "passed" (no alerts is what a fixed false positive
# looks like too). So this script refuses to install a ruleset that does not
# parse, and refuses to reload if the installed copy does not match what it
# intended to install.
#
# Run as an ordinary user: the two privileged steps go through the pinned
# NOPASSWD grants in /etc/sudoers.d/nemesis-suricata-rules (tee to the exact rules
# path, and `systemctl reload suricata`). `suricata -T` needs no privilege.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/config/suricata/local.rules"
DEST="/etc/suricata/rules/local.rules"
YAML="/etc/suricata/suricata.yaml"
PLACEHOLDER="@NEMESIS_HOST@"

HOST_IP=""
CHECK_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)  HOST_IP="${2:-}"; shift 2 ;;
        --check) CHECK_ONLY=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { echo "FATAL: $*" >&2; exit 1; }

[[ -f "$SRC" ]]  || die "rules source not found: $SRC"
[[ -f "$YAML" ]] || die "suricata config not found: $YAML"
command -v suricata >/dev/null || die "suricata binary not installed"

# ── Resolve THIS HOST's addresses ────────────────────────────────────────────
# Deliberately NOT `ip route get <internet ip>`, which is what install.sh uses and
# what the first version of this script used. On this box that returns the TAILNET
# address (routes to the internet go out tailscale0, table 52), while Suricata
# monitors the LAN interface. Excluding the tailnet address would have left the
# LAN self-noise completely unfixed while looking like a successful deploy — a
# plausible-looking wrong answer, which is the failure class this repo keeps
# catching. Measured 2026-08-06.
#
# Instead: exclude EVERY non-loopback IPv4 address this host holds. That is the
# robust definition of "this host" regardless of routing, and if it is ever
# incomplete the effect is the self-noise returning (noise), never a missed scan.
if [[ -z "$HOST_IP" ]]; then
    mapfile -t ADDRS < <(ip -4 -o addr show scope global 2>/dev/null \
                         | awk '{print $4}' | cut -d/ -f1 | sort -u)
    [[ ${#ADDRS[@]} -gt 0 ]] || die "could not determine any host address (pass --host <ip>)"
    HOST_IP="$(IFS=,; echo "${ADDRS[*]}")"
fi

for a in ${HOST_IP//,/ }; do
    # Validate each one: an unvalidated value substituted into a rule breaks
    # parsing, and a rule that does not parse is detection silently OFF.
    [[ "$a" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "not a valid IPv4 address: '$a'"
done

# Sanity-check against the interface Suricata actually watches: if the monitored
# interface's own address is not in the exclusion set, the exclusion is aimed at
# the wrong place and the self-noise will persist.
MON_IF="$(awk '/^af-packet:/{f=1} f && /^[[:space:]]*-[[:space:]]*interface:/{print $3; exit}' "$YAML" 2>/dev/null || true)"
if [[ -n "$MON_IF" && "$MON_IF" != "any" ]]; then
    MON_IP="$(ip -4 -o addr show dev "$MON_IF" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
    if [[ -n "$MON_IP" && ",$HOST_IP," != *",$MON_IP,"* ]]; then
        die "suricata monitors $MON_IF ($MON_IP) but that address is NOT in the exclusion set ($HOST_IP)"
    fi
    echo "suricata monitors: $MON_IF (${MON_IP:-no address})"
fi
echo "host addresses excluded as a source: $HOST_IP"

# ── Substitute, then VALIDATE before anything is installed ───────────────────
STAGE="$(mktemp -t nemesis-rules-XXXXXX.rules)"
TESTLOG="$(mktemp -d -t nemesis-rules-log-XXXXXX)"
trap 'rm -f "$STAGE"; rm -rf "$TESTLOG"' EXIT

grep -q "$PLACEHOLDER" "$SRC" || die "$PLACEHOLDER missing from $SRC — refusing to guess"
# Bracket form so a multi-address host substitutes into valid Suricata
# list syntax: `![a,b]`. Single-address hosts get `![a]`, also valid.
sed "s|$PLACEHOLDER|[$HOST_IP]|g" "$SRC" > "$STAGE"
grep -q "$PLACEHOLDER" "$STAGE" && die "placeholder survived substitution — refusing to deploy"

if ! suricata -T -c "$YAML" -S "$STAGE" -l "$TESTLOG" >"$TESTLOG/out" 2>&1; then
    echo "--- suricata -T output ---" >&2; cat "$TESTLOG/out" >&2
    die "ruleset FAILED validation — nothing was deployed"
fi
# `suricata -T` can exit 0 while still reporting per-signature parse errors, so
# the exit code alone is not sufficient evidence that every rule loaded.
if grep -qiE "error parsing signature|is not defined in configuration file|no rule options" \
        "$TESTLOG/out" "$TESTLOG"/suricata.log 2>/dev/null; then
    echo "--- suricata -T output ---" >&2; cat "$TESTLOG/out" >&2
    die "a signature failed to parse — nothing was deployed"
fi
echo "validation: OK (all signatures parsed)"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "--check: validated only, nothing deployed."
    exit 0
fi

# ── Install, verify the bytes landed, then reload ────────────────────────────
sudo -n tee "$DEST" < "$STAGE" >/dev/null \
    || die "could not write $DEST (is /etc/sudoers.d/nemesis-suricata-rules installed?)"

# Compare what is ON DISK against what we meant to install. A tee that silently
# truncated, or a concurrent writer, must not be followed by a confident reload.
if ! diff -q "$STAGE" "$DEST" >/dev/null; then
    die "installed file does NOT match the staged ruleset — refusing to reload"
fi
echo "installed: $DEST (matches staged copy)"

sudo -n systemctl reload suricata || die "suricata reload failed"

# Reload is asynchronous; confirm the service actually came back rather than
# assuming the reload command's exit code means the engine is healthy.
sleep 2
systemctl is-active --quiet suricata || die "suricata is NOT active after reload"
echo "suricata reloaded and active"
echo "DONE."
