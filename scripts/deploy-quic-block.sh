#!/usr/bin/env bash
# Deploy the Nemesis QUIC static-policy nft table (Piece K) — validating BEFORE
# installing, and verifying the table actually loaded afterwards.
#
# Usage:
#   scripts/deploy-quic-block.sh            # validate, install, enable, verify
#   scripts/deploy-quic-block.sh --check    # validate only, change nothing
#
# WHY VALIDATION IS NOT OPTIONAL. An nft ruleset that fails to parse does not
# degrade loudly — the table simply never exists, and the counter reads 0. A
# counter of 0 is indistinguishable from "no QUIC has crossed the box yet", which
# is a perfectly normal state. So a broken deploy looks exactly like a quiet
# network, and nothing surfaces the difference. The same failure shape stalled
# Piece K once already. `nft -c -f` is the cheap guard and it runs first.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_NFT="$REPO/config/nftables/nemesis-quic-block.nft"
SRC_UNIT="$REPO/config/nftables/nemesis-quic-block.service"
DEST_NFT="/etc/nemesis/nemesis-quic-block.nft"
DEST_UNIT="/etc/systemd/system/nemesis-quic-block.service"
TABLE="inet nemesis_policy"

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

die() { echo "FATAL: $*" >&2; exit 1; }

[[ -f "$SRC_NFT" ]]  || die "missing $SRC_NFT"
[[ -f "$SRC_UNIT" ]] || die "missing $SRC_UNIT"
command -v nft >/dev/null || die "nft not installed (apt install nftables)"

# ── Validate BEFORE touching anything ────────────────────────────────────────
# `nft -c -f` parses and checks the ruleset without applying it.
#
# ⚠ IT NEEDS ROOT EVEN TO PARSE. Run unprivileged it fails with
#   "netlink: Error: cache initialization failed: Operation not permitted"
# — which is the INSTRUMENT failing, not the ruleset being bad. Reporting that as
# "ruleset FAILED validation" would be a confident wrong answer, and this script
# did exactly that on its first run. The two cases are separated below and given
# different exit codes so a caller can tell them apart.
if ! nft -c -f "$SRC_NFT" 2>/tmp/nft-check.$$; then
    if grep -qiE "cache initialization failed|Operation not permitted|must be root" /tmp/nft-check.$$; then
        cat /tmp/nft-check.$$ >&2; rm -f /tmp/nft-check.$$
        echo "CANNOT VALIDATE: nft needs root even for --check. Re-run with sudo." >&2
        echo "  (this is NOT a statement about the ruleset — it was never parsed)" >&2
        exit 3
    fi
    echo "--- nft -c output ---" >&2; cat /tmp/nft-check.$$ >&2; rm -f /tmp/nft-check.$$
    die "ruleset FAILED validation — nothing was installed"
fi
rm -f /tmp/nft-check.$$
echo "validation: OK (ruleset parses)"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "--check: validated only, nothing installed."
    exit 0
fi

# ── Install ──────────────────────────────────────────────────────────────────
install -d -m 0755 /etc/nemesis
install -m 0644 "$SRC_NFT"  "$DEST_NFT"
install -m 0644 "$SRC_UNIT" "$DEST_UNIT"
systemctl daemon-reload
# `enable --now` does NOT reload a unit that is already running, so an upgrade
# that changes the ruleset would silently not take effect until the next reboot.
# Measured 2026-08-06: a corrected .nft file sat unused until an explicit reload.
# enable (for boot) + restart (to apply NOW) are both required.
systemctl enable nemesis-quic-block >/dev/null 2>&1 || \
    die "could not enable nemesis-quic-block.service"
systemctl restart nemesis-quic-block >/dev/null 2>&1 || \
    die "could not start nemesis-quic-block.service"

# ── Verify the RESULT, not the exit code ─────────────────────────────────────
# systemd reports a oneshot as successful whenever its ExecStart returns 0. That
# is not the same as the table existing, which is the thing we actually want.
sleep 1
nft list table $TABLE >/dev/null 2>&1 \
    || die "unit started but table '$TABLE' is ABSENT — QUIC is NOT being blocked"

# The rule must not have been silently narrowed to one address family. nft
# inserts `meta nfproto ipv4` when a reject is family-specific, after which IPv6
# QUIC passes freely while the counter still reads 0.
if nft list table $TABLE | grep -q "nfproto ipv4"; then
    die "rule was narrowed to IPv4 — IPv6 QUIC would pass unblocked"
fi

echo "installed: $DEST_NFT"
echo "enabled:   nemesis-quic-block.service"
echo "table:     $TABLE present, both address families"
echo "DONE."
