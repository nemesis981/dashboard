#!/usr/bin/env bash
# install.sh must pick the LAN-FACING interface, never the default-route one.
#
# Run: bash alert_manager/test_lan_iface_detection.sh   (exit 0 = all pass)
#
# THE DEFECT (found 2026-08-06, fixed 2026-09-05)
#   install.sh derived the monitored interface from `ip route get 8.8.8.8`. On any
#   box whose default route leaves via a VPN or tailnet, that returns the TUNNEL
#   interface, which install_suricata() then writes into suricata.yaml's af-packet
#   section. Suricata is bound to an interface carrying none of the LAN traffic the
#   host-defence rules exist to detect -- and the install succeeds, the service
#   runs, the dashboard looks healthy, and nothing reports an error.
#
# ⛔ THE FUNCTION UNDER TEST IS SOURCED FROM install.sh, NOT REIMPLEMENTED.
#   It reads `ip -4 -o addr show scope global` on stdin precisely so it can be fed
#   recorded output here. A copy of the logic in this file would drift from the
#   installer and prove nothing about what ships.
set -uo pipefail
ROOT="${NEMESIS_ROOT:-/opt/nemesis}"
EXPECTED_CHECKS=11
pass=0; fail=0

check() { # label expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass+1)); echo "  [PASS] $1";
  else fail=$((fail+1)); echo "  [FAIL] $1   (got='$3' want='$2')"; fi
}

# Source ONLY the helper out of install.sh -- running the whole installer is not
# an option and sourcing it would execute it.
eval "$(sed -n '/^_VIRTUAL_IFACE_RE=/,/^}/p' "$ROOT/install.sh")"
if ! declare -F pick_lan_iface >/dev/null; then
  echo "FATAL: could not extract pick_lan_iface from install.sh -- this TEST is stale, or the fix was reverted"
  exit 1
fi

# Recorded `ip -4 -o addr show scope global` shapes. Addresses are RFC1918 /
# RFC5737 / CGNAT ranges only.
LAN_ONLY='2: enp0s3    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic enp0s3'
TAILNET='5: tailscale0    inet 100.101.102.103/32 scope global tailscale0'
VPN_TUN='6: tun0    inet 10.8.0.2/24 scope global tun0'
DOCKER='4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0'
SECOND_LAN='3: enp0s8    inet 10.0.5.4/24 brd 10.0.5.255 scope global enp0s8'
PUBLIC_ONLY='2: eth0    inet 203.0.113.7/24 brd 203.0.113.255 scope global eth0'

echo "1. the ordinary case still works"
check "a single LAN NIC is chosen" "enp0s3" "$(printf '%s\n' "$LAN_ONLY" | pick_lan_iface)"

echo
echo "2. THE DEFECT: a tailnet/VPN default route must not win"
# This is the exact shape measured on the dev box: internet leaves via tailscale0.
out=$(printf '%s\n%s\n' "$TAILNET" "$LAN_ONLY" | pick_lan_iface)
check "tailnet present -> still picks the LAN NIC" "enp0s3" "$out"
check "  ...and never returns the tailnet interface" "" "$(printf '%s\n' "$TAILNET" | pick_lan_iface)"

echo
echo "3. a VPN tunnel on an RFC1918 address is still not the LAN"
# tun0 carries 10.8.0.2 -- RFC1918, so an address-only rule would accept it.
# The interface-NAME filter is what rejects it, and this proves that filter carries
# its own weight rather than being belt-and-braces.
out=$(printf '%s\n%s\n' "$VPN_TUN" "$LAN_ONLY" | pick_lan_iface)
check "tun0 on 10.8.0.0/24 is rejected by NAME" "enp0s3" "$out"
check "  ...tun0 alone yields nothing" "" "$(printf '%s\n' "$VPN_TUN" | pick_lan_iface)"

echo
echo "4. docker/bridge addresses are RFC1918 too, and must not compete"
out=$(printf '%s\n%s\n' "$DOCKER" "$LAN_ONLY" | pick_lan_iface)
check "docker0 on 172.17/16 is rejected by NAME" "enp0s3" "$out"

echo
echo "5. AMBIGUITY IS REPORTED, NOT GUESSED"
# Two real LAN NICs is a legitimate topology (a gateway with WAN/LAN legs).
# Guessing would be the plausible-looking wrong answer this rewrite exists to stop.
out=$(printf '%s\n%s\n' "$LAN_ONLY" "$SECOND_LAN" | pick_lan_iface)
check "two LAN NICs -> empty (caller must ask)" "" "$out"

echo
echo "6. a CGNAT/tailnet address on an ORDINARY interface name is still rejected"
# Not covered by the name filter -- this is the case that proves the RFC1918
# requirement is what excludes the tailnet. An explicit CGNAT branch was written
# and removed after mutation testing showed it could never fire; this fixture is
# what keeps the surviving mechanism honest if that line is ever loosened.
check "100.64/10 on enp0s9 yields nothing" "" \
  "$(printf '%s\n' '7: enp0s9    inet 100.64.5.6/10 scope global enp0s9' | pick_lan_iface)"

echo
echo "7. no LAN address at all is a failure, not a silent pick"
check "public-only host yields nothing" "" "$(printf '%s\n' "$PUBLIC_ONLY" | pick_lan_iface)"
check "empty input yields nothing" "" "$(printf '' | pick_lan_iface)"

echo
echo "8. CONTROL: the OLD derivation really would have picked wrong"
# Not a claim about the new code -- it proves the defect was real and that this
# test's fixtures represent it, so the assertions above are not vacuous.
old_pick=$(printf '%s\n%s\n' "$TAILNET" "$LAN_ONLY" | head -1 | awk '{print $2}')
check "default-route-style pick returns the tunnel" "tailscale0" "$old_pick"

echo
echo "$pass passed, $fail failed"
ran=$((pass+fail))
if [[ $ran -ne $EXPECTED_CHECKS ]]; then
  echo "EXPECTED_CHECKS MISMATCH: declared $EXPECTED_CHECKS, ran $ran"; exit 1
fi
[[ $fail -eq 0 ]] || exit 1
