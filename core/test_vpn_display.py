#!/usr/bin/env python3
"""VPN display: kind-matched detection, per-interface names, separate Tailscale.

Covers the 2026-08-30 rebuild of the dashboard's VPN section. Three properties
matter and each has a control, because each can pass for the wrong reason:
  * detection finds tunnels by KERNEL KIND, not by a hardcoded name list;
  * a USER LABEL always beats auto-detection, including confident detection;
  * Tailscale is reported SEPARATELY and never counted as the user's VPN.

Run:  python3 core/test_vpn_display.py
Exit: 0 all passed · 1 failure(s) · 3 harness could not establish its premise
"""
import os, sys, tempfile, traceback

_PASS, _FAIL = [], []
EXPECTED_CHECKS = 17


def check(label, cond, detail=""):
    (_PASS if cond else _FAIL).append(label)
    print(("  [PASS] " if cond else "  [FAIL] ") + label
          + (("  -- " + str(detail)) if detail and not cond else ""))
    return bool(cond)


def _die(msg):
    print("\nHARNESS PRECONDITION FAILED: %s" % msg)
    sys.exit(3)


os.environ["NEMESIS_DB_PATH"] = os.path.join(tempfile.mkdtemp(prefix="nemesis-vpnui-"), "t.db")
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_REPO, os.path.join(_REPO, "alert_manager"),
          os.path.join(_REPO, "core_module", "hw_monitor"), os.path.join(_REPO, "core")):
    if p not in sys.path:
        sys.path.insert(0, p)
try:
    import modules as _pkg
    _pkg.set_shared_db_path(os.environ["NEMESIS_DB_PATH"])
    import dashboard, database
    from core import vpn_dns_guard as vg
except Exception:
    traceback.print_exc()
    _die("could not import the dashboard stack")

print("\n== DETECTION IS KIND-MATCHED, NOT NAME-MATCHED ==")
# The bug this replaced: a hardcoded ["tun0","tun1","wg0","wg1",...] list that
# missed tun2, wg-mullvad and every non-default WireGuard name, showing
# "Disconnected" while a tunnel was up.
# Was written with an `or True` on the first pass, which made it unfailable --
# a vacuous assertion is worse than none, because it reads as coverage.
_dash_src = open(os.path.join(_REPO, "dashboard.py")).read()
# ⚠ MATCH CODE, NOT PROSE. The first version of this asserted the string was
# absent anywhere in the file and failed -- on the explanatory COMMENT that
# quotes the old list to say it was removed. A grep matching the note that
# announces a thing is obsolete is a standing failure in this codebase; the
# assignment must be anchored to the start of a line to mean "code".
import re as _re
check("the hardcoded interface-NAME list is gone from CODE (comments may cite it)",
      not _re.search(r"^_TUNNEL_IFACES\s*=", _dash_src, _re.M),
      "a real assignment still exists")
check("detection consults vpn_dns_guard's TUNNEL_KINDS", "TUNNEL_KINDS" in _dash_src)
check("TUNNEL_KINDS covers generic tun AND wireguard",
      {"tun", "wireguard"} <= vg.TUNNEL_KINDS, sorted(vg.TUNNEL_KINDS))
check("detect_vpn_tunnels returns a LIST (multi-VPN capable)",
      isinstance(dashboard.detect_vpn_tunnels(), list))

print("\n== TAILSCALE IS SEPARATE, AND THE EXCLUSION IS LOAD-BEARING ==")
ts = dashboard.get_tailscale_status()
check("tailscale status is readable", ts.get("error") is None, ts.get("error"))
check("it reports a definite up/down", isinstance(ts.get("running"), bool))
# THE CONTROL THAT MATTERS: tailscale0's kind is 'tun', which IS in TUNNEL_KINDS,
# so without the explicit skip it would be listed as one of the user's VPNs --
# kind-matching would have INTRODUCED the very conflation this rebuild removes.
check("CONTROL: tailscale0's kind is in TUNNEL_KINDS (so the skip is required)",
      "tun" in vg.TUNNEL_KINDS)
check("no detected tunnel is a tailscale interface",
      all(not t["iface"].startswith("tailscale") for t in dashboard.detect_vpn_tunnels()))

print("\n== PROVIDER NAMING REFUSES TO GUESS ==")
check("a generic tun0 yields NO provider", dashboard._vpn_provider_for("tun0", "tun") is None)
check("a generic wg0 yields NO provider", dashboard._vpn_provider_for("wg0", "wireguard") is None)
# CONTROL: it must still name the cases that ARE evidence about this tunnel, or
# "refuses to guess" would just mean "never identifies anything".
check("CONTROL: a vendor-created iface name IS identified",
      dashboard._vpn_provider_for("nordlynx", "tun") == "NordVPN")

print("\n== USER LABEL BEATS AUTO-DETECTION, ALWAYS ==")
_real = dashboard.detect_vpn_tunnels
dashboard.detect_vpn_tunnels = lambda: [
    {"iface": "tun0", "kind": "tun", "provider": "NordVPN",
     "protocol": "OpenVPN/tun", "vpn_ip": "10.8.0.2"}]
try:
    with dashboard.app.test_request_context():
        before = dashboard.render_network_paths_html()
    check("with no label, the detected name is shown", "NordVPN" in before)
    database.set_setting(dashboard.vpn_display_name_key("tun0"), "Work VPN")
    with dashboard.app.test_request_context():
        after = dashboard.render_network_paths_html()
    check("a user label REPLACES confident detection",
          "Work VPN" in after and "NordVPN" not in after, after[:200])
    # Clearing must fall back, or a label set once could never be undone.
    database.set_setting(dashboard.vpn_display_name_key("tun0"), "")
    with dashboard.app.test_request_context():
        cleared = dashboard.render_network_paths_html()
    check("CONTROL: clearing the label falls back to detection",
          "NordVPN" in cleared and "Work VPN" not in cleared)
finally:
    dashboard.detect_vpn_tunnels = _real

print("\n== UNNAMEABLE TUNNELS READ AS ACTIONABLE, NOT BROKEN ==")
dashboard.detect_vpn_tunnels = lambda: [
    {"iface": "tun0", "kind": "tun", "provider": None,
     "protocol": "OpenVPN/tun", "vpn_ip": None}]
try:
    with dashboard.app.test_request_context():
        un = dashboard.render_network_paths_html()
    check("shows 'VPN (unnamed)', not 'Unknown Provider'",
          "VPN (unnamed)" in un and "Unknown Provider" not in un, un[:200])
    check("and tells the user they can name it", "Settings" in un)
finally:
    dashboard.detect_vpn_tunnels = _real

print("\n== TOTALS ==")
_t = len(_PASS) + len(_FAIL)
check("assertion count matches EXPECTED_CHECKS", _t + 1 == EXPECTED_CHECKS,
      "ran %d expected %d" % (_t + 1, EXPECTED_CHECKS))
print("\n%d passed, %d failed" % (len(_PASS), len(_FAIL)))
sys.exit(1 if _FAIL else 0)
