"""Regression guard: the dnsmasq this module drives MUST support `nftset`.

WHY THIS EXISTS
    L3 Tier 2's DNS-time selection depends on dnsmasq's
    `nftset=/domain/inet#table#set`, which makes the resolver populate an nftables
    set directly -- near-zero custom code, landing in the same nftables world ADR
    0019's enforcement engine already owns. Without it that mechanism needs a
    separate bridge and gets materially more expensive.

    Recorded 2026-08-07 as time-critical for this module's build: "whichever
    dnsmasq that module ships must be compiled with nftset support ... This is
    exactly the kind of constraint that is cheap now and expensive after the
    module is finalized." Pi-hole's embedded FTL is compiled `no-nftset`;
    Debian/Ubuntu's packaged dnsmasq generally is not.

⚠ THE REQUIREMENT IS CURRENTLY SATISFIED BY ACCIDENT, WHICH IS WHY IT NEEDS PINNING.
    The requirement never reached this module's build -- `nftset` appears nowhere
    in the repo. It holds today only because the module independently stopped
    wrapping Pi-hole's FTL (`aa6916c`) and now drives the packaged dnsmasq, which
    happens to have nftset. Nothing checks that. Point the module back at an FTL-
    style build and a Tier 2 prerequisite breaks silently, with no failing test.

⚠ VERIFY BY THE COMPILE-TIME BANNER, NEVER THE VERSION NUMBER.
    Two builds of the same version differ on this. The 2026-08-07 finding was made
    from the runtime banner deliberately, not from `strings` and not from a version
    comparison.

⚠ AND `no-nftset` CONTAINS THE SUBSTRING `nftset`.
    A naive `"nftset" in banner` returns True for the exact build this guard exists
    to reject -- an instrument that cannot fail, reporting the one answer it can
    give. The parser tokenises and matches the whole option, and the known-bad case
    below is the REAL Pi-hole FTL banner recorded on 2026-08-07, so the trap is
    exercised rather than described.

ASSERTION COUNT IS FIXED -- every check runs unconditionally, none sits inside a
success-path branch (CLAUDE.md, 2026-08-29).
"""
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
# Repo root too: module.py does `from modules import NemesisModule`, so the
# package parent must be importable, not just this directory.
_ROOT = os.path.dirname(os.path.dirname(_HERE))
# alert_manager too -- module.py imports nemesis_errors from it, which itself
# imports flat siblings. This mirrors the PYTHONPATH the real services set.
_AM = os.path.join(_ROOT, "alert_manager")
for _p in (_HERE, _ROOT, _AM):
    if _p not in sys.path:
        sys.path.insert(0, _p)

EXPECTED_CHECKS = 12
passed = failed = 0


def check(label, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, extra))


def banner_has_nftset(banner):
    """True only if the banner advertises `nftset` as a WHOLE option token.

    Whole-token matching is the entire point: `no-nftset` and `nftset` differ by a
    prefix, and substring matching cannot tell them apart.
    """
    for line in (banner or "").splitlines():
        if "compile time options" not in line.lower():
            continue
        _, _, opts = line.partition(":")
        if "nftset" in opts.split():
            return True
    return False


# The REAL banners. Known-bad is Pi-hole's embedded FTL as recorded 2026-08-07.
FTL_BANNER = (
    "dnsmasq[2202]: started, version pi-hole-v2.93 cachesize 10000\n"
    "dnsmasq[2202]: compile time options: IPv6 GNU-getopt no-DBus no-UBus no-i18n "
    "IDN2 DHCP DHCPv6 Lua TFTP no-conntrack ipset no-nftset auth DNSSEC loop-detect "
    "inotify dumpfile\n"
)
PACKAGED_BANNER = (
    "Dnsmasq version 2.92  Copyright (c) 2000-2025 Simon Kelley\n"
    "Compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua "
    "TFTP conntrack ipset nftset auth DNSSEC loop-detect inotify dumpfile\n"
)

print("-- parser: known-good and known-bad, so it can actually discriminate --")
check("packaged dnsmasq banner -> SUPPORTED", banner_has_nftset(PACKAGED_BANNER) is True)
check("⭐ Pi-hole FTL banner (`no-nftset`) -> NOT supported",
      banner_has_nftset(FTL_BANNER) is False)
check("⭐ naive substring check WOULD have passed the bad banner (the trap is real)",
      "nftset" in FTL_BANNER)
check("empty banner -> not supported (a failed read is never a pass)",
      banner_has_nftset("") is False)
check("None -> not supported", banner_has_nftset(None) is False)
check("garbage -> not supported", banner_has_nftset("hello world") is False)
check("option named in a non-options line does not count",
      banner_has_nftset("some log line mentioning nftset\n") is False)

print("\n-- the module's OWN resolver is the source of truth for which binary --")
import module as dhcp_mod                                        # noqa: E402
binary = dhcp_mod._dnsmasq_binary()
check("module exposes _dnsmasq_binary()", callable(dhcp_mod._dnsmasq_binary))
check("resolver returned a non-empty path", bool(binary), "got %r" % (binary,))

print("\n-- LIVE: the binary this module would actually drive --")
if not os.path.exists(binary):
    state = "BINARY_ABSENT"
    live_banner = ""
else:
    try:
        live_banner = subprocess.run([binary, "--version"], capture_output=True,
                                     text=True, timeout=15).stdout
        state = "SUPPORTED" if banner_has_nftset(live_banner) else "NOT_SUPPORTED"
    except OSError as exc:
        state, live_banner = "UNREADABLE:%s" % exc, ""

print("     resolved binary : %s" % binary)
print("     state           : %s" % state)

# Explicit three-state result. BINARY_ABSENT is reported loudly and does NOT pass
# silently as "fine" -- dnsmasq is genuinely optional until the module runs in serve
# mode, but a missing read must never be reported as a satisfied requirement.
check("live state is one of the three recognised values",
      state in ("SUPPORTED", "NOT_SUPPORTED", "BINARY_ABSENT")
      or state.startswith("UNREADABLE:"), "got %r" % state)
check("⭐ the driven dnsmasq is NOT a no-nftset build",
      state != "NOT_SUPPORTED",
      "banner: %s" % " ".join(live_banner.split())[:200])

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

if state == "BINARY_ABSENT":
    print("\n  NOTE: dnsmasq is not installed here, so the live half asserted nothing")
    print("        about a real build. That is reported, not silently passed.")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
