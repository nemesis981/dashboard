#!/usr/bin/env python3
"""error_code_registry — the cross-namespace collision guard. Tests.

Run: python3 scripts/test_error_code_registry.py

Asserts the LIVE tree is clean AND that the checker actually catches a collision and an
unregistered namespace (a guard that cannot fail proves nothing)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import error_code_registry as reg                            # noqa: E402

_fail = 0
def check(label, cond, detail=""):
    global _fail
    if cond:
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s  %s" % (label, detail))


print("== the live repo is clean ==")
findings, decls = reg.check()
check("no collisions / unregistered namespaces in the tree", not findings, findings)
check("found a plausible number of codes", len(decls) > 30, len(decls))

print("== CONTROL: a duplicate code is caught ==")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "a")); os.makedirs(os.path.join(d, "b"))
    for sub in ("a", "b"):
        open(os.path.join(d, sub, "cat.py"), "w").write('CODES = {\n    "E-AGENT-999": ("dup", "x"),\n}\n')
    findings, _ = reg.check(root=d)
    check("duplicate E-AGENT-999 flagged as COLLISION",
          any(s == "COLLISION" and "E-AGENT-999" in m for s, m in findings), findings)

print("== CONTROL: an unregistered namespace is caught ==")
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "cat.py"), "w").write('CODES = {\n    "E-AGNET-001": ("typo ns", "x"),\n}\n')
    findings, _ = reg.check(root=d)
    check("typo namespace E-AGNET flagged as UNREGISTERED",
          any(s == "UNREGISTERED" and "AGNET" in m for s, m in findings), findings)

print("== CONTROL: a clean fixture yields no findings ==")
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "cat.py"), "w").write('CODES = {\n    "E-AGENT-001": ("ok", "x"),\n}\n')
    findings, _ = reg.check(root=d)
    check("a single registered code is clean", not findings, findings)

print("== test fixtures (test_*.py) are excluded ==")
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "test_fixtures.py"), "w").write('X = {\n    "E-A-001": ("fixture", "x"),\n}\n')
    findings, decls = reg.check(root=d)
    check("throwaway codes in test_*.py are not scanned", not decls and not findings, (decls, findings))

# ── Added 2026-08-31 with the constant-style fix ────────────────────────────
# The checker used to match ONLY catalog dict keys, so DHCP/CONSENT/CONN --
# which declare their codes as module-level constants -- were invisible to
# every run while sitting in REGISTERED_NAMESPACES looking covered. 24 real
# codes went unchecked and the output still printed an unqualified CLEAN.

print("== module-level CONSTANT declarations are scanned (the fixed blind spot) ==")
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "cat.py"), "w").write(
        'E_CONFIG_INVALID   = "E-DHCP-001"\n'
        'E_PIHOLE_DHCP_ON   = "E-DHCP-002"\n')
    findings, decls = reg.check(root=d)
    check("a constant-declared code is SEEN", "E-DHCP-001" in decls, sorted(decls))
    check("...both of them", len(decls) == 2, sorted(decls))
    check("...and a registered namespace is still clean", not findings, findings)

print("== a USE of a code is not mistaken for a DECLARATION ==")
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "uses.py"), "w").write(
        'def f(conn):\n'
        '    record_error(conn, "E-DHCP-001")\n'
        '    if code == "E-DHCP-001":\n'
        '        pass\n'
        '    return {"x": "E-DHCP-001"}\n')
    findings, decls = reg.check(root=d)
    check("call sites and comparisons are NOT counted as declarations",
          decls == {}, decls)

print("== a collision ACROSS the two declaration styles is caught ==")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "a")); os.makedirs(os.path.join(d, "b"))
    open(os.path.join(d, "a", "const.py"), "w").write('E_THING = "E-DHCP-055"\n')
    open(os.path.join(d, "b", "cat.py"), "w").write(
        'CODES = {\n    "E-DHCP-055": ("same code, other style", "x"),\n}\n')
    findings, _ = reg.check(root=d)
    check("constant in one file + dict key in another = COLLISION",
          any(s == "COLLISION" and "E-DHCP-055" in m for s, m in findings),
          findings)

print("== an UNREADABLE source file is reported, not skipped ==")
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "locked.py")
    open(p, "w").write('E_X = "E-DHCP-077"\n')
    os.chmod(p, 0o000)
    try:
        findings, decls = reg.check(root=d)
        unreadable_flagged = any(s == "UNREADABLE" for s, _ in findings)
        # CONTROL: if the test is running as root, chmod 000 does not deny, so
        # the file IS readable and this check would vacuously "fail". Detect
        # that and assert the opposite instead of reporting a false negative.
        readable_anyway = "E-DHCP-077" in decls
        if readable_anyway:
            check("SKIPPED (running as root: chmod 000 does not deny) -- "
                  "file was readable, so it was scanned", True)
        else:
            check("an unreadable file is flagged UNREADABLE", unreadable_flagged,
                  findings)
            check("...and the run does NOT report itself clean", bool(findings),
                  findings)
    finally:
        os.chmod(p, 0o600)

print()

print("\n%s" % ("ALL PASS" if not _fail else "FAILED (%d)" % _fail))
sys.exit(1 if _fail else 0)
