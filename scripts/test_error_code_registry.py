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

print("\n%s" % ("ALL PASS" if not _fail else "FAILED (%d)" % _fail))
sys.exit(1 if _fail else 0)
