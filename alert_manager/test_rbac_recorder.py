"""The RBAC error recorder actually records. (2026-08-26 finding.)

WHAT WENT WRONG: dashboard.py built its recorder with
`get_data_manager().connect("core")` — and "core" IS NOT a Data Manager
namespace. connect() raised, the recorder's own `except Exception: return None`
swallowed it, and E-RBAC-001/002/003 recorded NOTHING, EVER.

WHY IT SURVIVED: the live ledger held zero E-RBAC rows, which reads exactly like
"no drift has ever occurred". Absence of evidence was indistinguishable from a
broken instrument — so this suite asserts the recorder WRITES, using a control
pair, rather than asserting the ledger is empty.

The gate it disabled promises, in its own words: "Fail closed, and SAY SO ...
silence would let the registry drift out of step with the routes forever."
It failed closed correctly and said so to nobody.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

import data_manager as dm_mod                                   # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


_DASH = "/opt/nemesis/dashboard.py"
_SRC = open(_DASH).read()

print("-- 1. The namespace dashboard.py SHIPS is a real one --")
m = re.search(r'_rbac_recorder = nemesis_errors\.make_recorder\(\s*'
              r'"([a-z_]+)",\s*lambda: get_data_manager\(\)\.connect\("([a-z_]+)"\)', _SRC)
check("the recorder construction is still findable in dashboard.py", m is not None)
label, ns = (m.group(1), m.group(2)) if m else (None, None)
check("connect() names a VALID Data Manager namespace (not 'core')",
      ns in dm_mod.NAMESPACES, ns)
check("CONTROL: 'core' really is NOT a namespace — so §1 could fail",
      "core" not in dm_mod.NAMESPACES)
check("label matches the connect namespace (the codebase convention)",
      label == ns, (label, ns))

print("\n-- 2. BEHAVIOURAL control pair: it actually WRITES --")
_db = os.path.join(tempfile.mkdtemp(prefix="rbac-rec-"), "t.db")
import modules                                                  # noqa: E402
modules.set_shared_db_path(_db)
import database                                                 # noqa: E402
database.DB_PATH = _db
database.init_error_tables()
import nemesis_errors                                           # noqa: E402
from modules import get_data_manager                            # noqa: E402

CODES = {"E-RBAC-002": ("drift", "MEDIUM", "unclassified-route")}


def _record_with(namespace):
    """Mimics dashboard's recorder EXACTLY, including its swallowing except."""
    try:
        rec = nemesis_errors.make_recorder(
            namespace, lambda: get_data_manager().connect(namespace), CODES)
        return rec("E-RBAC-002", context={"endpoint": "module_x_y", "method": "POST"})
    except Exception:                                           # noqa: BLE001
        return None


def _rows():
    c = get_data_manager().connect("dashboard")
    try:
        return c.execute("SELECT COUNT(*) FROM error_occurrences "
                         "WHERE code='E-RBAC-002'").fetchone()[0]
    finally:
        c.close()


check("CONTROL: the BROKEN namespace writes NOTHING and swallows the error",
      _record_with("core") is None and _rows() == 0)
_before = _rows()
_ret = _record_with(ns)
check("the SHIPPED namespace writes a row", _ret is not None and _rows() > _before,
      (_ret, _rows()))

print("\n-- 3. SYSTEMIC: no OTHER recorder names a non-existent namespace --")
import pathlib                                                  # noqa: E402
pat = re.compile(r'make_recorder\(\s*"([A-Za-z_./]+)"\s*,\s*lambda:\s*'
                 r'get_data_manager\(\)\.connect\(\s*"([A-Za-z_./]+)"\s*\)', re.S)
bad = []
for p in pathlib.Path("/opt/nemesis").rglob("*.py"):
    if ".git" in str(p) or "__pycache__" in str(p) or "test_" in p.name:
        continue
    try:
        txt = p.read_text()
    except Exception:                                           # noqa: BLE001
        continue
    for mm in pat.finditer(txt):
        if mm.group(2) not in dm_mod.NAMESPACES:
            bad.append((str(p), mm.group(2)))
check("every get_data_manager-based recorder names a real namespace", bad == [], bad)
# Scope stated rather than implied: recorders using another connection factory
# (data_manager's own _raw_connect, watchdog's _db_connect) are NOT covered here —
# they never call connect(), so this bug shape cannot occur in them.

print("\n-- 4. MUTATION: prove §1 catches a revert to 'core' --")
mutated = _SRC.replace('"%s", lambda: get_data_manager().connect("%s")' % (label, ns),
                       '"core", lambda: get_data_manager().connect("core")')
check("CONTROL: the mutation actually applied", mutated != _SRC)
mm2 = re.search(r'_rbac_recorder = nemesis_errors\.make_recorder\(\s*'
                r'"([a-z_]+)",\s*lambda: get_data_manager\(\)\.connect\("([a-z_]+)"\)',
                mutated)
check("MUTANT (reverted to 'core') is DETECTED by §1's namespace check",
      mm2 is not None and mm2.group(2) not in dm_mod.NAMESPACES, mm2 and mm2.group(2))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
