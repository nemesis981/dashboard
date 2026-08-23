#!/usr/bin/env python3
"""A disabled module cannot write -- in this process or any other.

Guards the 2026-08-23 quiescence fix. Before it, "disabled" was a dashboard-process
display state: `stop()` was a no-op in 6 of 10 modules, Flask routes kept serving 200s
after unload, and three SEPARATE processes wrote through disabled modules because they
import the functions directly and never run modules_loader.

Three surfaces, three sections below. The CONFORMANCE section is the one that keeps this
true over time: it statically finds every public write function in every non-required
module and fails if one is not gated, so a new ungated write cannot land unnoticed.

No network. Throwaway DB. Nothing live is touched.
"""
import ast
import glob
import json
import os
import re
import sqlite3
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
_tmp = tempfile.mkdtemp(prefix="gate-")
_db = os.path.join(_tmp, "alerts.db")
os.environ["NEMESIS_DB_PATH"] = _db

import modules                                              # noqa: E402
modules.set_shared_db_path(_db)
from modules import gate                                    # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def _set_enabled(name, enabled):
    c = sqlite3.connect(_db)
    c.execute("CREATE TABLE IF NOT EXISTS modules_enabled ("
              "module_name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, actor TEXT)")
    c.execute("INSERT OR REPLACE INTO modules_enabled (module_name, enabled) VALUES (?,?)",
              (name, 1 if enabled else 0))
    c.commit(); c.close()
    gate.invalidate(name)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 1. the gate itself ==")

_set_enabled("tickets", True)
check("enabled module reports enabled", gate.is_enabled("tickets") is True)
_set_enabled("tickets", False)
check("disabled module reports disabled", gate.is_enabled("tickets") is False)

calls = []


@gate.write_gated("tickets")
def fake_write(x):
    calls.append(x)
    return "wrote"


_set_enabled("tickets", False)
try:
    fake_write(1)
    check("a gated write is REFUSED when disabled", False, "it ran")
except gate.ModuleDisabled:
    check("a gated write is REFUSED when disabled", True)
check("  ...and the function body never ran", len(calls) == 0)

# CONTROL: the same call succeeds when enabled -- proving the gate is the reason
# it was refused, not something incidental about the harness.
_set_enabled("tickets", True)
check("CONTROL: the SAME call succeeds when enabled", fake_write(1) == "wrote")
check("  ...and the body did run", len(calls) == 1)

# Refusal must RAISE, never return a legal-looking value: open_ticket returns an
# int where 0 already means "failed".
_set_enabled("tickets", False)
try:
    r = fake_write(2)
    check("refusal never returns a value", False, "returned %r" % (r,))
except gate.ModuleDisabled:
    check("refusal RAISES rather than returning a legal-looking value", True)

# FAIL CLOSED: enablement unreadable -> refuse, and say which.
_saved = gate._db_path
gate._db_path = lambda: "/nonexistent/nope/alerts.db"
gate.invalidate()
try:
    gate.require_enabled("tickets")
    check("unreadable enablement fails CLOSED", False, "it allowed the write")
except gate.EnablementUnknown:
    check("unreadable enablement fails CLOSED (EnablementUnknown)", True)
except gate.ModuleDisabled:
    check("unreadable enablement fails closed but is not distinguishable", False)
gate._db_path = _saved
gate.invalidate()
check("EnablementUnknown is a ModuleDisabled (one refusal path, two diagnoses)",
      issubclass(gate.EnablementUnknown, gate.ModuleDisabled))


# ═══════════════════════════════════════════════════════════════════════
print("\n== 2. CROSS-PROCESS shape: a direct import, no loader involved ==")

# This is exactly what watchdog / hw_monitor / nemesis_connectivity_notify do:
# import the write function directly. No modules_loader, no _loaded state.
from modules.tickets.module import open_ticket                # noqa: E402
from modules.community_queue.module import add_to_queue       # noqa: E402

check("open_ticket is gated at import time",
      getattr(open_ticket, "__nemesis_gated__", None) == "tickets")
check("add_to_queue is gated at import time",
      getattr(add_to_queue, "__nemesis_gated__", None) == "community_queue")

_set_enabled("tickets", False)
try:
    open_ticket(title="test data 2026-08-23 — write gate", body="x")
    check("a disabled module refuses a DIRECT import write", False, "it wrote")
except gate.ModuleDisabled:
    check("a disabled module refuses a DIRECT import write (the cross-process hole)", True)

_set_enabled("community_queue", False)
try:
    add_to_queue("test", "example.com", "test data 2026-08-23", 1, 1, "", "", {})
    check("community_queue refuses too", False, "it wrote")
except gate.ModuleDisabled:
    check("community_queue refuses too", True)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 3. ROUTES stop serving when the module is disabled ==")

from flask import Flask                                       # noqa: E402
import modules_loader as ML                                   # noqa: E402

app = Flask(__name__)
ML._app = app
served = []


class _Fake:
    def _api_write(self):
        served.append(1)
        return "wrote"


inst = _Fake()
app.add_url_rule("/gate/write", "module_faked__api_write",
                 ML._guard_view("faked", inst._api_write), methods=["POST"])
ML._loaded["faked"] = inst
c = app.test_client()

r = c.post("/gate/write")
check("loaded module serves normally", r.status_code == 200 and len(served) == 1)

ML._unload_module("faked")
r = c.post("/gate/write")
check("disabled module's route returns 503", r.status_code == 503, str(r.status_code))
check("  ...and the handler did NOT run", len(served) == 1)
check("  ...and the body says why", b"disabled" in r.data)

# CONTROL: re-loading restores service, so 503 tracks state rather than being sticky.
ML._loaded["faked"] = inst
r = c.post("/gate/write")
check("CONTROL: re-enabling restores 200", r.status_code == 200 and len(served) == 2)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 4. CONFORMANCE: a new ungated write cannot land unnoticed ==")

WRITE_SQL = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE)\b", re.I)
_WRITE_CALLS = ("execute", "executemany", "upsert", "increment_counter",
                "next_sequence")
_REPO = "/opt/nemesis"
_MAX_HOPS = 3
_memo = {}


def _direct_write(node):
    """Does this function body execute a write ITSELF?"""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            nm = getattr(sub.func, "attr", None) or getattr(sub.func, "id", None)
            if nm in _WRITE_CALLS:
                if nm != "execute" and nm != "executemany":
                    return True
                for arg in sub.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
                            and WRITE_SQL.search(arg.value):
                        return True
    return False


def _called_names(node):
    """Every callable name this function invokes, bare or dotted-last."""
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            nm = getattr(sub.func, "attr", None) or getattr(sub.func, "id", None)
            if nm:
                out.add(nm)
    return out


def _resolve_import(src_path, name):
    """Best-effort: which repo file defines `name` for this module?

    Handles `from x.y import name` and `import x.y` + `x.y.name(...)`. Anything
    that does not resolve to a file INSIDE this repo is stdlib or third-party and
    cannot write our database except through sqlite3 directly -- which
    `_direct_write` already catches at the call site.
    """
    try:
        tree = ast.parse(open(src_path, encoding="utf-8").read())
    except Exception:
        return None
    mods = []
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module:
            if any(a.name == name or a.asname == name for a in n.names):
                mods.append(n.module)
        elif isinstance(n, ast.Import):
            for a in n.names:
                mods.append(a.name)
    for m in mods:
        rel = m.replace(".", os.sep) + ".py"
        for base in (_REPO, os.path.join(_REPO, "alert_manager"),
                     os.path.join(_REPO, "core"), os.path.dirname(src_path)):
            cand = os.path.join(base, rel)
            if os.path.exists(cand):
                return cand
            cand = os.path.join(base, os.path.basename(rel))
            if os.path.exists(cand):
                return cand
    return None


def _writes(node, src_path, hops=0):
    """Does this function write, DIRECTLY OR THROUGH A HELPER?

    ⚠ WHY INDIRECTION IS RESOLVED (added 2026-08-23, after Window 3 found this).
    The first version matched only a direct `.execute("INSERT ...")`. A function
    that writes through a helper -- `notify.notify()` -> `enqueue()` ->
    `INSERT INTO notify_queue` -- was reported as NOT writing.

    That was not merely incomplete, it made this suite's own promise FALSE. The
    required-module skip below says that if `required` is ever removed, an
    ungated write "lands in the loop below on the next run and this test fails
    until it is gated". For a helper-mediated write it would instead be scanned,
    found clean, and pass -- protection reading as present while absent, which is
    the exact shape the gate's docstring argues against for decorators.

    Resolution is structural, not a maintained list of known write-helpers: a
    list is the same forget-to-update failure the gate rejected. Calls are
    followed through module-level functions, across repo files, to `_MAX_HOPS`.
    Unresolvable calls are stdlib/third-party, which cannot reach our database
    except via sqlite3 at the call site -- already caught directly.
    """
    if _direct_write(node):
        return True
    if hops >= _MAX_HOPS:
        return False
    key = (src_path, getattr(node, "name", None), hops)
    if key in _memo:
        return _memo[key]
    _memo[key] = False                     # cycle guard: recursion is not a write

    try:
        tree = ast.parse(open(src_path, encoding="utf-8").read())
    except Exception:
        return False
    local = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

    result = False
    for called in _called_names(node):
        if called in local and local[called] is not node:
            if _writes(local[called], src_path, hops + 1):
                result = True
                break
            continue
        target = _resolve_import(src_path, called)
        if target and target != src_path:
            try:
                ttree = ast.parse(open(target, encoding="utf-8").read())
            except Exception:
                continue
            for tn in ttree.body:
                if isinstance(tn, ast.FunctionDef) and tn.name == called:
                    if _writes(tn, target, hops + 1):
                        result = True
                    break
        if result:
            break
    _memo[key] = result
    return result


problems = []
for man_path in sorted(glob.glob("/opt/nemesis/modules/*/manifest.json")):
    mod = os.path.basename(os.path.dirname(man_path))
    man = json.load(open(man_path, encoding="utf-8"))
    if man.get("required"):
        # Required modules cannot be disabled (modules_loader.set_enabled refuses),
        # so a gate there would add a failure mode for zero benefit. Deliberate and
        # scoped -- if `required` is ever removed from a module, it lands in the
        # loop below on the next run and this test fails until it is gated.
        #
        # ⚠ IF YOU ARE HERE BECAUSE YOU JUST DROPPED `required` FROM A MANIFEST:
        # that one-word edit silently widens what must be gated. This test is now
        # what tells you so -- it follows writes through helpers and across files
        # (since 2026-08-23), so a module that "does not appear to write" may
        # still be caught. Declare the writes in `write_functions`, or record an
        # exemption WITH A REASON in `write_functions_exempt`. Do not delete the
        # finding to make this green.
        continue
    src_path = os.path.join(os.path.dirname(man_path), "module.py")
    if not os.path.exists(src_path):
        continue
    src = open(src_path, encoding="utf-8").read()
    declared = set(man.get("write_functions", []))
    # An EXEMPTION is a write that is deliberately not gated, and it must carry a
    # reason IN THE MANIFEST. This is not the "list someone forgets to update"
    # failure the gate rejected for decorators: an undeclared, unexempted write
    # still fails this test, so the only way to opt out is to write down why, in
    # a file that is reviewed. Silence is not an option; a sentence is.
    exempt = man.get("write_functions_exempt", {}) or {}
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_") \
                and _writes(node, src_path):
            if node.name in exempt:
                if not str(exempt[node.name]).strip():
                    problems.append("%s.%s is exempt with NO reason recorded"
                                    % (mod, node.name))
                continue
            if node.name not in declared:
                problems.append("%s.%s writes but is not in manifest "
                                "write_functions (or exempt with a reason)"
                                % (mod, node.name))

check("every public write fn in every NON-REQUIRED module is declared",
      not problems, "; ".join(problems))

# CONTROLS: "no problems" must be distinguishable from a detector that finds
# nothing at all -- and, since 2026-08-23, from one that finds only DIRECT writes.
_here = os.path.abspath(__file__)
_probe = ast.parse("def w():\n    conn.execute('INSERT INTO t VALUES (1)')\n").body[0]
check("CONTROL: detects a direct write", _writes(_probe, _here))
_probe2 = ast.parse("def r():\n    conn.execute('SELECT 1')\n").body[0]
check("CONTROL: does NOT flag a read", not _writes(_probe2, _here))

# THE REGRESSION Window 3 found: a write reached through a helper.
#
# PRIMARY CONTROL IS SYNTHETIC AND SELF-CONTAINED. An earlier version used
# alert_manager/notify.py as the only positive case, which quietly made three
# symbols in a file another window actively edits (`notify`, `enqueue`, `route`)
# load-bearing for this suite. Window 3 flagged it. The worst of the three
# failure modes was not a red test: if enqueue's INSERT ever moved behind
# another helper, the control would keep PASSING while no longer exercising
# indirection at all -- passing for the wrong reason, which is the exact defect
# this control exists to catch.
_fixdir = tempfile.mkdtemp(prefix="gate-fixture-")
with open(os.path.join(_fixdir, "helper_mod.py"), "w") as fh:
    fh.write("def _deep():\n    conn.execute('INSERT INTO t VALUES (1)')\n\n"
             "def writes_via_helper():\n    _deep()\n\n"
             "def writes_nothing():\n    conn.execute('SELECT 1')\n")
with open(os.path.join(_fixdir, "caller_mod.py"), "w") as fh:
    fh.write("from helper_mod import writes_via_helper\n\n"
             "def public_entry():\n    writes_via_helper()\n")

_hpath = os.path.join(_fixdir, "helper_mod.py")
_htree = ast.parse(open(_hpath).read())
_hfns = {n.name: n for n in _htree.body if isinstance(n, ast.FunctionDef)}

check("CONTROL: a write one hop away is detected",
      _writes(_hfns["writes_via_helper"], _hpath))
# The pin that stops this passing for the wrong reason: it must be detected
# BECAUSE of indirection, not because it writes directly.
check("CONTROL: ...and it does NOT write directly (indirection really exercised)",
      not _direct_write(_hfns["writes_via_helper"]))
check("CONTROL: a non-writing sibling is not flagged",
      not _writes(_hfns["writes_nothing"], _hpath))

# Real-world CORROBORATION, deliberately non-load-bearing. notify.py belongs to
# another window's active work; if its shape changes this reports that the
# corroboration lapsed rather than failing or silently passing.
#
# ⚠ SOFT DEPENDENCY ON alert_manager/notify.py: `notify` reaching `enqueue`,
# `enqueue` containing a literal INSERT, and `route` writing nothing. Treated as
# a contract by agreement with Window 3 (2026-08-23), but this suite does not
# BREAK if it changes -- see the skip below.
_notify_src = "/opt/nemesis/alert_manager/notify.py"
if os.path.exists(_notify_src):
    _nfns = {n.name: n for n in
             ast.parse(open(_notify_src, encoding="utf-8").read()).body
             if isinstance(n, ast.FunctionDef)}
    if "notify" in _nfns and "route" in _nfns:
        _n_indirect = (_writes(_nfns["notify"], _notify_src)
                       and not _direct_write(_nfns["notify"]))
        if _n_indirect:
            check("corroboration: the real notify() path is detected via indirection",
                  True)
            check("corroboration: route() writes nothing", 
                  not _writes(_nfns["route"], _notify_src))
        else:
            print("  [SKIP] notify.py corroboration lapsed — its shape changed "
                  "(notify no longer reaches a write through a helper). The "
                  "synthetic control above still covers this; tell Window 3.")
    else:
        print("  [SKIP] notify.py corroboration lapsed — expected symbols absent.")

# And the declarations must name real functions.
for man_path in sorted(glob.glob("/opt/nemesis/modules/*/manifest.json")):
    man = json.load(open(man_path, encoding="utf-8"))
    mod = os.path.basename(os.path.dirname(man_path))
    src_path = os.path.join(os.path.dirname(man_path), "module.py")
    if not man.get("write_functions") or not os.path.exists(src_path):
        continue
    names = {n.name for n in ast.parse(open(src_path, encoding="utf-8").read()).body
             if isinstance(n, ast.FunctionDef)}
    ghosts = [f for f in man["write_functions"] if f not in names]
    check("%s declares no phantom write functions" % mod, not ghosts, str(ghosts))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
