#!/usr/bin/env python3
"""The dependency_preflight diagnostic — and proof its canary measures.

Run: python3 diagnostics/test_dependency_preflight.py   (exit 0 = all pass)

WHAT THIS CHECK IS FOR. Python shells out to a binary that is not installed and
nothing fails until that exact path runs — which for a recovery or export path is
the worst possible moment. The shared `_run` helper maps FileNotFoundError to
rc=127 and a string, so a missing tool reaches the caller looking like a command
that ran and failed.

THE HARD PART IS NOT DETECTION, IT IS CLASSIFICATION. A naive scan finds ~33
invoked binaries here and calls a third of them absent. Those absences are almost
all correct: Windows-agent tools on a Linux appliance, optional VPN plugins with
an explicit skip-if-absent contract, and test-only binaries. A check that reports
them as faults is one nobody reads twice, so most of these tests are about NOT
reporting things.

REGRESSION GUARDED HERE. The first run reported `dualuse (2 call sites)` as a
missing required dependency — a binary that exists only inside this module's own
canary fixture. The module scans the whole tree INCLUDING its own source, so a
literal fixture is picked up as a real call site. Fixtures are now assembled at
runtime. `schema_drift.py` hit the identical trap while scanning for DDL, so it
is a property of any diagnostic that greps the tree, not a one-off.

NO EXECUTION. Source is parsed and PATH is queried; nothing is run.
"""
import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

_SRC_PATH = os.path.join(_HERE, "dependency_preflight.py")
_spec = importlib.util.spec_from_file_location("dp_under_test", _SRC_PATH)
dp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dp)

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


print("\n-- the canary passes on a sound classifier --")
ok, detail = dp._canary()
check("canary reports ok", ok, detail)

print("\n-- classification distinguishes all four categories --")
CASES = [
    ("systemctl", "dashboard.py", dp.CAT_REQUIRED),
    ("nft", "alert_manager/firewall.py", dp.CAT_REQUIRED),
    ("schtasks", "dashboard.py", dp.CAT_PLATFORM),
    ("powershell", "nemesis_agent/x.py", dp.CAT_PLATFORM),
    ("mullvad", "dashboard.py", dp.CAT_OPTIONAL),
    ("protonvpn-cli", "dashboard.py", dp.CAT_OPTIONAL),
    ("nmap", "diagnostics/test_thing.py", dp.CAT_TEST),
    ("nmap", "windows_agent/setup.py", dp.CAT_TEST),
]
for b, path, want in CASES:
    got = dp.classify(b, path)
    check("%-14s in %-30s -> %s" % (b, path, want), got == want, got)

print("\n-- CONTROL: not everything is one category --")
cats = {dp.classify(b, p) for b, p, _ in CASES}
check("more than one category is reachable", len(cats) > 1, cats)
check("all four are reachable",
      cats == {dp.CAT_REQUIRED, dp.CAT_PLATFORM, dp.CAT_OPTIONAL, dp.CAT_TEST}, cats)

print("\n-- a MISSING required binary is reported --")
ev = dp.evaluate({"gone": {"category": dp.CAT_REQUIRED, "sites": 2}},
                 which=lambda n: None)
check("absent required binary is a finding", bool(ev["missing_required"]), ev)
check("...with its call-site count", ev["missing_required"][0][1] == 2, ev)

print("\n-- CONTROL: a PRESENT required binary is not reported --")
ev = dp.evaluate({"here": {"category": dp.CAT_REQUIRED, "sites": 1}},
                 which=lambda n: "/usr/bin/here")
check("present required binary is clean", not ev["missing_required"], ev)
check("...and is counted as present", ev["present"] == 1, ev)

print("\n-- absent OPTIONAL / PLATFORM / TEST binaries are NOT faults --")
ev = dp.evaluate({"vpn": {"category": dp.CAT_OPTIONAL, "sites": 1},
                  "win": {"category": dp.CAT_PLATFORM, "sites": 1},
                  "tst": {"category": dp.CAT_TEST, "sites": 1}},
                 which=lambda n: None)
check("none are reported as missing dependencies", not ev["missing_required"], ev)
check("but all three are COUNTED, not dropped",
      set(ev["absent_benign"]) == {dp.CAT_OPTIONAL, dp.CAT_PLATFORM, dp.CAT_TEST},
      ev["absent_benign"])

print("\n-- strongest category wins across call sites --")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "sub"), exist_ok=True)
    with open(os.path.join(d, "test_x.py"), "w") as fh:
        fh.write(dp._fixture_call("shared"))
    with open(os.path.join(d, "sub", "real.py"), "w") as fh:
        fh.write(dp._fixture_call("shared"))
    got = dp.scan(d)
    check("a binary used by real code AND a test is REQUIRED",
          got.get("shared", {}).get("category") == dp.CAT_REQUIRED, got)
    check("call sites are counted across files",
          got.get("shared", {}).get("sites") == 2, got)

print("\n-- CONTROL: a test-only binary stays test-only --")
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "test_only.py"), "w") as fh:
        fh.write(dp._fixture_call("onlytest"))
    got = dp.scan(d)
    check("test-only binary is not promoted to required",
          got.get("onlytest", {}).get("category") == dp.CAT_TEST, got)

print("\n-- absolute paths are checked on disk, not on PATH --")
check("an existing absolute path is present",
      dp.present("/bin/sh", which=lambda n: None))
check("a non-existent absolute path is absent even if PATH would answer",
      not dp.present("/definitely/not/here/xyz", which=lambda n: "/usr/bin/x"))

print("\n-- REGRESSION: the module must not scan its own fixtures --")
# First run reported `dualuse (2 call sites)` — a binary that exists only inside
# this module's canary. Fixtures are assembled at runtime so the literal never
# appears in the source the scanner reads.
own = dp.scan(dp._repo_root())
for fake in ("dualuse", "shared", "onlytest"):
    check("fixture binary %r is not picked up from source" % fake,
          fake not in own, sorted(own)[:8])
check("CONTROL: the scan DID find real binaries", len(own) > 10, len(own))
check("...including a known real one", "systemctl" in own, sorted(own)[:8])

print("\n-- the produced result obeys the diagnostics contract --")
res = dp.run()
check("status is ok/warn/error/info (T3)",
      res["status"] in ("ok", "warn", "error", "info"), res["status"])
check("keys are EXACTLY the six contract keys (T5)",
      set(res) == {"id", "name", "icon", "status", "summary", "output"}, sorted(res))
check("every value is a string", all(isinstance(v, str) for v in res.values()))
check("META has all three description tiers (T2)",
      set(dp.META["descriptions"]) == {"beginner", "intermediate", "pro"})
check("META id is URL/DOM safe (T10)",
      dp.META["id"].replace("_", "").isalnum() and dp.META["id"].islower())

print("\n-- MUTATION: the canary must CATCH each injected defect --")
SRC = open(_SRC_PATH, encoding="utf-8").read()

MUTATIONS = [
    ("everything classified REQUIRED (floods the report)",
     "    if name in _WINDOWS_BINARIES:\n        return CAT_PLATFORM",
     "    if False:\n        return CAT_PLATFORM"),
    ("everything classified OPTIONAL (hides real gaps)",
     "    return CAT_REQUIRED\n",
     "    return CAT_OPTIONAL\n"),
    ("missing-required detection disabled",
     '        if info["category"] == CAT_REQUIRED:\n            missing_required.append((b, info["sites"]))',
     '        if False:\n            missing_required.append((b, info["sites"]))'),
    ("present binaries reported as missing",
     "        if present(b, which=which):\n            ok_count += 1\n            continue",
     "        if False:\n            ok_count += 1\n            continue"),
    ("weakest category wins (a real dependency hides behind a test)",
     "                    if strength[cat] > strength[cur[\"category\"]]:",
     "                    if strength[cat] < strength[cur[\"category\"]]:"),
    ("absolute paths resolved via PATH instead of the filesystem",
     '    if binary.startswith("/"):\n        return os.path.exists(binary) and os.access(binary, os.X_OK)',
     '    if False:\n        return os.path.exists(binary) and os.access(binary, os.X_OK)'),
]

for label, old, new in MUTATIONS:
    if old not in SRC:
        check("MUTATION anchor present: %s" % label, False,
              "anchor not found -- this TEST is stale, not the code")
        continue
    path = tempfile.mktemp(suffix=".py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(SRC.replace(old, new, 1))
    caught = False
    try:
        s2 = importlib.util.spec_from_file_location("dp_mutant", path)
        m2 = importlib.util.module_from_spec(s2)
        s2.loader.exec_module(m2)
        ok2, _d = m2._canary()
        caught = not ok2
    except Exception:
        caught = True
    finally:
        os.unlink(path)
    check("canary catches: %s" % label, caught,
          "the mutated module's canary still reported OK — it is not measuring")

print("\n-- a failed canary SUPPRESSES the verdict --")
path = tempfile.mktemp(suffix=".py")
with open(path, "w", encoding="utf-8") as fh:
    fh.write(SRC.replace('def _canary():\n    """Returns (ok, detail). Never raises. Runs on EVERY invocation."""',
                         'def _canary():\n    """stub"""\n    return False, "forced"', 1))
try:
    s3 = importlib.util.spec_from_file_location("dp_broken", path)
    m3 = importlib.util.module_from_spec(s3)
    s3.loader.exec_module(m3)
    r3 = m3.run()
    check("a failed canary yields status=error", r3["status"] == "error", r3["status"])
    check("...and says dependencies were NOT checked",
          "NOT checked" in r3["summary"], r3["summary"])
    check("...and does not claim everything is present",
          "All required" not in r3["summary"], r3["summary"])
finally:
    os.unlink(path)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
