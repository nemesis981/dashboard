#!/usr/bin/env python3
"""The agent_enrollment_integrity diagnostic — and proof its canary measures.

Run: python3 diagnostics/test_agent_enrollment_integrity.py  (exit 0 = all pass)

WHAT THIS CHECK IS FOR. `agent_devices` accumulates rows that look fine one at a
time and contradict each other in aggregate: one physical machine approved
several times (each counting against the licence), several approved rows claiming
one address (so acting on "the" device can act on the wrong one), and terminal
rows with no timestamp that can never be aged out.

THE RULE 8 SECTION IS NOT DECORATION. This is the diagnostic with the richest
supply of exactly what must not leave the box — device names, tailnet addresses,
hardware fingerprints — and two facts make that dangerous: `redact.py` scrubs
known secrets but NOT addresses or hostnames, and `/api/diagnostics/submit` mails
the finished report to an external address. So the check reports group sizes and
opaque tags, and the tests below assert no real identifier reaches the output.

THE LEAK TEST CARRIES ITS OWN CONTROL, deliberately. The first attempt at it
passed against an EMPTY string, because the check had not been registered yet and
`run_check` returned "Unknown check". A leak test over no output is vacuous and
looks exactly like a clean one — so it now asserts there is something to leak
before asserting nothing leaked.

NO WRITES. The database is opened read-only; the analysis is pure.
"""
import importlib.util
import os
import re
import sqlite3
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

_SRC_PATH = os.path.join(_HERE, "agent_enrollment_integrity.py")
_spec = importlib.util.spec_from_file_location("aei_under_test", _SRC_PATH)
aei = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aei)

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


def dev(**kw):
    base = {"device_id": "d", "device_name": "n", "ip_address": "a",
            "hw_stable_id": "", "enrollment_status": "approved",
            "public_key": "k", "agent_last_seen": "2026-08-22T00:00:00",
            "revoked_at": None, "uninstalled_at": None}
    base.update(kw)
    return base


print("\n-- the canary passes on a sound analyser --")
ok, detail = aei._canary()
check("canary reports ok", ok, detail)

print("\n-- CONTROL: a healthy register reports nothing --")
good = aei.analyse([dev(device_id="1", device_name="a", ip_address="ip1", hw_stable_id="fp1"),
                    dev(device_id="2", device_name="b", ip_address="ip2", hw_stable_id="fp2")])
for k in ("dup_fingerprint", "dup_address", "dup_name", "no_key",
          "never_seen", "undated_terminal"):
    check("healthy register: no %s" % k, not good[k], good[k])
check("healthy devices counted as active", good["active"] == 2)

print("\n-- each contradiction is detected --")
check("duplicate hardware fingerprint",
      len(aei.analyse([dev(device_id="1", hw_stable_id="s"),
                       dev(device_id="2", hw_stable_id="s")])["dup_fingerprint"]) == 1)
check("address collision",
      len(aei.analyse([dev(device_id="1", ip_address="s"),
                       dev(device_id="2", ip_address="s")])["dup_address"]) == 1)
check("duplicate display name",
      len(aei.analyse([dev(device_id="1", device_name="s"),
                       dev(device_id="2", device_name="s")])["dup_name"]) == 1)
check("approved with no public key",
      bool(aei.analyse([dev(public_key="")])["no_key"]))
check("approved never seen",
      bool(aei.analyse([dev(agent_last_seen=None)])["never_seen"]))
check("revoked with no timestamp",
      bool(aei.analyse([dev(enrollment_status="revoked")])["undated_terminal"]))

print("\n-- CONTROL: a dated terminal row is NOT a finding --")
check("revoked WITH a timestamp is clean",
      not aei.analyse([dev(enrollment_status="revoked",
                           revoked_at="2026-01-01")])["undated_terminal"])
check("uninstalled WITH a timestamp is clean",
      not aei.analyse([dev(enrollment_status="uninstalled",
                           uninstalled_at="2026-01-01")])["undated_terminal"])

print("\n-- retired rows do not collide with their own replacement --")
# Otherwise every rebuild of a machine reports a duplicate forever.
retired = aei.analyse([dev(device_id="1", hw_stable_id="same"),
                       dev(device_id="2", hw_stable_id="same",
                           enrollment_status="uninstalled",
                           uninstalled_at="2026-01-01")])
check("an uninstalled row is not a duplicate of the live one",
      not retired["dup_fingerprint"], retired["dup_fingerprint"])
check("...and it is not counted as active", retired["active"] == 1)
rejected = aei.analyse([dev(device_id="1", ip_address="same"),
                        dev(device_id="2", ip_address="same",
                            enrollment_status="rejected")])
check("a rejected row does not create an address collision",
      not rejected["dup_address"])

print("\n-- MISSING data must not become a duplicate group --")
# Blank fingerprints are common on devices that never reported one; bucketing
# them together would invent a finding out of absence.
blanks = aei.analyse([dev(device_id="1", hw_stable_id=""),
                      dev(device_id="2", hw_stable_id=""),
                      dev(device_id="3", hw_stable_id=None)])
check("blank fingerprints are not grouped", not blanks["dup_fingerprint"], blanks)
check("blank addresses are not grouped",
      not aei.analyse([dev(device_id="1", ip_address=""),
                       dev(device_id="2", ip_address=None)])["dup_address"])

print("\n-- opaque tags stand in for values without revealing them --")
t1, t2 = aei.opaque_tag("192.0.2.5"), aei.opaque_tag("192.0.2.6")
check("different values -> different tags", t1 != t2)
check("same value -> same tag (stable within a run)",
      aei.opaque_tag("192.0.2.5") == t1)
check("the tag does not contain the value", "192" not in t1 and "0.2.5" not in t1)
check("the tag is short and hex", len(t1) == 6 and all(c in "0123456789abcdef" for c in t1))

print("\n-- load_rows RAISES on an unreadable DB, never returns [] --")
try:
    aei.load_rows(os.path.join(tempfile.gettempdir(), "nope-7b2c.db"))
    check("an unreadable database raises", False, "it returned a value")
except Exception:
    check("an unreadable database raises rather than returning []", True)

print("\n-- a DB missing newer columns degrades, it does not fail --")
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "old.db")
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE agent_devices (device_id TEXT PRIMARY KEY, "
              "device_name TEXT, enrollment_status TEXT)")
    c.execute("INSERT INTO agent_devices VALUES ('1','a','approved')")
    c.commit(); c.close()
    rows, missing = aei.load_rows(p)
    check("rows still load from an older schema", len(rows) == 1, rows)
    check("...and the absent columns are REPORTED, not silently skipped",
          "ip_address" in missing and "hw_stable_id" in missing, missing)

print("\n-- the produced result obeys the diagnostics contract --")
res = aei.run()
check("status is ok/warn/error/info (T3)",
      res["status"] in ("ok", "warn", "error", "info"), res["status"])
check("keys are EXACTLY the six contract keys (T5)",
      set(res) == {"id", "name", "icon", "status", "summary", "output"}, sorted(res))
check("every value is a string", all(isinstance(v, str) for v in res.values()))
check("META has all three description tiers (T2)",
      set(aei.META["descriptions"]) == {"beginner", "intermediate", "pro"})
check("META id is URL/DOM safe (T10)",
      aei.META["id"].replace("_", "").isalnum() and aei.META["id"].islower())

print("\n-- RULE 8: no device identifier reaches the output --")
import diagnostics as _pkg
live = _pkg.run_check("agent_enrollment_integrity")
blob = live["output"] + live["summary"]
# CONTROL FIRST. A leak test over an empty string passes trivially — which is
# exactly what happened on the first attempt, before the check was registered.
check("CONTROL: the check is registered and produced real output",
      len(live["output"]) > 200 and "Unknown check" not in live["summary"],
      "%r / %d chars" % (live["summary"], len(live["output"])))
try:
    conn = sqlite3.connect("file:%s?mode=ro" % aei._resolve_db(), uri=True)
    secrets = {str(v).strip() for row in conn.execute(
        "SELECT device_name, ip_address, hw_stable_id, device_id FROM agent_devices")
        for v in row if v and str(v).strip()}
    conn.close()
except Exception:
    secrets = set()
check("CONTROL: there are real identifiers to leak", len(secrets) > 0, len(secrets))
leaked = sorted(s for s in secrets if s in blob)
check("no device name / address / fingerprint / id in the output",
      not leaked, leaked)
check("no IP-shaped string in the output",
      not re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob))

print("\n-- MUTATION: the canary must CATCH each injected defect --")
SRC = open(_SRC_PATH, encoding="utf-8").read()

MUTATIONS = [
    ("duplicate detection disabled (reports clean always)",
     "        return {k: v for k, v in buckets.items() if len(v) > 1}",
     "        return {}"),
    ("EVERY row grouped, including singletons (flags everything)",
     "        return {k: v for k, v in buckets.items() if len(v) > 1}",
     "        return buckets"),
    ("retired rows counted as active (rebuilds report forever)",
     '    active = [r for r in rows if (r.get("enrollment_status") or "") in ACTIVE_STATUSES]',
     "    active = list(rows)"),
    ("blank grouping values bucketed together (absence becomes a duplicate)",
     '            v = (r.get(key) or "").strip()\n            if not v:\n                continue',
     '            v = (r.get(key) or "").strip()\n            if False:\n                continue'),
    ("undated-terminal detection disabled",
     '        and not ((r.get("revoked_at") or "") or (r.get("uninstalled_at") or ""))',
     "        and False"),
    ("the opaque tag leaks the raw value",
     '    h = hashlib.sha256((salt + "|" + str(value)).encode("utf-8", "replace"))\n    return h.hexdigest()[:6]',
     "    return str(value)"),
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
        s2 = importlib.util.spec_from_file_location("aei_mutant", path)
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
    s3 = importlib.util.spec_from_file_location("aei_broken", path)
    m3 = importlib.util.module_from_spec(s3)
    s3.loader.exec_module(m3)
    r3 = m3.run()
    check("a failed canary yields status=error", r3["status"] == "error", r3["status"])
    check("...and says enrollment was NOT checked",
          "NOT checked" in r3["summary"], r3["summary"])
    check("...and does not claim consistency",
          "consistent" not in r3["summary"].lower(), r3["summary"])
finally:
    os.unlink(path)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
