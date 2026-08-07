"""Track C REQUIREMENT 0 — the consent gate fails closed on every path.

Run: python3 nemesis_agent/test_consent.py

The build plan's acceptance is "verified by test, not by inspection", and the
requirement most at risk is that a bug quietly turns into permission. So every
negative case here asserts the gate is CLOSED, and they are paired against a
positive case proving the gate can open at all — a suite where everything
returns False would pass just as happily against `return False`, which is the
same can-only-say-one-thing defect this repo keeps finding.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config                       # noqa: E402
import consent                      # noqa: E402

passed = failed = 0
_tmp = tempfile.mkdtemp(prefix="consent-test-")
config.CONF_PATH = os.path.join(_tmp, "nemesis_agent.conf")


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


def clear():
    try:
        os.remove(consent.state_path())
    except FileNotFoundError:
        pass


def write_raw(text):
    with open(consent.state_path(), "w", encoding="utf-8") as f:
        f.write(text)


def write_rec(**over):
    rec = {"record_schema": 1, "granted": True,
           "disclosure_version": consent.DISCLOSURE_VERSION,
           "granted_at": "2026-08-07T12:00:00-0500",
           "granted_by": "device-user", "device_id": "dev-abc"}
    rec.update(over)
    write_raw(json.dumps(rec))


# ---------------------------------------------------------------- the positive
print("gate OPENS only for valid, current, affirmative consent")
clear()
consent.grant("dev-abc")
check("after grant() -> allowed", consent.collection_allowed() is True)
check("consent_version() returns the current version",
      consent.consent_version() == consent.DISCLOSURE_VERSION)
st = consent.status()
check("status: granted=True, stale=False", st["granted"] is True and st["stale"] is False)
check("status carries the audit fields (req 8)",
      st["granted_at"] and st["granted_by"] == "device-user" and st["device_id"] == "dev-abc")
check("no .tmp left behind (atomic write)",
      not os.path.exists(consent.state_path() + ".tmp"))

# ------------------------------------------------------------- absence is not consent
print("absence is never consent (req 2)")
clear()
check("no file at all -> DENIED", consent.collection_allowed() is False)
check("consent_version() is None when denied", consent.consent_version() is None)
check("status reports not-granted, not-stale", consent.status()["granted"] is False
      and consent.status()["stale"] is False)
write_raw("")
check("empty file -> DENIED", consent.collection_allowed() is False)

# ------------------------------------------------------------------- fail closed
print("every malformed/hostile shape fails CLOSED (req 3)")
write_raw("{not json at all")
check("malformed JSON -> DENIED", consent.collection_allowed() is False)
write_raw('["granted"]')
check("JSON list instead of object -> DENIED", consent.collection_allowed() is False)
write_raw('"granted"')
check("JSON bare string -> DENIED", consent.collection_allowed() is False)
write_raw("null")
check("JSON null -> DENIED", consent.collection_allowed() is False)
write_rec(record_schema=2)
check("unknown record_schema -> DENIED (no forward-guessing)",
      consent.collection_allowed() is False)
write_rec(granted="true")
check('granted as the STRING "true" -> DENIED', consent.collection_allowed() is False)
write_rec(granted=1)
check("granted as int 1 -> DENIED", consent.collection_allowed() is False)
write_rec(granted=False)
check("granted=False -> DENIED", consent.collection_allowed() is False)
r = dict(record_schema=1, granted=True, disclosure_version=consent.DISCLOSURE_VERSION,
         granted_at="x", granted_by="y")
write_raw(json.dumps(r))
check("missing device_id -> DENIED (req 8 unsatisfiable)",
      consent.collection_allowed() is False)
write_rec(device_id="")
check("empty device_id -> DENIED", consent.collection_allowed() is False)
write_rec(disclosure_version="1")
check("disclosure_version as string -> DENIED", consent.collection_allowed() is False)

# unreadable file: the gate must deny, not crash
write_rec()
os.chmod(consent.state_path(), 0o000)
unreadable_denied = consent.collection_allowed() is False
os.chmod(consent.state_path(), 0o600)
check("unreadable file -> DENIED, no exception", unreadable_denied)

# --------------------------------------------------------- version binding (req 6)
print("consent is bound to the disclosure it was given for (req 6)")
write_rec(disclosure_version=consent.DISCLOSURE_VERSION - 1)
check("superseded disclosure_version -> DENIED", consent.collection_allowed() is False)
st = consent.status()
check("  status distinguishes STALE from never-asked",
      st["granted"] is False and st["stale"] is True)
check("  and reports both versions for the re-consent prompt",
      st["disclosure_version"] == consent.DISCLOSURE_VERSION - 1
      and st["current_disclosure_version"] == consent.DISCLOSURE_VERSION)
write_rec(disclosure_version=consent.DISCLOSURE_VERSION + 1)
check("FUTURE disclosure_version -> DENIED (not silently accepted)",
      consent.collection_allowed() is False)

# ------------------------------------------------------------ revocation (req 7)
print("revocation closes the gate and demands a purge (req 7)")
clear()
consent.grant("dev-xyz")
check("granted before revoke", consent.collection_allowed() is True)
out = consent.revoke()
check("revoke() reports success", out["revoked"] is True)
check("  gate is CLOSED immediately after", consent.collection_allowed() is False)
check("  purge_required is signalled with the device_id",
      out["purge_required"] is True and out["device_id"] == "dev-xyz")
out2 = consent.revoke()
check("revoke() on already-revoked is safe and idempotent", out2["revoked"] is True)
check("  and asks for no purge when there was nothing consented",
      out2["purge_required"] is False)

# ------------------------------------------------------------- no implicit grant
print("there is no way to express a pre-ticked box (req 2)")
clear()
raised = False
try:
    consent.grant("")
except ValueError:
    raised = True
check("grant('') raises rather than recording anonymous consent", raised)
raised = False
try:
    consent.grant(None)
except ValueError:
    raised = True
check("grant(None) raises", raised)
check("  and nothing was written", consent.collection_allowed() is False)

# ------------------------------------------------------- disclosure/version pairing
print("disclosure text and version cannot drift apart")
check("DISCLOSURE_TEXT is non-trivial", len(consent.DISCLOSURE_TEXT) > 400)
for phrase in ("WHAT IS RECORDED", "WHAT IS NOT RECORDED", "HOW LONG IT IS KEPT",
               "WHO CAN SEE IT", "YOUR CHOICE"):
    check("  discloses: %s" % phrase, phrase in consent.DISCLOSURE_TEXT)
check("  states the retention period", "30 days" in consent.DISCLOSURE_TEXT)
check("  states that content is NOT recorded",
      "contents of your traffic" in consent.DISCLOSURE_TEXT)
check("  states revocation deletes history",
      "DELETES" in consent.DISCLOSURE_TEXT)

shutil.rmtree(_tmp, ignore_errors=True)
print()
print("%d/%d passed" % (passed, passed + failed))
sys.exit(1 if failed else 0)
