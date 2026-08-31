"""Security-telemetry disclosure gate — every path, both directions.

Run: python3 nemesis_agent/test_consent.py

⚠ THIS SUITE WAS INVERTED ON 2026-08-31 AND THAT IS THE POINT.
It used to assert "absence => collect nothing". The model changed to
disclosure-and-toggle (on by default, individually switchable off), so absence now
means COLLECT. The dangerous direction inverted with it: under opt-in the risk was
a bug turning into permission; under default-on the risk is a user's explicit OFF
being lost and collection silently resuming.

So the load-bearing assertions here are:
  * a stored OFF survives being read back, and survives `revoke()`
  * `revoke()` leaves a TOMBSTONE and does not delete the file — the v1 behaviour
    deleted it, which made "never configured" and "actively refused" identical
  * a CORRUPT record collects NOTHING, because a mangled refusal must never be
    read as permission — the one place default-on does not apply

Every negative is paired with a positive proving the gate can answer both ways. A
suite of all-True assertions would pass against `return True`, which is the
can-only-say-one-thing defect this repo keeps finding.

ASSERTION COUNT IS FIXED and self-asserted at the end.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config                       # noqa: E402
import consent                      # noqa: E402

EXPECTED_CHECKS = 45
passed = failed = 0
_tmp = tempfile.mkdtemp(prefix="consent-test-")
config.CONF_PATH = os.path.join(_tmp, "nemesis_agent.conf")


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name
          + ("" if ok or not detail else "  (%s)" % detail))
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
    os.makedirs(os.path.dirname(consent.state_path()), exist_ok=True)
    with open(consent.state_path(), "w", encoding="utf-8") as f:
        f.write(text)


C = consent.ITEM_CONNECTIONS

print("\nDEFAULT-ON: an unconfigured device collects")
clear()
check("absent record -> connections allowed", consent.collection_allowed(C) is True)
check("absent record -> every item allowed",
      all(consent.enabled_items().values()), consent.enabled_items())
check("absent record -> consent_version is the CURRENT disclosure",
      consent.consent_version() == consent.DISCLOSURE_VERSION)
check("absent record -> disclosure counts as current (nothing to re-show)",
      consent.disclosure_is_current() is True)
check("absent record -> status says not configured",
      consent.status()["configured"] is False)

print("\n⭐ AN EXPLICIT OFF IS DURABLE (the failure mode of this model)")
clear()
consent.set_enabled(C, False, device_id="dev-abc")
check("after set_enabled(False) -> that item is DENIED",
      consent.collection_allowed(C) is False)
check("⭐ the record FILE STILL EXISTS (tombstone, not deletion)",
      os.path.exists(consent.state_path()))
check("⭐ re-reading still says DENIED (survives a fresh read)",
      consent.collection_allowed(C) is False)
check("other items are UNAFFECTED and still on",
      consent.collection_allowed(consent.ITEM_USB_EVENTS) is True)
check("status reports configured", consent.status()["configured"] is True)
check("stored telemetry records the false explicitly",
      json.load(open(consent.state_path()))["telemetry"][C] is False)

print("\n⭐ revoke() TOMBSTONES rather than deleting (v1 deleted — the whole bug)")
clear()
consent.set_enabled(C, True, device_id="dev-abc")
res = consent.revoke(device_id="dev-abc")
check("revoke() reports revoked", res["revoked"] is True)
check("revoke() asks for the server-side purge", res["purge_required"] is True)
check("⭐ revoke() left the file in place", os.path.exists(consent.state_path()))
check("⭐ connections DENIED after revoke", consent.collection_allowed(C) is False)
check("revoke() did not disturb other items",
      consent.collection_allowed(consent.ITEM_LOGIN_EVENTS) is True)

print("\nTURNING BACK ON works (a gate that can only close is not a toggle)")
consent.set_enabled(C, True, device_id="dev-abc")
check("re-enabled -> allowed again", consent.collection_allowed(C) is True)

print("\nPER-ITEM independence")
clear()
for item in consent.ITEM_KEYS:
    consent.set_enabled(item, False, device_id="dev-abc")
check("all six can be individually turned off",
      not any(consent.enabled_items().values()), consent.enabled_items())
consent.set_enabled(consent.ITEM_USB_EVENTS, True, device_id="dev-abc")
check("turning one back on affects only that one",
      consent.enabled_items() == {consent.ITEM_CONNECTIONS: False,
                                  consent.ITEM_TOP_PROCESSES: False,
                                  consent.ITEM_LOGIN_EVENTS: False,
                                  consent.ITEM_USB_EVENTS: True,
                                  consent.ITEM_NEW_FILES: False,
                                  consent.ITEM_BEHAVIORAL: False},
      consent.enabled_items())

print("\n⭐ BEHAVIOURAL IS INDEPENDENT OF CONNECTIONS (the 2026-08-31 split)")
# Until the split, behavioural monitoring rode the connections gate: agent.py
# called collection_allowed() with no argument in three places. Switching off
# network connections silently stopped Sysmon/Falco too. These two assertions are
# the split -- if the default ever comes back, they fail.
clear()
consent.set_enabled(consent.ITEM_CONNECTIONS, False, device_id="dev-abc")
check("connections OFF -> behavioural still ON",
      consent.collection_allowed(consent.ITEM_BEHAVIORAL) is True)
clear()
consent.set_enabled(consent.ITEM_BEHAVIORAL, False, device_id="dev-abc")
check("behavioural OFF -> connections still ON",
      consent.collection_allowed(consent.ITEM_CONNECTIONS) is True)

print("\n⭐ collection_allowed() REQUIRES an item -- no silent wrong-gate answer")
_bare_ok = False
try:
    consent.collection_allowed()          # type: ignore[call-arg]
except TypeError:
    _bare_ok = True
check("calling with no item raises TypeError rather than guessing", _bare_ok)

print("\n⭐ CORRUPT COLLECTS NOTHING — the one place default-on does not apply")
for label, raw in (("empty file", ""),
                   ("malformed JSON", "{not json"),
                   ("JSON list", "[]"),
                   ("bare string", '"yes"'),
                   ("unknown schema", json.dumps({"record_schema": 99})),
                   ("telemetry not an object",
                    json.dumps({"record_schema": 2, "telemetry": "all"})),
                   ("non-bool item value",
                    json.dumps({"record_schema": 2, "telemetry": {C: "true"}})),
                   ("unknown item key",
                    json.dumps({"record_schema": 2, "telemetry": {"wiretap": True}}))):
    write_raw(raw)
    check("%s -> collects nothing" % label,
          not any(consent.enabled_items().values()), consent.enabled_items())

write_raw("{not json")
check("corrupt -> consent_version None (never stamps under an unknown state)",
      consent.consent_version() is None)
check("corrupt -> disclosure NOT treated as current",
      consent.disclosure_is_current() is False)

print("\nv1 MIGRATION — the old opt-in record still means yes")
write_raw(json.dumps({"record_schema": 1, "granted": True,
                      "disclosure_version": 1,
                      "granted_at": "2026-08-07T12:00:00-0500",
                      "granted_by": "device-user", "device_id": "dev-abc"}))
check("v1 granted:true -> connections allowed", consent.collection_allowed(C) is True)
check("v1 record -> items it never governed take the new default",
      consent.collection_allowed(consent.ITEM_USB_EVENTS) is True)
check("v1 record at an older disclosure -> user is owed the new text",
      consent.disclosure_is_current() is False)
write_raw(json.dumps({"record_schema": 1, "granted": False, "device_id": "d"}))
check("v1 granted:false -> corrupt, collects nothing (v1 could not express a no)",
      not any(consent.enabled_items().values()))

print("\nUNKNOWN ITEMS are denied, never defaulted on")
clear()
check("unknown item name -> False", consent.collection_allowed("wiretap") is False)
check("empty item name -> False", consent.collection_allowed("") is False)

print("\nDISCLOSURE COPY is disclosure, not a prompt")
txt = consent.DISCLOSURE_TEXT
check("says it is on by default", "ON by default" in txt)
check("tells the user how to turn it off", "TURNING IT OFF" in txt)
check("does not ask a yes/no question", "YOUR CHOICE" not in txt and "decline" not in txt)
check("still states what is NOT recorded", "WHAT IS NOT RECORDED" in txt)
check("names all six items", all(lbl in txt for _k, lbl, _d in consent.TELEMETRY_ITEMS))
check("disclosure version was bumped for the rewrite", consent.DISCLOSURE_VERSION == 2)

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
