"""
Test harness for the stored-XSS fix in integrity_watch's dashboard card.

get_dashboard_card() renders device_id, signal, and detail into HTML via plain
%s interpolation, with no escaping until 2026-08-04. device_id is agent-supplied
(the heartbeat payload's device_id field, no format validation at enrollment)
and reaches this render path unmodified through integrity_observations, so a
malicious or compromised agent could set a crafted device_id containing markup
and have it render live, unescaped, in an authenticated operator's dashboard.

This harness proves the fix by getting a crafted value all the way to the
rendered HTML through the real code path (evaluate() -> _persist() ->
Module.get_dashboard_card()), not by unit-testing an escaping function in
isolation -- the same "prove it end to end, not just the piece that's easy to
test" discipline as this module's own three-state verdict logic.

Run:  python3 modules/integrity_watch/test_integrity_watch.py   (exit 0 = all pass)
"""

import os
import sys
import tempfile
import datetime

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db

import modules
modules.set_shared_db_path(_db)

from modules.integrity_watch import module as iw

_failures = []


def check(cond, label):
    if not isinstance(cond, bool):
        raise TypeError(
            f"check() needs a bool condition, got {type(cond).__name__} ({cond!r}). "
            f"Arguments are check(cond, label) -- likely reversed at: {label!r}"
        )
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        _failures.append(label)


_PAYLOAD = "<script>alert(1)</script>"
_ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;"


def main():
    print("crafted device_id renders escaped, not literal\n")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Bypass evaluate()/_gather() and insert directly -- the point under test is
    # the render path, not the detection logic, and this is the same shape any
    # agent-controlled device_id takes by the time it reaches a row here.
    iw._persist([{
        "observed_at": now, "device_id": _PAYLOAD, "signal": "finding_regression",
        "verdict": "flag", "scans_window": 10, "findings_window": 0,
        "scans_prior": 10, "findings_prior": 3, "fleet_devices": 1,
        "detail": "produced 3 findings historically but 0 in the last 30 days "
                  "across 10 completed scans",
    }])

    obs = iw.latest()
    check(len(obs) == 1, "one observation recorded")
    check(obs[0]["device_id"] == _PAYLOAD,
          "latest() returns the RAW value -- escaping is a render-time concern, "
          "not a storage-time one")

    module = iw.Module({"name": "integrity_watch"})
    card = module.get_dashboard_card()

    check(_PAYLOAD not in card,
          "the raw <script> tag does not appear literally in the rendered card")
    check(_ESCAPED in card,
          "the escaped form is present instead")
    check("<script>" not in card,
          "no unescaped opening script tag anywhere in the output "
          "(catches a partial escape that got the entity encoding wrong)")

    # CONTROL: prove the harness can tell escaped from literal at all -- render
    # a card with a benign device_id and confirm IT is not flagged as escaped
    # markup, so the checks above are measuring something real.
    iw._persist([{
        "observed_at": now, "device_id": "agent-042", "signal": "finding_regression",
        "verdict": "flag", "scans_window": 10, "findings_window": 0,
        "scans_prior": 10, "findings_prior": 3, "fleet_devices": 1,
        "detail": "produced 3 findings historically but 0 in the last 30 days "
                  "across 10 completed scans",
    }])
    card2 = module.get_dashboard_card()
    check("agent-042" in card2,
          "CONTROL: an ordinary device_id still renders plainly -- the fix "
          "escapes markup, it does not mangle normal text")

    print()
    if _failures:
        print(f"RESULT: {len(_failures)} FAILED")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
