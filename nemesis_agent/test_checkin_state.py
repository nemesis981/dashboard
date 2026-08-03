#!/usr/bin/env python3
"""Agent check-in wording: state what is known, never assert a cause.

Run: python3 nemesis_agent/test_checkin_state.py

_agent_checkin_state is extracted verbatim from dashboard.py rather than copied,
so this exercises the shipped code. The point of the function is that it must
NOT claim a device is offline -- the server cannot distinguish powered-off from
off-network from waiting-at-the-unlock-prompt -- so most of these checks are
about what the output refuses to say.
"""
import os
import re
import sys
from datetime import datetime, timedelta

DASHBOARD = "/opt/nemesis/dashboard.py"
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def extract(func_name, ns):
    lines = open(DASHBOARD).read().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("def %s(" % func_name))
    end = start + 1
    while end < len(lines) and (lines[end].startswith("    ") or not lines[end].strip()):
        end += 1
    exec(compile("\n".join(lines[start:end]), DASHBOARD, "exec"), ns)
    return ns[func_name]


def main():
    src = open(DASHBOARD).read()
    ns = {"datetime": datetime, "_AGENT_STALE_AFTER_S": 30 * 60,
          "_AGENT_CLOCK_SKEW_S": 300}
    human = extract("_human_age", ns)
    ns["_human_age"] = human
    state = extract("_agent_checkin_state", ns)
    print("extracted _agent_checkin_state + _human_age verbatim from dashboard.py\n")

    now = datetime(2026, 8, 3, 12, 0, 0)

    def at(delta_s):
        return (now - timedelta(seconds=delta_s)).isoformat(timespec="seconds")

    print("fresh device — a note would be noise")
    check("POSITIVE a recent check-in produces NO explanatory note",
          state(at(60), now)[1], "")
    check("and the label reports the age", "ago" in state(at(60), now)[0], True)

    print("\nstale device — the three causes, none asserted")
    label, note = state(at(3600), now)
    check("CONTROL a stale device DOES get a note", bool(note), True)
    check("CONTROL the label never says 'offline'", "offline" in label.lower(), False)
    check("CONTROL the note never says 'offline'", "offline" in note.lower(), False)
    check("names cause 1 — powered off", "powered off" in note, True)
    check("names cause 2 — off the network", "off the network" in note, True)
    check("names cause 3 — awaiting device password", "device password" in note, True)
    check("states plainly that it cannot distinguish them",
          "cannot tell these apart" in note, True)
    check("points at revoke for the stolen case", "revoke" in note.lower(), True)

    print("\nevery failure mode gets its own label, none reads as healthy")
    for raw, tag in ((None, "never"), ("", "never"), ("-", "never")):
        lab, nt = state(raw, now)
        check("CONTROL missing timestamp (%r) is 'never checked in'" % raw,
              "never checked in" in lab, True)
        check("CONTROL missing timestamp (%r) still explains itself" % raw,
              bool(nt), True)

    lab, nt = state("not-a-timestamp", now)
    check("CONTROL an unreadable timestamp says so explicitly",
          "unreadable" in lab, True)
    check("CONTROL an unreadable timestamp is NOT silently treated as fresh",
          bool(nt), True)

    future = (now + timedelta(hours=2)).isoformat(timespec="seconds")
    lab, nt = state(future, now)
    check("CONTROL a future timestamp is flagged as clock disagreement",
          "future" in lab, True)
    check("CONTROL it is not rendered as a fresh check-in", bool(nt), True)

    # small negative age is jitter, not the future
    near_future = (now + timedelta(seconds=30)).isoformat(timespec="seconds")
    check("CONTROL minor clock jitter is tolerated, not flagged",
          state(near_future, now)[1], "")

    print("\nthreshold behaviour")
    check("just inside the window is quiet", state(at(30 * 60 - 30), now)[1], "")
    check("CONTROL just outside the window warns",
          bool(state(at(30 * 60 + 30), now)[1]), True)

    print("\n_human_age never renders a negative age")
    check("CONTROL a negative age clamps to 'just now'", human(-5), "just now")
    check("seconds", human(20), "20s ago")
    check("minutes", human(600), "10m ago")
    check("hours", human(7200), "2h ago")
    check("days", human(259200), "3d ago")

    print("\nrendering: no badge, revoke adjacent")
    row = src[src.index("for r in enrolled"):]
    row = row[:row.index("if revoked:")]
    check("CONTROL no online/offline badge is rendered",
          bool(re.search(r'>\s*(Online|Offline)\s*<', row)), False)
    check("the computed label is what gets shown", "{checkin_label}" in row, True)
    check("the note is rendered when present", "{checkin_note}" in row, True)
    check("Revoke sits after the note, not before",
          row.index("{checkin_note}") < row.index("agentRevoke"), True)
    check("the label is HTML-escaped", "html.escape(_ck_label)" in row, True)
    check("CONTROL the note is HTML-escaped too",
          "html.escape(_ck_note)" in row, True)

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
