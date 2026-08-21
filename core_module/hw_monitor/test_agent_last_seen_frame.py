#!/usr/bin/env python3
"""`agent_last_seen` is the SERVER's clock — a foreign-timezone agent reads fresh.

Run: python3 core_module/hw_monitor/test_agent_last_seen_frame.py

WHAT THIS GUARDS. `_update_agent_device` used to store `payload["timestamp"]` --
the agent's own naive `datetime.now()`, in the AGENT's timezone. Every reader
compares that against the SERVER's naive `datetime.now()`. Both operands naive,
so Python subtracted them without complaint and returned an answer wrong by the
offset difference.

Measured live 2026-08-20: gateway on Etc/UTC, agents on America/Chicago. A node
that had beaten 0 seconds earlier computed an age of 18000s against an 1800s
threshold -- so every healthy node rendered "no check-in since ...", whose note
ends "If you think it may be lost or stolen, revoke it." A healthy device was
indistinguishable from a dead one, on a path that advises revocation.

The failure was silent in the worst way: no exception, no malformed value, just
a plausible number. That is why it gets a test rather than a comment.

HOW IT AVOIDS TESTING A COPY. Two halves, both real:
  * the WRITER is the shipped `hw_monitor._update_agent_device`, called against a
    temp DB, and the assertions read the TABLE BACK rather than trusting a return
    value;
  * the READERS are `_agent_checkin_state` / `_agent_status_from_seen` / their
    constants, extracted verbatim out of dashboard.py at test time.
Retyping either half would keep passing after the shipped code broke.

EVERY ASSERTION IS PAIRED WITH A CONTROL. A suite that only ever asserts "reads
fresh" cannot tell a working staleness signal from one hardwired to say "online",
so a genuinely-old value must still read stale, and the pre-fix agent-framed value
must still read stale when fed to the readers directly.
"""
import os
import re
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "alert_manager"))
sys.path.insert(0, _HERE)

import hw_monitor as hm                       # noqa: E402

DASHBOARD = os.path.join(_ROOT, "dashboard.py")
HW_SRC_PATH = os.path.join(_HERE, "hw_monitor.py")

passed = failed = 0


def check(label, got, want):
    global passed, failed
    if got == want:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s\n         got=%r\n         want=%r" % (label, got, want))


def check_true(label, cond, detail=""):
    check(label + (" %s" % detail if detail else ""), bool(cond), True)


# ── real readers, lifted out of dashboard.py ─────────────────────────────────
def _extract(func_name, ns):
    lines = open(DASHBOARD).read().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("def %s(" % func_name))
    end = start + 1
    while end < len(lines) and (lines[end].startswith("    ") or not lines[end].strip()):
        end += 1
    exec(compile("\n".join(lines[start:end]), DASHBOARD, "exec"), ns)
    return ns[func_name]


def _extract_const(name, src):
    """Parse the shipped constant rather than restating it -- a hardcoded copy
    here would keep passing after the real threshold was retuned."""
    m = re.search(r"^%s\s*=\s*([0-9*\s]+)$" % name, src, re.M)
    if not m:
        raise SystemExit("could not find %s in dashboard.py" % name)
    return eval(m.group(1))                      # noqa: S307 -- digits and '*' only


DASH_SRC = open(DASHBOARD).read()
_NS = {"datetime": datetime,
       "_AGENT_STALE_AFTER_S": _extract_const("_AGENT_STALE_AFTER_S", DASH_SRC),
       "_AGENT_CLOCK_SKEW_S": _extract_const("_AGENT_CLOCK_SKEW_S", DASH_SRC)}
_NS["_human_age"] = _extract("_human_age", _NS)
checkin_state = _extract("_agent_checkin_state", _NS)
status_from_seen = _extract("_agent_status_from_seen", _NS)

STALE_AFTER_S = _NS["_AGENT_STALE_AFTER_S"]


def reads_fresh(stored, now):
    """Both shipped readers' verdicts for a stored value, at server time `now`."""
    label, _note = checkin_state(stored, now=now)
    return ("no check-in since" not in label and "future" not in label
            and "unreadable" not in label,
            status_from_seen(stored, now) == "online")


# ── temp DB wired to the shipped writer ──────────────────────────────────────
_tmp = tempfile.mkdtemp(prefix="agent-last-seen-")
DB = os.path.join(_tmp, "alerts.db")
hm._db_connect = lambda: sqlite3.connect(DB, timeout=5.0)
hm.init_db()

# Offsets chosen to straddle the server in both directions: America/Chicago is
# UTC-5 (the live fleet's real case, and the direction that reads as DEAD rather
# than announcing itself), and +9 stands in for an east-of-server agent.
WEST_OFFSET_H = -5
EAST_OFFSET_H = +9


def beat(device_id, agent_offset_h):
    """One heartbeat from an agent whose clock is `agent_offset_h` from the
    server's. Returns (claimed_by_agent, stored_in_db)."""
    claimed = (datetime.now() + timedelta(hours=agent_offset_h)).isoformat(timespec="seconds")
    hm._update_agent_device({"device_id": device_id,
                             "device_name": device_id,
                             "device_type": "linux",
                             "connection_type": "local",
                             "timestamp": claimed,
                             "agent_health": {}}, remote_ip="192.88.99.7")
    row = sqlite3.connect(DB).execute(
        "SELECT agent_last_seen FROM agent_devices WHERE device_id=?",
        (device_id,)).fetchone()
    return claimed, (row[0] if row else None)


def main():
    now = datetime.now()

    print("\n-- CONTROLS: the readers must be able to say BOTH things --")
    fresh_srv = (now - timedelta(seconds=5)).isoformat(timespec="seconds")
    stale_srv = (now - timedelta(seconds=STALE_AFTER_S + 3600)).isoformat(timespec="seconds")
    check("a server-framed value from 5s ago reads fresh", reads_fresh(fresh_srv, now), (True, True))
    check("a server-framed value well past the threshold reads stale",
          reads_fresh(stale_srv, now), (False, False))

    print("\n-- CONTROL: this is what the bug looked like (pre-fix stored value) --")
    # The value the OLD writer would have stored for an agent beating right now.
    old_style = (now + timedelta(hours=WEST_OFFSET_H)).isoformat(timespec="seconds")
    check("an agent-framed timestamp fed to the readers still reads STALE",
          reads_fresh(old_style, now), (False, False))
    print("         (so check 'reads fresh' below cannot pass by accident)")

    print("\n-- WRITER: the agent's clock must not reach the column --")
    claimed_w, stored_w = beat("dev-west", WEST_OFFSET_H)
    check_true("west agent's claimed timestamp is NOT what was stored",
               stored_w != claimed_w)
    check_true("stored value is the server's clock (within 5s)",
               abs((datetime.fromisoformat(stored_w) - now).total_seconds()) < 5,
               "-> %s" % stored_w)

    claimed_e, stored_e = beat("dev-east", EAST_OFFSET_H)
    check_true("east agent's claimed timestamp is NOT what was stored",
               stored_e != claimed_e)

    print("\n-- END TO END: a device beating from a foreign timezone reads fresh --")
    check("west-of-server agent (the live America/Chicago case) reads fresh + online",
          reads_fresh(stored_w, now), (True, True))
    check("east-of-server agent reads fresh + online, not 'in the future'",
          reads_fresh(stored_e, now), (True, True))

    print("\n-- the column still AGES: a stored beat does not read fresh forever --")
    later = now + timedelta(seconds=STALE_AFTER_S + 3600)
    check("the same stored value reads stale once real time passes",
          reads_fresh(stored_w, later), (False, False))

    print("\n-- INVARIANT: both writers of this column use the SERVER clock --")
    hw_src = open(HW_SRC_PATH).read()
    upd = hw_src[hw_src.index("def _update_agent_device"):]
    upd = upd[:upd.index("\ndef ", 1)]
    check_true("_update_agent_device does not source its ts from the payload",
               not re.search(r"^\s*ts\s*=.*payload", upd, re.M))
    check_true("_update_agent_device stamps ts from datetime.now()",
               re.search(r"^\s*ts\s*=\s*datetime\.now\(\)", upd, re.M) is not None)
    enr = hw_src[hw_src.index("def _create_enrollment"):]
    enr = enr[:enr.index("\ndef ", 1)]
    check_true("_create_enrollment seeds the column from datetime.now() too",
               re.search(r"^\s*now\s*=\s*datetime\.now\(\)", enr, re.M) is not None)

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
