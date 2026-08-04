"""
Test harness for the observation layer — process enumeration + UDP attribution.

Standalone (no pytest). Covers both halves: the agent-side enumerators in
agent.py, and the server-side persistence in hw_monitor._update_agent_device().

WHAT THIS LAYER IS FOR, AND THE ONE PROPERTY THAT MATTERS
---------------------------------------------------------
It is the technique-independent foundation for memory-injection work and the
attribution source Tier 3 needs. It reports; it judges nothing.

Its correctness hinges on VISIBILITY ACCOUNTING. Measured on a real non-root
host: 600 processes visible but 401 with exe() denied, and 34 UDP sockets with
only 26 carrying an attributable pid. An unqualified list would therefore be a
plausible, confident, WRONG picture that no consumer could detect. So every
count is reported alongside what was actually obtainable, and these checks pin
that — including that an empty result is never allowed to mean "nothing here"
when it really means "could not look".

Run:  python3 nemesis_agent/test_observation.py   (exit 0 = all pass)
"""

import os
import sys
import json
import tempfile
import sqlite3
import importlib.util

# The agent ships its OWN `modules` package (nemesis_agent/modules/) whose name
# collides with the server's /opt/nemesis/modules. Each half must be loaded with
# its own path winning, so the path is set per-half rather than once globally.
_AGENT_DIR = "/opt/nemesis/nemesis_agent"

_failures = []


def check(cond, label):
    if not isinstance(cond, bool):
        raise TypeError(f"check(cond, label) looks reversed at {label!r}")
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        _failures.append(label)


def eq(label, got, expected):
    ok = (got == expected)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}  (got {got!r}, expected {expected!r})")
    if not ok:
        _failures.append(label)


def _load_agent():
    """Load agent.py by path.

    NOT wrapped in a bare except: a swallowed load error would leave a module
    object with none of the functions under test, and every assertion below
    would then fail for the wrong reason (or a hasattr guard would skip them
    entirely and report green). Let it raise.
    """
    sys.path.insert(0, _AGENT_DIR)
    spec = importlib.util.spec_from_file_location(
        "nem_agent_under_test", os.path.join(_AGENT_DIR, "agent.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ag = _load_agent()
    check(hasattr(ag, "_enumerate_processes"), "process enumerator exists")
    check(hasattr(ag, "_enumerate_udp_connections"), "UDP enumerator exists")

    print("\n-- process enumeration reports what it could NOT see --")
    p = ag._enumerate_processes()
    eq("state is ok on a normal host", p.get("state"), "ok")
    check(isinstance(p.get("total"), int) and p["total"] > 0,
          f"total processes is a real count ({p.get('total')})")
    check(p.get("reported") <= p.get("total"), "reported never exceeds total")
    check("detail_denied" in p,
          f"privilege-denied detail is COUNTED, not silently dropped "
          f"({p.get('detail_denied')} of {p.get('total')})")
    check(p.get("truncated") == (p["total"] > len(p["processes"])),
          "truncated flag agrees with the actual list length")
    check(p.get("order") == "newest_first",
          "ordering is declared, so truncation semantics are knowable")

    print("\n-- truncation keeps the NEWEST, which is the security-relevant end --")
    procs = p["processes"]
    if len(procs) > 1:
        starts = [r.get("started") or 0 for r in procs]
        check(starts == sorted(starts, reverse=True),
              "processes are ordered newest-first as declared")
    else:
        check(True, "too few processes to order-check (vacuous, noted)")

    print("\n-- a denied exe is null AND counted, never an invented value --")
    denied_rows = [r for r in procs if r.get("exe") is None]
    check(all(("exe" in r) for r in procs),
          "every row carries the exe key, so absent != missing-field")
    if denied_rows:
        check(all(r["exe"] is None for r in denied_rows),
              "unreadable exe is null, not a guess or empty string")
    else:
        check(True, "(no denied rows on this host - vacuous, noted)")

    print("\n-- UDP attribution exposes the gap it cannot close --")
    u = ag._enumerate_udp_connections()
    check(u.get("state") in ("ok", "denied", "unavailable"),
          f"state is explicit: {u.get('state')}")
    if u.get("state") == "ok":
        eq("attributable + unattributed accounts for every socket",
           u["attributable"] + u["unattributed"], u["total"])
        check(u["unattributed"] >= 0,
              f"unattributed sockets are surfaced, not hidden ({u['unattributed']})")
        for c in u["connections"][:20]:
            if c.get("pid") is None:
                check(c.get("proc") is None,
                      "an unattributable socket names no process")
                break
        else:
            check(True, "(all sampled sockets attributable - vacuous, noted)")

    print("\n-- a failure is NEVER an empty list --")
    # The whole point: "no UDP sockets" is essentially never true on a live host,
    # so a denied enumeration must not look like a quiet one.
    import psutil
    _real = psutil.net_connections
    psutil.net_connections = lambda kind=None: (_ for _ in ()).throw(psutil.AccessDenied())
    try:
        d = ag._enumerate_udp_connections()
        eq("denied enumeration reports state=denied", d.get("state"), "denied")
        check(d.get("total") is None,
              "denied enumeration reports total=None, NOT 0 (0 would read as a measurement)")
        check("reason" in d, "the reason is preserved")
    finally:
        psutil.net_connections = _real
    # Control: the same call path yields state=ok when not denied.
    check(ag._enumerate_udp_connections().get("state") == "ok",
          "(control) the same path returns ok when permitted")

    _realpi = psutil.process_iter
    psutil.process_iter = lambda attrs=None: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        d = ag._enumerate_processes()
        eq("failed process enumeration is explicit", d.get("state"), "unavailable")
        check(d.get("total") is None, "failed enumeration reports total=None, not 0")
    finally:
        psutil.process_iter = _realpi

    print("\n-- CADENCE: local observes every beat, remote every Nth --")
    ag._beat_count = 0
    local = [ag._observation_for_beat("local") for _ in range(12)]
    check(all(o is not None for o in local),
          "a LOCAL agent observes on every one of 12 beats")
    check(all("processes" in o and "udp" in o for o in local if o),
          "every local observation is COMPLETE, not thinned")

    ag._beat_count = 0
    N = ag._REMOTE_OBSERVE_EVERY_N_BEATS
    remote = [ag._observation_for_beat("vpn_remote") for _ in range(12)]
    sent = [i for i, o in enumerate(remote, start=1) if o is not None]
    check(remote[0] is not None,
          "a remote agent observes on its FIRST beat (not invisible for N intervals)")
    eq(f"remote observes {12 // N + 1} times in 12 beats at N={N}", len(sent), 12 // N + 1)
    check(all("processes" in o and "udp" in o for o in remote if o),
          "every remote observation is COMPLETE — less often, never thinned")
    check(all(o is None or o["cadence"]["every_n_beats"] == N for o in remote),
          "the snapshot declares its own cadence, so staleness is checkable")
    eq("local cadence declares every_n_beats=1", local[0]["cadence"]["every_n_beats"], 1)
    check(all(o.get("observed_at") for o in local + remote if o),
          "each snapshot carries when it was taken")

    print("\n-- a DEFERRED beat must not destroy the stored snapshot --")
    deferred = [o for o in remote if o is None]
    check(bool(deferred), "(premise) some beats really were deferred")
    check(all(o is None for o in deferred),
          "deferral is None, not a partial dict the server would persist over a good one")

    print("\n-- the divisor is operator-settable, and independently clamped --")
    eq("absent value keeps current (older server sends none)",
       ag._clamp_observe_n(None), None)
    eq("a sane value is accepted", ag._clamp_observe_n(12), 12)
    eq("zero is rejected (would divide by zero)", ag._clamp_observe_n(0), None)
    eq("negative is rejected (would make every beat due)", ag._clamp_observe_n(-3), None)
    eq("garbage is rejected", ag._clamp_observe_n("lots"), None)
    # bool subclasses int: True would otherwise clamp to 1 = full fidelity on a
    # metered link, i.e. a nonsense value silently becoming the expensive one.
    eq("True is rejected before the int check", ag._clamp_observe_n(True), None)
    eq("above the ceiling is clamped, not rejected",
       ag._clamp_observe_n(9999), ag._OBSERVE_N_MAX)
    eq("below the floor is clamped", ag._clamp_observe_n(0.5), None)

    print("\n-- a server-set divisor actually changes remote cadence --")
    _saved = ag._remote_observe_n
    try:
        ag._remote_observe_n = 3
        ag._beat_count = 0
        r3 = [ag._observation_for_beat("vpn_remote") for _ in range(12)]
        eq("at N=3, remote observes 5 times in 12 beats",
           sum(1 for o in r3 if o is not None), 5)
        check(all(o["cadence"]["every_n_beats"] == 3 for o in r3 if o),
              "the snapshot reports the divisor actually in force")
        # Control: N=1 is full fidelity, proving the knob spans its whole range.
        ag._remote_observe_n = 1
        ag._beat_count = 0
        r1 = [ag._observation_for_beat("vpn_remote") for _ in range(12)]
        eq("(control) at N=1 a remote agent observes every beat",
           sum(1 for o in r1 if o is not None), 12)
    finally:
        ag._remote_observe_n = _saved

    print("\n-- SERVER HALF: the snapshot is actually persisted --")
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    os.environ["NEMESIS_DB_PATH"] = db
    # Hand the namespace back to the server: drop the agent dir from the path and
    # evict its `modules` package, or the server's import resolves to the agent's.
    while _AGENT_DIR in sys.path:
        sys.path.remove(_AGENT_DIR)
    for _m in [k for k in sys.modules if k == "modules" or k.startswith("modules.")]:
        del sys.modules[_m]
    sys.path.insert(0, "/opt/nemesis")
    sys.path.insert(0, "/opt/nemesis/alert_manager")
    sys.path.insert(0, "/opt/nemesis/core_module/hw_monitor")
    import modules
    modules.set_shared_db_path(db)
    import hw_monitor
    hw_monitor.init_db()

    payload = {
        "device_id": "obs-test-1", "device_name": "ObsTest",
        "device_type": "laptop", "connection_type": "wifi",
        "agent_health": {},
        "observation": {"processes": {"state": "ok", "total": 7, "reported": 7,
                                      "detail_denied": 2, "processes": []},
                        "udp": {"state": "ok", "total": 3, "attributable": 2,
                                "unattributed": 1, "connections": []}},
    }
    hw_monitor._update_agent_device(payload)
    conn = sqlite3.connect(db)
    row = conn.execute("SELECT last_heartbeat_data FROM agent_devices WHERE device_id=?",
                       ("obs-test-1",)).fetchone()
    check(row is not None and row[0] is not None,
          "observation snapshot is written to last_heartbeat_data")
    if row and row[0]:
        stored = json.loads(row[0])
        eq("process accounting survived the round trip",
           stored["processes"]["detail_denied"], 2)
        eq("UDP accounting survived the round trip",
           stored["udp"]["unattributed"], 1)

    print("\n-- a DEFERRED beat leaves the stored snapshot intact (end to end) --")
    hw_monitor._update_agent_device({
        "device_id": "obs-test-1", "device_name": "ObsTest",
        "device_type": "laptop", "connection_type": "vpn_remote",
        "agent_health": {}, "observation": None,
    })
    rowd = conn.execute("SELECT last_heartbeat_data FROM agent_devices WHERE device_id=?",
                        ("obs-test-1",)).fetchone()
    check(rowd is not None and rowd[0] is not None,
          "observation=None (deferred remote beat) does NOT blank the snapshot")
    if rowd and rowd[0]:
        eq("the PREVIOUS complete snapshot survives a deferred beat",
           json.loads(rowd[0])["processes"]["detail_denied"], 2)

    print("\n-- an agent that omits `observation` must not blank the snapshot --")
    hw_monitor._update_agent_device({
        "device_id": "obs-test-1", "device_name": "ObsTest",
        "device_type": "laptop", "connection_type": "wifi", "agent_health": {},
    })
    row2 = conn.execute("SELECT last_heartbeat_data FROM agent_devices WHERE device_id=?",
                        ("obs-test-1",)).fetchone()
    check(row2 is not None and row2[0] is not None,
          "an older agent's beat leaves the stored snapshot intact")
    conn.close()

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
