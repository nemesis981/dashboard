"""Tests for steering_nft — the Linux/nftables steering backend.

No root, no real nft: a fake runner stands in for `nft`, fed output shaped like
real `nft -j list table` JSON and real nft error strings. That covers the pure
logic (ruleset construction, JSON parsing, error classification) and the
SteeringBackend contract, AND drives the REAL SteeringController against this
backend to prove the failsafe machinery works over the nft backend's shape --
including the cases that matter most: a permission error reading as UNKNOWN
(fail-open), and a teardown that a read-back does not confirm.

A live-nft proof against a real ruleset is a separate VM run (needs CAP_NET_ADMIN);
this suite is what runs anywhere, every time.

Run: python3 nemesis_agent/test_steering_nft.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import steering_nft as snf                                   # noqa: E402
import steering_lease as sl                                  # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def check_true(label, got):
    check(label, bool(got), True)


# ── a fake nft, modelling a live ruleset in memory ──────────────────────────

class FakeNft:
    """Stands in for the `nft` binary. Holds an in-memory 'ruleset' (does our
    table exist?) and can be told to deny permission or vanish, so the backend's
    error handling is exercised, not just the happy path."""

    def __init__(self):
        self.table_present = False
        self.deny = False          # every call returns a permission error
        self.missing = False       # nft binary 'not found'
        self.calls = []

    def __call__(self, args, stdin=None, timeout=10):
        self.calls.append(list(args))
        if self.missing:
            return snf.NftResult(127, "", "nft not found")
        if self.deny:
            return snf.NftResult(1, "", "Error: Operation not permitted")
        # apply: nft -f -
        if args and args[0] == "-f":
            self.table_present = True
            return snf.NftResult(0, "", "")
        # delete table
        if args[:1] == ["delete"]:
            if not self.table_present:
                return snf.NftResult(1, "", "Error: No such file or directory")
            self.table_present = False
            return snf.NftResult(0, "", "")
        # list table (json)
        if args[:1] == ["-j"]:
            if not self.table_present:
                return snf.NftResult(1, "", "Error: No such file or directory")
            return snf.NftResult(0, _list_json(present=True), "")
        return snf.NftResult(2, "", "unexpected args: %r" % (args,))


def _list_json(present):
    """Shaped like real `nft -j list table inet nemesis_steer` output."""
    if not present:
        return "{}"
    return json.dumps({"nftables": [
        {"metainfo": {"version": "1.1.6", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "nemesis_steer", "handle": 42}},
        {"chain": {"family": "inet", "table": "nemesis_steer", "name": "steer",
                   "handle": 1, "type": "nat", "hook": "output", "prio": -100,
                   "policy": "accept"}},
    ]})


def main():
    print("ruleset construction")
    be = snf.NftablesSteeringBackend(runner=FakeNft())
    inert = be.build_ruleset({})
    check("inert ruleset names the table", "table inet nemesis_steer" in inert, True)
    check("inert ruleset has NO redirect rule", "redirect to" in inert, False)
    check("inert ruleset marks itself inert", "inert" in inert, True)
    withport = be.build_ruleset({"forwarder_port": 9040})
    check("a forwarder port produces a redirect rule",
          "redirect to :9040" in withport, True)
    check("...to tcp dport 443", "tcp dport 443" in withport, True)

    print("\njson parse — only a REAL table object counts as present")
    check("present json -> present", snf.NftablesSteeringBackend._table_present_in_json(
        _list_json(True)), True)
    check("empty json -> absent", snf.NftablesSteeringBackend._table_present_in_json(
        "{}"), False)
    check("garbage json -> absent (a broken read never reads as present)",
          snf.NftablesSteeringBackend._table_present_in_json("not json"), False)
    check("rc0-but-empty must not read as present",
          snf.NftablesSteeringBackend._table_present_in_json(""), False)
    # a table of a DIFFERENT name must not count
    other = json.dumps({"nftables": [{"table": {"family": "inet", "name": "filter"}}]})
    check("a different table is not ours",
          snf.NftablesSteeringBackend._table_present_in_json(other), False)

    print("\nerror classification")
    check("absent error recognised", snf._is_absent(
        snf.NftResult(1, "", "Error: No such file or directory")), True)
    check("permission error recognised", snf._is_permission(
        snf.NftResult(1, "", "Error: Operation not permitted")), True)
    check("nft-missing is treated as permission/unknown", snf._is_permission(
        snf.NftResult(127, "", "nft not found")), True)
    check("timeout is unknown", snf._is_permission(snf.NftResult(124, "", "")), True)
    check("rc0 is neither absent nor permission",
          (snf._is_absent(snf.NftResult(0)), snf._is_permission(snf.NftResult(0))),
          (False, False))

    print("\nthe SteeringBackend contract over the fake nft")
    nft = FakeNft()
    be = snf.NftablesSteeringBackend(runner=nft)
    check("read starts absent -> safe", be.read_state().is_safe, True)
    be.apply({})
    check("after apply -> active", be.read_state().active, True)
    check("...and not safe", be.read_state().is_safe, False)
    be.teardown()
    check("after teardown -> safe again", be.read_state().is_safe, True)
    check("teardown of an ABSENT table is idempotent (no raise)",
          (be.teardown() or "ok"), "ok")

    print("\napply failure raises (so the controller fails back to safe)")
    nft2 = FakeNft(); nft2.deny = True
    be2 = snf.NftablesSteeringBackend(runner=nft2)
    try:
        be2.apply({})
        check("denied apply raises", "no raise", "RuntimeError")
    except RuntimeError:
        check("denied apply raises RuntimeError", True, True)

    print("\npermission error on READ -> UNKNOWN (fail-open), never a false 'safe'")
    nft3 = FakeNft(); nft3.deny = True
    be3 = snf.NftablesSteeringBackend(runner=nft3)
    st = be3.read_state()
    check("denied read is unknown", st.unknown, True)
    check("...and therefore NOT safe", st.is_safe, False)

    print("\nteardown that CANNOT clear (permission) raises, not silently 'done'")
    nft4 = FakeNft(); nft4.table_present = True; nft4.deny = True
    be4 = snf.NftablesSteeringBackend(runner=nft4)
    try:
        be4.teardown()
        check("denied teardown raises", "no raise", "RuntimeError")
    except RuntimeError:
        check("denied teardown raises RuntimeError", True, True)

    print("\nEND-TO-END: the real SteeringController driving the nft backend")
    # This is the point -- the failsafe machinery must work over the real backend
    # shape, not just the recording backend.
    class Clock:
        def __init__(self): self.t = 1000.0
        def __call__(self): return self.t
        def advance(self, dt): self.t += dt
    clock = Clock()
    nft5 = FakeNft()
    nft5.table_present = True                # pretend a prior run left steering ON
    ctrl = sl.SteeringController(snf.NftablesSteeringBackend(runner=nft5),
                                ttl_seconds=10.0, clock=clock)
    check("boot reconcile tears down the inherited nft table", ctrl.reconcile_boot(),
          True)
    check("...table really gone", nft5.table_present, False)
    ev = sl.RenewalEvidence(True, True, True)
    check("good heartbeat applies the nft table", ctrl.on_heartbeat(ev), True)
    check("...table really present", nft5.table_present, True)
    clock.advance(11.0)
    ctrl.tick()
    check("lease expiry deletes the nft table", nft5.table_present, False)

    print("\nEND-TO-END: a permission fault mid-run is caught by read-back, loudly")
    clock2 = Clock()
    nft6 = FakeNft()
    alarms = []
    ctrl2 = sl.SteeringController(snf.NftablesSteeringBackend(runner=nft6),
                                 ttl_seconds=10.0, clock=clock2,
                                 on_alarm=lambda r, d: alarms.append(r))
    ctrl2.reconcile_boot()
    ctrl2.on_heartbeat(sl.RenewalEvidence(True, True, True))
    check("armed with real table", nft6.table_present, True)
    nft6.deny = True                         # privilege lost: teardown+read now denied
    clock2.advance(11.0)
    ctrl2.tick()
    check("a teardown that cannot be confirmed raises the alarm",
          ctrl2.status()["alarm"] is not None, True)
    check("...the alarm fired", len(alarms) >= 1, True)
    nft6.deny = False                        # privilege back
    ctrl2.tick()
    check("...and recovers to safe once nft works again", nft6.table_present, False)
    check("...alarm cleared", ctrl2.status()["alarm"], None)

    print("\nforwarder lifecycle — started before the redirect, stopped after it")
    # A fake forwarder + a runner that both append to ONE ordered event log, so the
    # SEQUENCE (not just the fact) of start/apply/delete/stop is asserted.
    events = []

    class FakeForwarder:
        def __init__(self, listen_port, upstream):
            self.upstream = upstream
            self.bound_port = 0
            self.started = False
        def start(self):
            events.append("forwarder_start")
            self.started = True
            self.bound_port = 9999
            return self.bound_port
        def stop(self):
            events.append("forwarder_stop")
            self.started = False

    made = []
    def factory(listen_port, upstream):
        f = FakeForwarder(listen_port, upstream)
        made.append(f)
        return f

    class LoggingNft(FakeNft):
        def __call__(self, args, stdin=None, timeout=10):
            if args[:1] == ["-f"]:
                events.append("nft_apply")
            elif args[:1] == ["delete"]:
                events.append("nft_delete")
            return super().__call__(args, stdin=stdin, timeout=timeout)

    lnft = LoggingNft()
    be = snf.NftablesSteeringBackend(runner=lnft, forwarder_factory=factory)
    plan = {"appliance_upstream": ("10.0.0.1", 9443), "forwarder_port": None}

    be.apply(plan)
    check("apply started the forwarder", made and made[0].started, True)
    check("...redirect targets the forwarder's bound port",
          "redirect to :9999" in be.build_ruleset({"forwarder_port": 9999}), True)
    # the ORDERING: forwarder_start must precede nft_apply
    check("forwarder starts BEFORE the redirect is applied",
          events.index("forwarder_start") < events.index("nft_apply"), True)
    check("...table is present after apply", lnft.table_present, True)

    events_before_td = list(events)
    be.teardown()
    # nft_delete must precede forwarder_stop
    td_events = events[len(events_before_td):]
    check("teardown removes the redirect BEFORE stopping the forwarder",
          td_events.index("nft_delete") < td_events.index("forwarder_stop"), True)
    check("...forwarder is stopped", made[0].started, False)
    check("...table is gone", lnft.table_present, False)

    print("\nno upstream -> INERT: no forwarder started at all")
    events2 = []
    made2 = []
    be2 = snf.NftablesSteeringBackend(runner=FakeNft(),
                                      forwarder_factory=lambda lp, up: made2.append(1))
    be2.apply({"appliance_upstream": None})
    check("inert apply starts NO forwarder", made2, [])
    check("...and the table is still created (lifecycle-only)",
          be2.read_state().active, True)
    be2.teardown()
    check("inert teardown is clean", be2.read_state().is_safe, True)

    print("\na failed nft apply STOPS the just-started forwarder (no leaked listener)")
    stopped = []
    class FailNft(FakeNft):
        def __call__(self, args, stdin=None, timeout=10):
            if args[:1] == ["-f"]:
                return snf.NftResult(1, "", "Error: something broke")
            return super().__call__(args, stdin=stdin, timeout=timeout)
    class TrackForwarder(FakeForwarder):
        def stop(self):
            stopped.append(1)
            super().stop()
    be3 = snf.NftablesSteeringBackend(
        runner=FailNft(), forwarder_factory=lambda lp, up: TrackForwarder(lp, up))
    try:
        be3.apply({"appliance_upstream": ("10.0.0.1", 9443)})
        check("a failed apply raises", "no raise", "RuntimeError")
    except RuntimeError:
        check("a failed apply raises RuntimeError", True, True)
    check("...and the forwarder it started was stopped (no leak)", stopped, [1])

    print("\nteardown stops the forwarder EVEN IF the nft delete fails")
    stopped2 = []
    class DenyDeleteNft(FakeNft):
        def __call__(self, args, stdin=None, timeout=10):
            if args[:1] == ["delete"]:
                return snf.NftResult(1, "", "Error: Operation not permitted")
            return super().__call__(args, stdin=stdin, timeout=timeout)
    be4 = snf.NftablesSteeringBackend(runner=DenyDeleteNft())
    # give it a running forwarder, then tear down while the nft delete is denied.
    f4 = FakeForwarder(None, ("10.0.0.1", 9443)); f4.start()
    f4.stop = lambda: stopped2.append(1)
    be4._forwarder = f4
    try:
        be4.teardown()
        check("a denied teardown raises", "no raise", "RuntimeError")
    except RuntimeError:
        check("a denied teardown raises RuntimeError", True, True)
    check("...but the forwarder was stopped anyway (no leaked listener)",
          stopped2, [1])

    print("\nCAPSTONE: controller + nft backend + a REAL forwarder (real sockets)")
    # Only the nft is faked (needs root); the forwarder is REAL, so arming brings up
    # an actual listener and lapsing takes it down -- proven by connecting to it.
    import socket as _sock
    import time as _time
    import forwarder as _fw

    # a real fake-appliance socket for the forwarder's upstream
    appsrv = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    appsrv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    appsrv.bind(("127.0.0.1", 0)); appsrv.listen(4)
    app_port = appsrv.getsockname()[1]

    def real_factory(listen_port, upstream):
        return _fw.TransparentForwarder(listen_host="127.0.0.1",
                                        listen_port=listen_port or 0, upstream=upstream)

    class Clock2:
        def __init__(self): self.t = 5000.0
        def __call__(self): return self.t
        def advance(self, dt): self.t += dt
    clk = Clock2()
    capnft = FakeNft()
    backend = snf.NftablesSteeringBackend(runner=capnft, forwarder_factory=real_factory)
    ctrl = sl.SteeringController(backend, ttl_seconds=10.0, clock=clk)
    ctrl.reconcile_boot()
    ctrl.on_heartbeat(sl.RenewalEvidence(True, True, True),
                      plan={"appliance_upstream": ("127.0.0.1", app_port),
                            "forwarder_port": None})
    fwd = backend._forwarder
    check("arming started a REAL forwarder with a bound port",
          fwd is not None and fwd.bound_port > 0, True)
    # prove it is actually listening: connect to it
    try:
        c = _sock.create_connection(("127.0.0.1", fwd.bound_port), timeout=2)
        c.close()
        listening = True
    except OSError:
        listening = False
    check("...and the forwarder port is genuinely accepting connections", listening,
          True)
    port_was = fwd.bound_port

    clk.advance(11.0)
    ctrl.tick()                     # lease expires -> teardown -> forwarder stops
    check("lease expiry stopped the forwarder", backend._forwarder, None)
    _time.sleep(0.2)
    # prove it is no longer listening
    try:
        c = _sock.create_connection(("127.0.0.1", port_was), timeout=1)
        c.close()
        still = True
    except OSError:
        still = False
    check("...and the port is no longer accepting (listener really gone)", still, False)
    appsrv.close()

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  -", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
