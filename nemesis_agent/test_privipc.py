#!/usr/bin/env python3
"""Privileged-IPC subsystem — pure-logic tests (cross-platform; no Windows needed).

Covers the parts of the SYSTEM-service / session-client boundary that MUST be right
and can be tested without a real pipe or a real service:
  * winsvc.next_status  — the SCM control -> status transition (a mis-reported
    service state is exactly the silent-wrong-status this split cannot afford)
  * privservice.authorize_client / dispatch — who may talk, and the answers
  * privclient.verify_server — the anti-squatting SYSTEM check
The Windows shells (real pipe, real service under the SCM, token->SID reads) are the
VM acceptance test.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import winsvc                                                # noqa: E402
import privservice                                           # noqa: E402
import privclient                                            # noqa: E402
import privchannel as pc                                     # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-62s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


def _raises(exc, fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except exc:
        return True
    except Exception:                                        # noqa: BLE001
        return False


AGENT_SID = "S-1-5-21-1004336348-1177238915-682003330-1001"
OTHER_SID = "S-1-5-21-1004336348-1177238915-682003330-1002"


# ── winsvc: the SCM status state machine ─────────────────────────────────────

def test_stop_and_shutdown_wind_down():
    print("\n[STOP and SHUTDOWN both -> STOP_PENDING + signal the work loop]")
    for ctrl, name in ((winsvc.SERVICE_CONTROL_STOP, "STOP"),
                       (winsvc.SERVICE_CONTROL_SHUTDOWN, "SHUTDOWN")):
        state, action = winsvc.next_status(winsvc.SERVICE_RUNNING, ctrl)
        check("%s -> STOP_PENDING" % name, state, winsvc.SERVICE_STOP_PENDING)
        check("%s -> ACTION_STOP" % name, action, winsvc.ACTION_STOP)


def test_interrogate_restates_without_stopping():
    print("\n[INTERROGATE restates current state, does NOT stop]")
    state, action = winsvc.next_status(winsvc.SERVICE_RUNNING,
                                       winsvc.SERVICE_CONTROL_INTERROGATE)
    check("state unchanged", state, winsvc.SERVICE_RUNNING)
    check("no stop", action, winsvc.ACTION_NONE)


def test_unknown_control_is_a_noop():
    print("\n[an unhandled control does not silently change state or stop]")
    state, action = winsvc.next_status(winsvc.SERVICE_RUNNING, 0x99)
    check("state unchanged", state, winsvc.SERVICE_RUNNING)
    check("no action", action, winsvc.ACTION_NONE)


def test_accepted_controls_only_when_running():
    print("\n[STOP/SHUTDOWN are accepted only while RUNNING, not mid-transition]")
    check("RUNNING accepts stop+shutdown",
          winsvc.accepted_controls(winsvc.SERVICE_RUNNING),
          winsvc.SERVICE_ACCEPT_STOP | winsvc.SERVICE_ACCEPT_SHUTDOWN)
    check("START_PENDING accepts nothing",
          winsvc.accepted_controls(winsvc.SERVICE_START_PENDING), 0)
    check("STOPPED accepts nothing",
          winsvc.accepted_controls(winsvc.SERVICE_STOPPED), 0)


# ── privservice: client authorization (server side of mutual auth) ───────────

def test_authorize_only_the_enrolled_agent_user():
    print("\n[the service authorizes ONLY the enrolled agent-user SID]")
    check("the agent user is authorized",
          privservice.authorize_client(AGENT_SID, AGENT_SID), True)
    check("a different user is refused",
          privservice.authorize_client(OTHER_SID, AGENT_SID), False)
    check("an unreadable client SID (None) is refused (fail-closed)",
          privservice.authorize_client(None, AGENT_SID), False)
    check("no expected SID configured -> refuse everyone",
          privservice.authorize_client(AGENT_SID, None), False)
    check("case-insensitive match still authorizes",
          privservice.authorize_client(AGENT_SID.lower(), AGENT_SID), True)


# ── privservice: request dispatch (nothing privileged in 3b) ─────────────────

def test_dispatch_ping_and_unknown():
    print("\n[dispatch answers ping; unknown actions error, never raise]")
    r = privservice.dispatch({"action": "ping", "proto": pc.PROTO_VERSION})
    check("ping -> pong", r.get("pong"), True)
    check("ping ok", r.get("ok"), True)
    check("ping reports SYSTEM", r.get("server"), "SYSTEM")
    # 3b asserted this action was UNKNOWN. 3c makes it known -- but with no inspector
    # injected it must still refuse, and refuse EXPLICITLY: a caller has to be able to
    # tell "this build cannot inspect" apart from "inspected and found nothing".
    noinsp = privservice.dispatch({"action": "inspect_pid", "pid": 1234})
    check("inspect_pid without an inspector refuses", noinsp.get("ok"), False)
    check("  and says it was NOT scanned", noinsp.get("scanned"), False)
    check("  and does not claim a readable state", noinsp.get("state"), "undetermined")
    served = privservice.dispatch({"action": "inspect_pid", "pid": 1234},
                                  inspector=lambda params: {"ok": True,
                                                            "pid": params["pid"]})
    check("with an inspector, inspect_pid routes to it", served.get("pid"), 1234)
    check("garbage request errors, no raise",
          privservice.dispatch({}).get("ok"), False)


# ── privclient: server verification (anti-squatting) ─────────────────────────

def test_client_only_talks_to_system():
    print("\n[the client refuses any server that is not LocalSystem]")
    check("SYSTEM server verifies (no raise)",
          verify_returns_none(pc.SID_LOCAL_SYSTEM), True)
    check("a non-SYSTEM server is refused",
          _raises(pc.PrivChannelAuthError, privclient.verify_server, AGENT_SID), True)
    check("an unreadable server SID (None) is refused",
          _raises(pc.PrivChannelAuthError, privclient.verify_server, None), True)
    check("Administrators is NOT good enough (must be SYSTEM)",
          _raises(pc.PrivChannelAuthError, privclient.verify_server, "S-1-5-32-544"),
          True)


def verify_returns_none(sid):
    try:
        return privclient.verify_server(sid) is None
    except Exception:                                        # noqa: BLE001
        return False


# ── the two ends agree on the protocol ───────────────────────────────────────

def test_ends_agree_on_protocol_version():
    print("\n[client request and server response carry the same proto version]")
    resp = privservice.dispatch({"action": "ping", "proto": pc.PROTO_VERSION})
    check("server echoes the shared PROTO_VERSION", resp.get("proto"),
          pc.PROTO_VERSION)


if __name__ == "__main__":
    print("privileged-IPC subsystem — pure-logic tests")
    test_stop_and_shutdown_wind_down()
    test_interrogate_restates_without_stopping()
    test_unknown_control_is_a_noop()
    test_accepted_controls_only_when_running()
    test_authorize_only_the_enrolled_agent_user()
    test_dispatch_ping_and_unknown()
    test_client_only_talks_to_system()
    test_ends_agree_on_protocol_version()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
