"""Tests for agent_gui_core — the settings/status window's logic, no display needed.

What is checked hardest, and why:

* **Partial saves.** The window must write only the keys a person changed. A
  full-snapshot save would roll back whatever the AGENT wrote to the same file
  while the window was open (`last_scan_at`, the enrollment fields) -- a data-loss
  bug that would look exactly like nothing happening.
* **Failure is never a value.** An unreachable agent raises; it does not return a
  healthy-looking dict. A check-in that never happened reads as "never", not as a
  timestamp at the epoch.
* **The validators agree with the agent.** Bounds come from config.py, so what
  this window accepts is what the agent will actually apply.

Run: python3 nemesis_agent/test_agent_gui_core.py
"""
import json
import os
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import config                                                # noqa: E402
import agent_gui_core as core                                # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def check_true(label, got):
    check(label, bool(got), True)


# ── a stand-in for the agent's command listener ──────────────────────────────

class _FakeAgent:
    """A real HTTP server on a real port, answering like the agent does.

    A mock of `call_agent` would test the test. This exercises the actual socket,
    the actual JSON round-trip, and the actual error paths -- including the one
    that matters most, nobody listening at all.
    """

    def __init__(self, responder):
        self.responder = responder
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length))
                code, payload = outer.responder(body)
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", len(raw))
                self.end_headers()
                self.wfile.write(raw)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]

    def __enter__(self):
        self._prev = (config.COMMAND_HOST, config.COMMAND_PORT)
        config.COMMAND_PORT = self.port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        config.COMMAND_HOST, config.COMMAND_PORT = self._prev


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    print("validation — device name")
    check("a plain name is accepted", core.validate_device_name(" My Laptop "),
          ("My Laptop", None))
    check("an empty name is refused", core.validate_device_name("   ")[0], None)
    check("an over-long name is refused",
          core.validate_device_name("x" * (core.DEVICE_NAME_MAX + 1))[0], None)
    # Asserted on the VALUE, not on the error being None -- a validator that
    # returned (None, None) for everything would pass an error-only check while
    # accepting nothing at all.
    check("a name at the limit is accepted",
          core.validate_device_name("x" * core.DEVICE_NAME_MAX),
          ("x" * core.DEVICE_NAME_MAX, None))
    for hostile in ("<script>", 'a"b', "a'b", "a\\b", "a\nb", "a;b"):
        check("refused: %r" % hostile, core.validate_device_name(hostile)[0], None)

    print("\nvalidation — check-in interval (bounds shared with the agent)")
    check("the default is accepted",
          core.validate_poll_interval(str(config.POLL_INTERVAL_DEFAULT)),
          (config.POLL_INTERVAL_DEFAULT, None))
    check("exactly the floor is accepted",
          core.validate_poll_interval(config.POLL_INTERVAL_FLOOR)[0],
          config.POLL_INTERVAL_FLOOR)
    check("one below the floor is refused",
          core.validate_poll_interval(config.POLL_INTERVAL_FLOOR - 1)[0], None)
    check("above the ceiling is refused",
          core.validate_poll_interval(config.POLL_INTERVAL_CEILING + 1)[0], None)
    check("non-numeric is refused", core.validate_poll_interval("soon")[0], None)
    check("empty is refused", core.validate_poll_interval("")[0], None)
    check("a float is refused (not silently truncated)",
          core.validate_poll_interval("30.5")[0], None)
    # The bound the window enforces IS the bound the agent enforces. If these ever
    # diverge, this window accepts a number the agent then clamps without telling
    # anyone -- the exact silent-disagreement shape this project keeps finding.
    import agent                                             # noqa: PLC0415
    check("agent floor == config floor", agent.POLL_INTERVAL_FLOOR,
          config.POLL_INTERVAL_FLOOR)
    check("agent default == config default", agent.POLL_INTERVAL_DEFAULT,
          config.POLL_INTERVAL_DEFAULT)
    check("the shipped default parses to the same number",
          int(config.DEFAULTS["poll_interval"]), config.POLL_INTERVAL_DEFAULT)

    print("\nvalidation — a whole form reports EVERY bad field, not just the first")
    cleaned, errors = core.validate_all({
        "device_name": "", "poll_interval": "1",
        "scan_on_reconnect": True, "reputation_cache_enabled": False})
    check("both bad fields reported", sorted(errors), ["device_name", "poll_interval"])
    check("the good booleans still came through", cleaned,
          {"scan_on_reconnect": "true", "reputation_cache_enabled": "false"})

    print("\nconf writes — ONLY changed keys, and nothing else in the file moves")
    tmpdir = tempfile.mkdtemp(prefix="nemesis-gui-test-")
    prev_conf_path = config.CONF_PATH
    try:
        config.CONF_PATH = os.path.join(tmpdir, "nemesis_agent.conf")
        config.save({
            "device_name": "Old Name", "poll_interval": "300",
            "scan_on_reconnect": "true", "reputation_cache_enabled": "true",
            # Written by the AGENT, not by this window. These are what a
            # full-snapshot save would destroy.
            "last_scan_at": "2026-08-20T09:00:00",
            "enrollment_status": "approved",
            "enrollment_token": "token-that-must-survive",
            "device_id": "abcd-1234",
        })

        loaded = core.load_editable()
        check("load_editable returns only the editable keys",
              sorted(loaded), sorted(core.EDITABLE_KEYS))

        changed = core.save_changes({
            "device_name": "New Name", "poll_interval": "300",
            "scan_on_reconnect": "true", "reputation_cache_enabled": "true"})
        check("only the genuinely changed key was written", changed,
              {"device_name": "New Name"})

        after = config.load()
        check("the changed key landed", after["device_name"], "New Name")
        check("the agent's last_scan_at survived", after["last_scan_at"],
              "2026-08-20T09:00:00")
        check("enrollment_status survived", after["enrollment_status"], "approved")
        check("enrollment_token survived", after["enrollment_token"],
              "token-that-must-survive")
        check("device_id survived", after["device_id"], "abcd-1234")

        check("saving no changes writes nothing", core.save_changes(
            {"device_name": "New Name"}), {})

        print("\nrestart-vs-live classification (it decides what the window promises)")
        check("the cache toggle needs a restart",
              core.restart_required(["reputation_cache_enabled", "device_name"]),
              ["reputation_cache_enabled"])
        check("device name does not", core.restart_required(["device_name"]), [])

        print("\npending — disk vs what the agent says it is USING")
        # Agent still running the old name: that is a pending change, and the
        # window must show it rather than claiming the save took effect.
        check("a not-yet-adopted change is pending",
              core.pending_keys({"device_name": "Old Name", "poll_interval": "300",
                                 "scan_on_reconnect": "true",
                                 "reputation_cache_enabled": "true"}),
              ["device_name"])
        check("once adopted, nothing is pending",
              core.pending_keys({"device_name": "New Name", "poll_interval": "300",
                                 "scan_on_reconnect": "true",
                                 "reputation_cache_enabled": "true"}), [])
        check("a key the agent did not report is not guessed at",
              core.pending_keys({"device_name": "New Name"}), [])
    finally:
        config.CONF_PATH = prev_conf_path

    print("\ntalking to the agent — over a real socket")
    with _FakeAgent(lambda body: (200, {"ok": True, "echo": body["action"]})):
        check("status round-trips", core.fetch_status()["echo"], "status")
        check("checkin round-trips", core.request_checkin()["echo"], "checkin")
        check("scan round-trips", core.request_scan()["echo"], "scan")
        check("restart round-trips", core.request_restart()["echo"], "restart")

    print("\nfailure is an exception, never a healthy-looking dict")
    prev_port = config.COMMAND_PORT
    config.COMMAND_PORT = _free_port()          # nothing is listening there
    try:
        core.fetch_status(timeout=1.0)
        check("nobody listening raises", "returned a value", "AgentUnreachable")
    except core.AgentUnreachable as exc:
        check("nobody listening raises AgentUnreachable", True, True)
        check_true("...with a reason attached", str(exc))
    finally:
        config.COMMAND_PORT = prev_port

    with _FakeAgent(lambda body: (200, {"error": "unknown action: status"})):
        try:
            core.fetch_status()
            check("an older agent is detected", "returned a value", "AgentUnreachable")
        except core.AgentUnreachable as exc:
            check("an agent too old for `status` is detected, not rendered blank",
                  "does not support" in str(exc), True)

    with _FakeAgent(lambda body: (500, {"nope": True})):
        try:
            core.fetch_status()
            check("an HTTP error raises", "returned a value", "AgentUnreachable")
        except core.AgentUnreachable:
            check("an HTTP error raises AgentUnreachable", True, True)

    print("\nformatting — 'never' is never a date")
    check("no check-in yet", core.humanize_ago(None, 1000.0), "never")
    check("seconds", core.humanize_ago(940.0, 1000.0), "1 minute ago")
    check("one second is singular", core.humanize_ago(999.0, 1000.0), "1 second ago")
    check("hours", core.humanize_ago(1000.0 - 7200, 1000.0), "2 hours ago")
    check("a clock that jitters backwards does not print a negative",
          core.humanize_ago(1100.0, 1000.0), "just now")
    check("unknown next check-in", core.humanize_until(None, 1000.0), "unknown")
    check("an overdue check-in", core.humanize_until(900.0, 1000.0), "due now")
    check("a future check-in", core.humanize_until(1120.0, 1000.0), "in 2 minutes")

    print("\noverall state — every branch reachable, none defaulting to healthy")
    check("no agent -> unknown", core.overall_state(None)[0], "unknown")
    check("pending approval -> warn", core.overall_state(
        {"conf": {"enrollment_status": "pending"}})[0], "warn")
    check("rejected -> bad", core.overall_state(
        {"conf": {"enrollment_status": "rejected"}})[0], "bad")
    check("approved but never checked in, with an error -> bad", core.overall_state(
        {"conf": {"enrollment_status": "approved"}, "last_checkin_ok_at": None,
         "last_checkin_error": "cannot reach the appliance"})[0], "bad")
    check("approved and starting up -> warn", core.overall_state(
        {"conf": {"enrollment_status": "approved"}, "last_checkin_ok_at": None})[0],
        "warn")
    check("checked in but the last attempt failed -> warn", core.overall_state(
        {"conf": {"enrollment_status": "approved"}, "last_checkin_ok_at": 900.0,
         "last_checkin_error": "HTTP 401", "now": 1000.0})[0], "warn")
    check("healthy -> ok", core.overall_state(
        {"conf": {"enrollment_status": "approved"}, "last_checkin_ok_at": 940.0,
         "last_checkin_error": None, "now": 1000.0})[0], "ok")
    check("shutting down -> bad", core.overall_state(
        {"running": False, "conf": {}})[0], "bad")

    def _first_cap(problems):
        """First problem's capability, or a sentinel. NEVER indexes blind: a
        mutation that empties the list must FAIL cleanly, not raise IndexError --
        a crash aborts the remaining checks, changes the count, and reads as
        silence to any harness that greps for FAIL."""
        return problems[0]["capability"] if problems else "<none returned>"

    print("\nengine health — a config flag is not a working engine")
    # ⛔ THE FIXTURES BELOW USE THE REAL SHAPE, AND THE FIRST VERSION DID NOT.
    # engine_inventory.inventory() returns {"engines": {name: {...}}} -- a DICT
    # keyed by name, values carrying NO "engine" key. The original tests built a
    # LIST of dicts with an "engine" field, invented rather than read from the
    # contract, so engine_problems() returned [] for every real payload while
    # passing 125 checks and four mutations. A fixture that diverges from
    # production proves the function correct in a world that does not exist.
    _ok_base = {"conf": {"enrollment_status": "approved"},
                "last_checkin_ok_at": 940.0, "last_checkin_error": None, "now": 1000.0}

    # ── the contract itself, driven by the real producer ─────────────────────
    # This is the check that would have caught the original bug. It calls
    # inventory() rather than trusting a hand-built shape, so a future change to
    # its return type breaks HERE instead of silently emptying the GUI.
    import engine_inventory as _ei
    _real = _ei.inventory()
    check("inventory() returns a dict for 'engines' (the contract)",
          isinstance(_real.get("engines"), dict), True)
    check("...and its values carry no 'engine' key -- the dict key IS the name",
          any("engine" in v for v in _real["engines"].values()), False)
    check("engine_problems handles the REAL producer output without crashing",
          isinstance(core.engine_problems({"engine_inventory": _real}), list), True)
    # Every non-available engine in the real inventory must be reported.
    _expected = {n for n, v in _real["engines"].items()
                 if str(v.get("capability", "")).lower() not in ("available", "ok")}
    check("every non-available engine in the REAL inventory is surfaced",
          {p["name"] for p in core.engine_problems({"engine_inventory": _real})},
          _expected)

    # ── hand-built cases, in the real shape ──────────────────────────────────
    check("no inventory at all -> unchanged, still ok",
          core.overall_state(dict(_ok_base))[0], "ok")
    check("all engines available -> still ok", core.overall_state(dict(
        _ok_base, engine_inventory={"engines": {
            "clamav": {"capability": "available"},
            "yara": {"capability": "available"}}}))[0], "ok")
    check("a DEGRADED engine -> bad, not ok", core.overall_state(dict(
        _ok_base, engine_inventory={"engines": {
            "clamav": {"capability": "degraded",
                       "detail": "no signature database reported"}}}))[0], "bad")
    check("...and the reason is surfaced, not just a colour", "signature database" in
          core.overall_state(dict(_ok_base, engine_inventory={"engines": {
              "clamav": {"capability": "degraded",
                         "detail": "no signature database reported"}}}))[1], True)
    check("an ABSENT engine -> bad", core.overall_state(dict(
        _ok_base, engine_inventory={"engines": {
            "yara": {"capability": "absent", "detail": "yara not on PATH"}}}))[0], "bad")
    check("absent is reported before degraded (worse first)",
          ([p["name"] for p in core.engine_problems({"engine_inventory": {"engines": {
              "clamav": {"capability": "degraded"},
              "yara": {"capability": "absent"}}}})] or ["<none>"])[0], "yara")
    check("engine health OUTRANKS a failed check-in", core.overall_state(dict(
        _ok_base, last_checkin_error="HTTP 401", engine_inventory={"engines": {
            "clamav": {"capability": "absent", "detail": "not on PATH"}}}))[0], "bad")
    # CONTROL: without the engine problem that same status is only a warn, so the
    # assertion above is measuring the engine branch and not something else.
    check("CONTROL: the same status without an engine problem is only warn",
          core.overall_state(dict(_ok_base, last_checkin_error="HTTP 401"))[0], "warn")

    # ── an UNREADABLE inventory must not read as healthy ─────────────────────
    # The original bug's real damage: a shape it did not understand became [],
    # which is indistinguishable from "everything is fine".
    check("a LIST (the old wrong shape) is reported unreadable, NOT empty",
          _first_cap(core.engine_problems({"engine_inventory": {"engines": [
              {"engine": "clamav", "capability": "absent"}]}})),
          "unreadable")
    check("...and that makes the overall state bad, not ok", core.overall_state(dict(
        _ok_base, engine_inventory={"engines": [{"engine": "x", "capability": "absent"}]}))[0],
        "bad")
    check("a non-dict inventory is reported unreadable",
          _first_cap(core.engine_problems({"engine_inventory": "not-a-dict"})),
          "unreadable")
    check("absent inventory (never reported) stays empty, not unreadable",
          core.engine_problems({"engine_inventory": None}), [])

    print("\ncheck-in staleness — a 5-minute blip and a 5-day outage are not the same")
    _stale = dict(_ok_base)
    check("fresh check-in -> ok", core.overall_state(_stale)[0], "ok")
    check("just under the threshold -> not escalated", core.overall_state(dict(
        _ok_base, last_checkin_ok_at=0.0, now=core.STALE_CHECKIN_SECONDS - 60))[0], "ok")
    check("just over the threshold -> bad", core.overall_state(dict(
        _ok_base, last_checkin_ok_at=0.0, now=core.STALE_CHECKIN_SECONDS + 60))[0], "bad")
    check("...and says 'cached rules', not merely 'failed'", "cached rules" in
          core.overall_state(dict(_ok_base, last_checkin_ok_at=0.0,
                                  now=core.STALE_CHECKIN_SECONDS + 60))[1], True)
    check("a stale check-in outranks a transient error's wording", core.overall_state(dict(
        _ok_base, last_checkin_ok_at=0.0, now=core.STALE_CHECKIN_SECONDS + 60,
        last_checkin_error="timeout"))[0], "bad")
    # A device configured near POLL_INTERVAL_CEILING must not trip on ONE missed beat.
    check("threshold floors at three poll intervals", core.effective_stale_seconds(
        {"conf": {"poll_interval": "86400"}}), 3.0 * 86400)
    check("a normal poll interval leaves the threshold at 24h",
          core.effective_stale_seconds({"conf": {"poll_interval": "300"}}),
          core.STALE_CHECKIN_SECONDS)
    check("an unparseable poll_interval falls back, never crashes",
          core.effective_stale_seconds({"conf": {"poll_interval": "banana"}}),
          core.STALE_CHECKIN_SECONDS)
    check("checkin_age returns None rather than guessing when now is absent",
          core.checkin_age({"last_checkin_ok_at": 5.0}), None)

    print("\nconnection type — a failed read is UNKNOWN, never a confident location")
    # The sentinel split (2026-08-20). Before it, all three collapsed to
    # "vpn_remote", which was safe while the field was descriptive and stops being
    # safe the moment it decides whether to steer a device's traffic.
    check("on the subnet -> local",
          agent._detect_connection_type({"nemesis_subnet": "127.0.0.0/8"}),
          agent.CONN_LOCAL)
    check("subnet configured, nothing matched -> an affirmative remote",
          agent._detect_connection_type({"nemesis_subnet": "203.0.113.0/24"}),
          agent.CONN_REMOTE)
    check("no subnet configured -> UNKNOWN, not remote",
          agent._detect_connection_type({}), agent.CONN_UNKNOWN)
    check("blank subnet -> UNKNOWN, not remote",
          agent._detect_connection_type({"nemesis_subnet": ""}), agent.CONN_UNKNOWN)
    check("an unparseable subnet -> UNKNOWN, not remote",
          agent._detect_connection_type({"nemesis_subnet": "not-a-subnet"}),
          agent.CONN_UNKNOWN)

    print("\n...and only an AFFIRMATIVE remote may ever drive steering")
    check("confirmed remote", agent.is_confirmed_remote(agent.CONN_REMOTE), True)
    check("local is not remote", agent.is_confirmed_remote(agent.CONN_LOCAL), False)
    check("UNKNOWN is NOT remote (the whole point)",
          agent.is_confirmed_remote(agent.CONN_UNKNOWN), False)
    check("nonsense is not remote", agent.is_confirmed_remote("banana"), False)
    check("None is not remote", agent.is_confirmed_remote(None), False)

    print("\nthe HEARTBEAT stays two-valued — the server keys behaviour off it")
    # hw_monitor fires return_from_remote on
    # prev_conn_type == "vpn_remote" and conn_type == "local". Sending "unknown"
    # would break that transition silently, so the wire keeps the old contract.
    check("unknown is collapsed to remote on the wire",
          agent._connection_type_for_wire(agent.CONN_UNKNOWN), agent.CONN_REMOTE)
    check("local passes through untouched",
          agent._connection_type_for_wire(agent.CONN_LOCAL), agent.CONN_LOCAL)
    check("remote passes through untouched",
          agent._connection_type_for_wire(agent.CONN_REMOTE), agent.CONN_REMOTE)
    check("the two strings the server compares are unchanged",
          (agent.CONN_LOCAL, agent.CONN_REMOTE), ("local", "vpn_remote"))

    print("\nthe conservative branch is still taken for UNKNOWN")
    check("an unplaceable device gets the ROAMING ruleset, not office",
          agent._expected_suricata_profile(agent.CONN_UNKNOWN, {}), "roaming")
    check("...and a local one still gets office",
          agent._expected_suricata_profile(agent.CONN_LOCAL, {}), "office")
    check("an explicit profile preference still wins",
          agent._expected_suricata_profile(agent.CONN_UNKNOWN,
                                           {"suricata_profile": "office"}), "office")

    print("\nDMZ mode — the kill switch that turns protection OFF")
    check("dmz_mode is editable", "dmz_mode" in core.EDITABLE_KEYS, True)
    check("dmz_mode is a RESTART key (enforcement starts at agent boot)",
          "dmz_mode" in core.RESTART_KEYS, True)
    check("dmz_mode is a bool", "dmz_mode" in core.BOOL_KEYS, True)
    check("dmz_mode requires confirmation to enable",
          "dmz_mode" in core.CONFIRM_ON_ENABLE, True)
    check("dmz_active reads a status snapshot",
          core.dmz_active({"conf": {"dmz_mode": "true"}}), True)
    check("dmz_active reads a bare conf dict too",
          core.dmz_active({"dmz_mode": "true"}), True)
    check("dmz_active is False when off", core.dmz_active({"conf": {"dmz_mode": "false"}}),
          False)
    check("dmz_active is False on a non-dict", core.dmz_active(None), False)
    check("dmz_active defaults to False when the key is absent",
          core.dmz_active({"conf": {}}), False)
    # The warning wording is a single source of truth; the tests pin what it must
    # and must NOT claim, so it can never quietly start over- or under-stating.
    check("the DMZ warning says UDP/QUIC filtering is off",
          "UDP/QUIC" in core.DMZ_WARNING and "OFF" in core.DMZ_WARNING.upper(), True)
    check("the DMZ warning is honest that OTHER protections stay on",
          "still active" in core.DMZ_WARNING, True)

    print("\nDMZ downgrades the top-line health, and never reads 'Protected'")
    healthy_dmz = {"conf": {"enrollment_status": "approved", "dmz_mode": "true"},
                   "last_checkin_ok_at": 940.0, "last_checkin_error": None, "now": 1000.0}
    st, sentence = core.overall_state(healthy_dmz)
    check("a healthy DMZ device is warn, not ok", st, "warn")
    check("...and the headline does NOT say Protected",
          "Protected" in sentence, False)
    check("...and it names the exposure", "exposed" in sentence, True)
    # A real problem still outranks DMZ: an unreachable appliance is more urgent.
    dmz_but_failing = {"conf": {"enrollment_status": "approved", "dmz_mode": "true"},
                       "last_checkin_ok_at": 940.0,
                       "last_checkin_error": "cannot reach the appliance", "now": 1000.0}
    check("a check-in failure still outranks the DMZ notice",
          "check-in failed" in core.overall_state(dmz_but_failing)[1], True)

    print("\nDMZ is reported UP the heartbeat and is in the status allowlist")
    check("dmz_mode is in the status allowlist", "dmz_mode" in agent._STATUS_CONF_KEYS,
          True)
    snap_off = agent._status_snapshot()
    check("a snapshot carries a dmz_mode conf key",
          "dmz_mode" in snap_off["conf"], True)
    # the heartbeat payload reports dmz_mode as a real bool
    import config as _cfg
    prev = dict(agent._conf) if isinstance(agent._conf, dict) else {}
    try:
        agent._conf = dict(_cfg.DEFAULTS, dmz_mode="true", device_id="x")
        payload = agent._collect_payload(agent._conf)
        check("the heartbeat reports dmz_mode=True when on", payload["dmz_mode"], True)
        agent._conf = dict(_cfg.DEFAULTS, dmz_mode="false", device_id="x")
        check("the heartbeat reports dmz_mode=False when off",
              agent._collect_payload(agent._conf)["dmz_mode"], False)
    finally:
        agent._conf = prev

    print("\nthe DMZ enforcement predicate is the ONE source of truth")
    check("udp_filtering_suppressed True when dmz on",
          agent.udp_filtering_suppressed({"dmz_mode": "true"}), True)
    check("udp_filtering_suppressed False when dmz off",
          agent.udp_filtering_suppressed({"dmz_mode": "false"}), False)
    check("udp_filtering_suppressed False when absent",
          agent.udp_filtering_suppressed({}), False)

    print("\nthe status allowlist — a secret added to DEFAULTS must not leak")
    # The listener is unauthenticated, so this is the property that keeps a future
    # credential in config.DEFAULTS from being published to every local process.
    for secret in ("enrollment_token", "private_key_path", "public_key_path"):
        check("%s is NOT in the status allowlist" % secret,
              secret in agent._STATUS_CONF_KEYS, False)
    snapshot = agent._status_snapshot()
    check("a live snapshot exposes exactly the allowlist",
          sorted(snapshot["conf"]), sorted(agent._STATUS_CONF_KEYS))
    check("...and reports 'never' as None, not 0",
          snapshot["last_checkin_ok_at"], None)
    check("...and declares ram_recovery unavailable",
          snapshot["capabilities"]["ram_recovery"], False)
    check("...and declares the three wired actions available",
          [snapshot["capabilities"][k] for k in ("scan", "checkin", "restart")],
          [True, True, True])
    check("the window's protection keys are all in the allowlist",
          [k for k in core.PROTECTION_KEYS if k not in agent._STATUS_CONF_KEYS], [])
    check("the window's editable keys are all in the allowlist",
          [k for k in core.EDITABLE_KEYS if k not in agent._STATUS_CONF_KEYS], [])

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
