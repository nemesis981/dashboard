#!/usr/bin/env python3
"""Stage 1 step 5: retire the three broken `:5002` loopback pushes.

Run: python3 nemesis_agent/test_loopback_retirement.py

WHAT IS BEING RETIRED, and why it is safe to retire
---------------------------------------------------
The agent's command listener binds `127.0.0.1:5002` (agent.py `_start_command_
listener`). Three server-side sites POST to `http://{agent_ip}:5002`:

    dashboard.py  api_scan_trigger        (remote scan)
    dashboard.py  api_agent_notify        (on-device notification)
    hw_monitor.py _dispatch_pending_scans (queued scan on check-in)

Because the listener is bound to loopback, every one of those pushes is
unreachable for a device that is not the Nemesis box itself. ADR 0004 Stage 1
replaced this transport: tasks ride the heartbeat response and execute through
the SAME `_CommandHandler._dispatch`, so the actions survive; only the transport
is retired.

WHY THIS SUITE EXISTS, AND WHAT MAKES IT A CONTROL RATHER THAN A HAPPY PATH
--------------------------------------------------------------------------
There is exactly ONE configuration in which the old push genuinely works: a
device whose recorded `ip_address` is a loopback address (an agent on the
Nemesis host). That is the local-device case, and it is the only thing the
retirement could regress. A suite that only proved "remote pushes fail" would be
vacuous — it would pass even if the push had never worked for anybody, and it
would say nothing about what we are about to remove.

So section 1 proves BOTH halves on live sockets, in-process, against a listener
bound exactly the way the agent binds its own:
  * a push to the loopback address SUCCEEDS  — there is something real to regress
  * a push to this box's own routable address is REFUSED — the breakage is real

Both directions come from one listener and two addresses, so neither result can
be an artifact of a mock that can only produce one answer. No external network
is involved and nothing waits on a timeout: the refusal is an immediate RST from
this machine's own stack.

The premise is a TCP-level binding property, so `urllib` alone establishes it —
`requests` (dashboard) and `urllib` (hw_monitor) sit on the same socket layer and
cannot differ on whether a connection is accepted.

Structural checks use AST, never substring matching against source text. The
string "127.0.0.1" and the digits "5002" both appear in prose comments in these
files; a grep would match the comment that EXPLAINS the retirement as though it
were the code being retired. Comments are absent from the AST entirely, which is
what makes it the right instrument here.

EXPECTED RESULT BEFORE THE FIX: sections 1, 2 and 4 pass; section 3 and 5 FAIL.
That is the control working — it is asserting the post-fix state, so it must be
RED until the fix lands. A green run on unfixed code would mean the control is
broken, not that the work is done.
"""
import ast
import http.server
import json
import os
import socket
import sys
import threading
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DASHBOARD = os.path.join(REPO, "dashboard.py")
HW_MONITOR = os.path.join(REPO, "core_module", "hw_monitor", "hw_monitor.py")
AGENT = os.path.join(HERE, "agent.py")

# Declared up front, and asserted at the end. The suites in this directory
# compute `total = len(_results)`, which makes total the RAN count -- a check
# that never executes shrinks numerator and denominator together and still
# prints "N/N passed". Declaring the count separately is what turns a silently
# skipped check into a visible failure (standing practice: a verification driver
# reports `ran=` alongside `failed=`).
EXPECTED_CHECKS = 17

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


# ── helpers ──────────────────────────────────────────────────────────────────

def routable_self_address():
    """This box's own non-loopback IPv4, discovered at runtime.

    Never hardcoded -- a literal from the build machine would be wrong for any
    other user (Rule 8) and would silently turn this control into a test of an
    address that does not exist here. Returns None on failure, which the caller
    turns into an explicit FAIL rather than a skip.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connectionless: nothing is sent. 192.0.2.1 is TEST-NET-1, chosen only
        # so the kernel picks the default-route interface.
        s.connect(("192.0.2.1", 9))
        addr = s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()
    if not addr or addr.startswith("127."):
        return None
    return addr


class _Received:
    body = None


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        _Received.body = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *a):
        pass


def push(url, payload, timeout=5):
    """Reproduce the production push shape. Returns (status, error_class)."""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, None
    except urllib.error.URLError as e:
        return None, type(getattr(e, "reason", e)).__name__
    except Exception as e:
        return None, type(e).__name__


# ── AST helpers ──────────────────────────────────────────────────────────────

def parse(path):
    with open(path) as fh:
        return ast.parse(fh.read(), path)


def fstring_sites_mentioning(tree, needle):
    """Line numbers of f-strings whose literal text contains `needle`.

    An f-string is a JoinedStr node -- real code. Comments and docstrings that
    mention the same text are not JoinedStr, so they cannot match.
    """
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        text = "".join(v.value for v in node.values
                       if isinstance(v, ast.Constant) and isinstance(v.value, str))
        if needle in text:
            hits.append(node.lineno)
    return sorted(hits)


def function_named(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def calls_named(node, name):
    """Line numbers of calls to `name` (bare or attribute) inside `node`."""
    hits = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        got = fn.id if isinstance(fn, ast.Name) else (
            fn.attr if isinstance(fn, ast.Attribute) else None)
        if got == name:
            hits.append(sub.lineno)
    return sorted(hits)


def string_comparisons_in(node, varname):
    """String constants compared against `varname` -- e.g. `action == "scan"`.

    Scoped to one function body deliberately. The same action names appear in
    prose elsewhere in agent.py, and matching those would be the substring trap
    this suite exists to avoid.
    """
    found = set()
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Compare):
            continue
        left = sub.left
        if not (isinstance(left, ast.Name) and left.id == varname):
            continue
        for comp in sub.comparators:
            if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                found.add(comp.value)
    return found


# ── the suite ────────────────────────────────────────────────────────────────

def section_premise():
    """Live sockets: prove loopback-bound means remote-unreachable, both ways."""
    print("\npremise: a loopback-bound listener is reachable locally, not remotely")

    routable = routable_self_address()
    # An explicit failure, never a skip: if this box has no routable address the
    # negative control below cannot mean anything, and reporting "passed" for a
    # control that never ran is the exact defect this file guards against.
    check("this box has a routable non-loopback address to test against",
          routable is not None, True)
    if routable is None:
        print("      cannot run the negative control without one -- see above")
        return

    # Bound exactly as agent.py binds it: loopback only, ephemeral port so the
    # suite never collides with a real agent on 5002.
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        _Received.body = None
        status, err = push("http://127.0.0.1:%d" % port,
                           {"action": "notify", "message": "local"})
        check("POSITIVE a push to the loopback address is accepted", status, 200)
        # Proves the 200 came from our handler actually reading the body, not
        # from something else answering on that port.
        got = json.loads(_Received.body or b"{}").get("message")
        check("POSITIVE the listener really received the pushed body", got, "local")

        status2, err2 = push("http://%s:%d" % (routable, port),
                             {"action": "notify", "message": "remote"}, timeout=5)
        check("CONTROL the same push to this box's routable address fails",
              status2, None)
        check("CONTROL it fails by connection refusal, not by timing out",
              err2, "ConnectionRefusedError")
    finally:
        srv.shutdown()
        srv.server_close()


def section_agent_binding():
    """The binding above is what the agent actually does -- AST, not grep."""
    print("\nthe agent binds its command listener to loopback only")
    tree = parse(AGENT)
    binds = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None)
            if name == "HTTPServer" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Tuple) and len(arg.elts) == 2:
                    a, p = arg.elts
                    binds.append((getattr(a, "value", None), getattr(p, "value", None)))
    check("exactly one command listener is bound", len(binds), 1)
    if len(binds) == 1:
        check("it binds the loopback address", binds[0][0], "127.0.0.1")
        check("it binds port 5002", binds[0][1], 5002)
    else:
        check("it binds the loopback address", "no single bind found", "127.0.0.1")
        check("it binds port 5002", "no single bind found", 5002)


def section_pushes_retired():
    """The three push sites are gone. RED until the fix lands -- by design."""
    print("\nthe three :5002 push sites are retired")
    dash = fstring_sites_mentioning(parse(DASHBOARD), ":5002")
    hw = fstring_sites_mentioning(parse(HW_MONITOR), ":5002")
    if dash:
        print("      dashboard.py still pushes at lines: %s" % dash)
    if hw:
        print("      hw_monitor.py still pushes at lines: %s" % hw)
    check("dashboard.py constructs no :5002 push URL", len(dash), 0)
    check("hw_monitor.py constructs no :5002 push URL", len(hw), 0)


def section_tasking_covers_it():
    """Everything the pushes carried is reachable over the task channel."""
    print("\nthe task channel carries the actions the pushes carried")
    disp = function_named(parse(AGENT), "_dispatch")
    actions = string_comparisons_in(disp, "action") if disp else set()
    check("_dispatch handles the scan action", "scan" in actions, True)
    check("_dispatch handles the notify action", "notify" in actions, True)

    hw_tree = parse(HW_MONITOR)
    enq = function_named(hw_tree, "enqueue_task")
    check("hw_monitor exposes enqueue_task", enq is not None, True)
    args = [a.arg for a in enq.args.args] if enq else []
    check("enqueue_task takes device_id, action and params",
          args[:3], ["device_id", "action", "params"])


def section_local_device_regression():
    """The retired sites enqueue instead -- including for a loopback device.

    This is the regression half. Tasks are dispatched per device_id at check-in
    with no reference to the device's address, so a loopback device is covered by
    the same path as any other -- but only if these three call sites actually
    enqueue. RED until the fix lands.
    """
    print("\nthe retired sites enqueue a task instead (covers the local device)")
    dash_tree = parse(DASHBOARD)
    hw_tree = parse(HW_MONITOR)
    for tree, fname, label in (
            (dash_tree, "api_scan_trigger", "api_scan_trigger"),
            (dash_tree, "api_agent_notify", "api_agent_notify"),
            (hw_tree, "_dispatch_pending_scans", "_dispatch_pending_scans")):
        fn = function_named(tree, fname)
        hits = calls_named(fn, "enqueue_task") if fn else []
        check("%s enqueues a task" % label, bool(hits), True)


def main():
    section_premise()
    section_agent_binding()
    section_pushes_retired()
    section_tasking_covers_it()
    section_local_device_regression()

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    # Reported separately from pass/fail: a suite that silently ran fewer checks
    # than it declares has not "passed", whatever the ratio says.
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
