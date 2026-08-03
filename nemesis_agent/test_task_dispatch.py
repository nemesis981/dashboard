#!/usr/bin/env python3
"""Stage 1 step 3: tasks ride the heartbeat response and execute.

Run: python3 nemesis_agent/test_task_dispatch.py

This is the first step with real blast radius, so the controls matter more than
the happy path. The one I care most about: an UNVERIFIABLE task must never reach
the dispatcher. Execution has to sit downstream of verification, not beside it —
if those two are merely adjacent, a refusal logs a warning and the task runs
anyway, which is the worst possible outcome and looks fine in the logs.

The agent half is exercised behaviourally with fake responses. hw_monitor is not
imported (it opens sockets and a DB on import); its half is covered structurally
plus a real signed round-trip through server_keys.
"""
import ast
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, "/opt/nemesis/alert_manager")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_results = []
DEV = "device-under-test"


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


class FakeResponse:
    def __init__(self, payload, ok=True):
        self._payload = payload
        self.status_code = 200 if ok else 500
        self.text = json.dumps(payload) if isinstance(payload, dict) else str(payload)

    def json(self):
        if not isinstance(self._payload, dict):
            raise ValueError("not json")
        return self._payload


def main():
    tmp = tempfile.mkdtemp(prefix="nemesis-dispatch-")
    try:
        import nemesis_paths
        import server_keys
        nemesis_paths.data_dir = lambda: tmp
        server_keys.ensure_server_keypair()
        pub = serialization.load_pem_public_key(server_keys.public_key_pem().encode())

        import config
        config.CONF_PATH = os.path.join(tmp, "nemesis_agent.conf")
        import tasks as task_mod
        import agent

        # capture what reaches the dispatcher, without executing anything real
        dispatched = []
        real_dispatch = agent._CommandHandler._dispatch
        agent._CommandHandler._dispatch = (
            lambda self, action, body: dispatched.append((action, body)) or {"ok": True})

        try:
            # ── the response shape must not disturb an agent ignoring it ──
            print("backward compatibility")
            agent._task_anchor = None
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "server_time": "x", "tasks": []}), DEV)
            check("CONTROL no anchor -> nothing dispatched", dispatched, [])
            env_unarmed = server_keys.build_task(DEV, "scan", {"path": "/"})
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "tasks": [env_unarmed]}), DEV)
            check("CONTROL no anchor -> a REAL task is still refused", dispatched, [])
            agent._handle_response_tasks(FakeResponse("not json at all"), DEV)
            check("CONTROL non-JSON body is tolerated, not fatal", dispatched, [])

            # ── armed: the happy path ────────────────────────────────────
            print("\narmed agent, genuine task")
            agent._task_anchor = pub
            env = server_keys.build_task(DEV, "scan", {"path": "C:\\"})
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "tasks": [env]}), DEV)
            check("POSITIVE the task reached the dispatcher", len(dispatched), 1)
            check("POSITIVE with the right action", dispatched[0][0], "scan")
            check("POSITIVE with the right params", dispatched[0][1], {"path": "C:\\"})

            # ── THE control: unverifiable must never execute ─────────────
            print("\nunverifiable tasks must NEVER reach the dispatcher")
            for label, bad in (
                ("wrong key",
                 (lambda: (lambda k: server_keys.build_task(DEV, "scan"))(None))()),
            ):
                pass
            dispatched.clear()

            rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            forged = server_keys.build_task(DEV, "notify", {"message": "pwn"})
            import base64, hashlib
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            digest = hashlib.sha256(
                server_keys._canonical_bytes(forged)).hexdigest().encode()
            forged["signature"] = base64.b64encode(
                rogue.sign(digest, padding.PKCS1v15(), hashes.SHA256())).decode()
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "tasks": [forged]}), DEV)
            check("CONTROL forged signature -> NOT dispatched", dispatched, [])

            other = server_keys.build_task("someone-else", "scan", {"path": "/"})
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "tasks": [other]}), DEV)
            check("CONTROL task for another device -> NOT dispatched", dispatched, [])

            stale = server_keys.build_task(DEV, "scan", ttl_seconds=1,
                                           now=datetime.now() - timedelta(hours=2))
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "tasks": [stale]}), DEV)
            check("CONTROL expired task -> NOT dispatched", dispatched, [])

            tampered = server_keys.build_task(DEV, "scan", {"path": "/"})
            tampered["params"] = {"path": "C:\\Windows\\System32"}
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "tasks": [tampered]}), DEV)
            check("CONTROL tampered params -> NOT dispatched", dispatched, [])

            # ── replay executes exactly once ─────────────────────────────
            print("\nreplay executes once")
            dispatched.clear()
            once = server_keys.build_task(DEV, "notify", {"message": "hi"})
            body = {"ok": True, "tasks": [once]}
            agent._handle_response_tasks(FakeResponse(body), DEV)
            agent._handle_response_tasks(FakeResponse(body), DEV)
            agent._handle_response_tasks(FakeResponse(body), DEV)
            check("CONTROL delivered 3x, executed exactly once", len(dispatched), 1)

            # ── a mixed batch: good ones run, bad ones don't ─────────────
            print("\nmixed batch")
            dispatched.clear()
            good = server_keys.build_task(DEV, "ping")
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "tasks": [forged, good, other]}), DEV)
            check("POSITIVE only the valid task ran",
                  [a for a, _ in dispatched], ["ping"])
        finally:
            agent._CommandHandler._dispatch = real_dispatch
            agent._task_anchor = None

        # ── structural: execution is downstream of verification ─────────
        print("\nstructure")
        src = open(os.path.join(HERE, "agent.py")).read()
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_handle_response_tasks")
        body_src = ast.get_source_segment(src, fn)

        def call_lines(node, name):
            """Line numbers where `name` is actually CALLED — not where it is
            mentioned in a docstring or comment. Matching text finds the prose
            first and reports the opposite of the truth."""
            out = []
            for n in ast.walk(node):
                if isinstance(n, ast.Call):
                    f = n.func
                    ident = getattr(f, "attr", None) or getattr(f, "id", None)
                    if ident == name:
                        out.append(n.lineno)
            return sorted(out)

        v_lines = call_lines(fn, "verify_task")
        d_lines = call_lines(fn, "_dispatch")
        c_lines = call_lines(fn, "claim_task")
        check("CONTROL verify_task is actually called", bool(v_lines), True)
        check("CONTROL _dispatch is actually called", bool(d_lines), True)
        check("CONTROL verify_task runs BEFORE _dispatch",
              v_lines[0] < d_lines[0], True)
        check("CONTROL a refusal `continue`s rather than falling through",
              "continue" in body_src, True)
        check("CONTROL claim_task runs BEFORE execution (atomic, crash-safe)",
              c_lines[0] < d_lines[0], True)
        check("CONTROL no read-then-act helper is used to gate execution",
              "already_claimed" in body_src, False)

        disp = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "_dispatch")
        uses_self = any(isinstance(n, ast.Name) and n.id == "self"
                        for n in ast.walk(ast.Module(body=disp.body, type_ignores=[])))
        check("CONTROL _dispatch body never uses self (unbound call stays valid)",
              uses_self, False)

        hw = open("/opt/nemesis/core_module/hw_monitor/hw_monitor.py").read()
        hw_tree = ast.parse(hw)

        # Compare CALL sites, not definitions. _tasks_for_response is defined far
        # earlier in the file than _verify_agent_heartbeat is called, so a plain
        # text index() compares a def against a call and reports the reverse.
        def hw_call_lines(name):
            return sorted(n.lineno for n in ast.walk(hw_tree)
                          if isinstance(n, ast.Call)
                          and (getattr(n.func, "attr", None)
                               or getattr(n.func, "id", None)) == name)

        auth = hw_call_lines("_verify_agent_heartbeat")
        built = hw_call_lines("_tasks_for_response")
        check("CONTROL both are actually called", bool(auth) and bool(built), True)
        check("tasks are built AFTER the heartbeat auth gate",
              auth[0] < built[0], True)
        check("CONTROL the not_approved early-return body is unchanged",
              'b\'{"ok":false,"status":"not_approved"}\'' in hw, True)
        check("CONTROL task-building failure returns [] rather than raising",
              "return []" in hw[hw.index("def _tasks_for_response"):
                                hw.index("def _dispatch_pending_scans")], True)
        check("CONTROL local in-process scan branch untouched",
              'device_id == "local"' in hw, True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

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
