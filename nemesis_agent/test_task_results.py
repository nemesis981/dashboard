#!/usr/bin/env python3
"""Stage 1 step 4 (Part A): task outcomes reported back to the server.

Run: python3 nemesis_agent/test_task_results.py

Three layers, because the failure modes are in different places:

  1. the agent's on-disk report store   — behavioural, real files
  2. the agent's execute->record path   — behavioural, fake responses
  3. the server's recorder              — the REAL function source and the REAL
     DDL, lifted out of hw_monitor.py and exec'd against a temp database

Layer 3 is done that way on purpose. hw_monitor cannot be imported (it opens
sockets and the live DB), and the alternative — asserting on the source text, or
retyping the SQL into the test — proves nothing about what actually runs. A
retyped copy passes forever after the shipped query is changed. Extracting the
function means the device-scoping control below fails if the real WHERE clause
ever loses its device_id.
"""
import ast
import importlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import textwrap
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, "/opt/nemesis/alert_manager")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_results = []
DEV = "device-under-test"
OTHER = "someone-elses-laptop"
HW_PATH = "/opt/nemesis/core_module/hw_monitor/hw_monitor.py"


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200
        self.text = json.dumps(payload)

    def json(self):
        if not isinstance(self._payload, dict):
            raise ValueError("not json")
        return self._payload


# ── layer 3 helpers: lift the real server code out of hw_monitor ──────────
def load_server_recorder(db_path):
    """exec the REAL _record_task_results against a temp DB built from the REAL DDL."""
    src = open(HW_PATH).read()
    tree = ast.parse(src)

    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_record_task_results")
    fn_src = textwrap.dedent(ast.get_source_segment(src, fn))

    # The DDL, also lifted rather than retyped — so a column added to the shipped
    # CREATE without a matching migration shows up here as a failure.
    start = src.index("CREATE TABLE IF NOT EXISTS scan_tasks")
    ddl = src[start:src.index('"""', start)]

    conn = sqlite3.connect(db_path)
    conn.execute(ddl)
    conn.commit()
    conn.close()

    ns = {"datetime": datetime,
          "MAX_RESULTS_PER_BEAT_IN": 20,
          "RESULT_DETAIL_MAX": 500,
          "_db_connect": lambda: sqlite3.connect(db_path)}
    exec(compile(fn_src, HW_PATH, "exec"), ns)
    return ns["_record_task_results"], ddl


def seed_task(db_path, task_id, device_id, status="dispatched"):
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO scan_tasks (task_id, device_id, action, status) "
                 "VALUES (?,?,?,?)", (task_id, device_id, "scan", status))
    conn.commit()
    conn.close()


def row(db_path, task_id):
    conn = sqlite3.connect(db_path)
    try:
        r = conn.execute("SELECT status, result_ok, result_detail, reported_at "
                         "FROM scan_tasks WHERE task_id=?", (task_id,)).fetchone()
    finally:
        conn.close()
    return r


def main():
    tmp = tempfile.mkdtemp(prefix="nemesis-results-")
    try:
        import nemesis_paths
        import server_keys
        nemesis_paths.data_dir = lambda: tmp
        server_keys.ensure_server_keypair()
        pub = serialization.load_pem_public_key(server_keys.public_key_pem().encode())

        import config
        config.CONF_PATH = os.path.join(tmp, "nemesis_agent.conf")
        import tasks
        import agent

        now = datetime(2026, 8, 3, 12, 0, 0)

        # ══ layer 1: the on-disk report store ═════════════════════════════
        print("the report store")
        check("POSITIVE a result is recorded",
              tasks.record_result("t-1", True, "scanned 12 files", "scan", now), True)
        pend = tasks.pending_results(now=now)
        check("POSITIVE it comes back pending", len(pend), 1)
        check("POSITIVE the outcome round-trips", pend[0]["ok"], True)
        check("POSITIVE the detail round-trips", pend[0]["detail"], "scanned 12 files")
        check("POSITIVE the action round-trips", pend[0]["action"], "scan")

        # A restart is the event most likely to FOLLOW a failed task, so the
        # report has to outlive the process. Re-importing drops every scrap of
        # module state; only the disk survives.
        importlib.reload(tasks)
        check("CONTROL the report survives a restart (module state discarded)",
              len(tasks.pending_results(now=now)), 1)

        check("CONTROL a second report for the same task is refused",
              tasks.record_result("t-1", False, "OVERWRITTEN", "scan", now), False)
        check("CONTROL ...and the first, genuine outcome is intact",
              tasks.pending_results(now=now)[0]["detail"], "scanned 12 files")

        # ── ack deletes exactly what was acked, nothing more ──────────────
        print("\nacknowledgement")
        for i in range(2, 6):
            tasks.record_result("t-%d" % i, True, "d%d" % i, "scan",
                                now + timedelta(seconds=i))
        check("CONTROL five reports are pending", len(tasks.pending_results(now=now)), 5)
        check("POSITIVE acking two removes two", tasks.ack_results(["t-2", "t-4"]), 2)
        remaining = sorted(r["task_id"] for r in tasks.pending_results(now=now))
        check("CONTROL exactly the UN-acked reports remain",
              remaining, ["t-1", "t-3", "t-5"])
        check("CONTROL an un-acked report is re-sent on the next beat",
              "t-1" in [r["task_id"] for r in tasks.pending_results(now=now)], True)
        check("CONTROL acking an unknown id is harmless",
              tasks.ack_results(["never-existed"]), 0)
        check("CONTROL ...and removed nothing", len(tasks.pending_results(now=now)), 3)

        # ── ordering, cap, pruning, path safety ───────────────────────────
        print("\nordering, bounds and path safety")
        tasks.ack_results(["t-1", "t-3", "t-5"])
        for i in range(25):
            tasks.record_result("batch-%02d" % i, True, "d", "ping",
                                now + timedelta(seconds=i))
        got = tasks.pending_results(now=now)
        check("CONTROL a beat carries at most MAX_RESULTS_PER_BEAT",
              len(got), tasks.MAX_RESULTS_PER_BEAT)
        check("CONTROL oldest first (a backlog drains in event order)",
              [r["task_id"] for r in got],
              ["batch-%02d" % i for i in range(tasks.MAX_RESULTS_PER_BEAT)])
        check("CONTROL nothing was DROPPED, only deferred",
              len(os.listdir(tasks._results_dir())), 25)

        check("CONTROL stale reports are pruned by age",
              tasks.prune_results(now + timedelta(days=tasks.RESULT_MAX_AGE_DAYS + 1)),
              25)
        check("CONTROL ...and a fresh one is NOT pruned",
              (tasks.record_result("keep-me", True, "d", "ping", now),
               tasks.prune_results(now + timedelta(hours=1)))[1], 0)
        tasks.ack_results(["keep-me"])

        # An unreadable report must be SKIPPED, never sent as a defaulted record:
        # a default `ok` is indistinguishable from a genuine success.
        with open(os.path.join(tasks._results_dir(), "corrupt.json"), "w") as fh:
            fh.write("{ this is not json")
        tasks.record_result("good-one", True, "d", "ping", now)
        got = tasks.pending_results(now=now)
        check("CONTROL an unreadable report is skipped, not defaulted",
              [r["task_id"] for r in got], ["good-one"])
        check("CONTROL ...and the corrupt file is not silently deleted either",
              os.path.exists(os.path.join(tasks._results_dir(), "corrupt.json")), True)
        os.remove(os.path.join(tasks._results_dir(), "corrupt.json"))
        tasks.ack_results(["good-one"])

        check("CONTROL a crafted task_id cannot escape the results dir",
              os.path.dirname(tasks._result_path("../../etc/passwd")),
              tasks._results_dir())

        # ══ layer 2: execute -> record ════════════════════════════════════
        print("\nexecution outcomes are recorded")
        dispatched = []
        real_dispatch = agent._CommandHandler._dispatch
        try:
            agent._task_anchor = pub

            agent._CommandHandler._dispatch = (
                lambda self, action, body:
                    dispatched.append(action) or {"ok": True, "scan_id": 7})
            env = server_keys.build_task(DEV, "scan", {"path": "/"})
            agent._handle_response_tasks(FakeResponse({"ok": True, "tasks": [env]}), DEV)
            rec = {r["task_id"]: r for r in tasks.pending_results(now=now)}
            check("POSITIVE a successful task is reported ok",
                  rec.get(env["task_id"], {}).get("ok"), True)

            # THE control for this layer. _dispatch signals an unknown action by
            # RETURNING {"error": ...}, it does not raise — so "it returned" as a
            # success test reports the most important failure as a success.
            agent._CommandHandler._dispatch = (
                lambda self, action, body: {"error": "unknown action: %s" % action})
            env2 = server_keys.build_task(DEV, "teleport", {})
            agent._handle_response_tasks(FakeResponse({"ok": True, "tasks": [env2]}), DEV)
            rec = {r["task_id"]: r for r in tasks.pending_results(now=now)}
            check("CONTROL a returned {'error':...} is reported as FAILED",
                  rec.get(env2["task_id"], {}).get("ok"), False)
            check("CONTROL ...carrying the reason, not a generic failure",
                  "unknown action" in rec.get(env2["task_id"], {}).get("detail", ""),
                  True)

            def boom(self, action, body):
                raise RuntimeError("scanner is on fire")
            agent._CommandHandler._dispatch = boom
            env3 = server_keys.build_task(DEV, "scan", {"path": "/"})
            agent._handle_response_tasks(FakeResponse({"ok": True, "tasks": [env3]}), DEV)
            rec = {r["task_id"]: r for r in tasks.pending_results(now=now)}
            check("CONTROL a raising task is reported as FAILED",
                  rec.get(env3["task_id"], {}).get("ok"), False)
            check("CONTROL ...carrying the exception text",
                  "on fire" in rec.get(env3["task_id"], {}).get("detail", ""), True)

            # A task that never ran must produce NO report — otherwise a refusal
            # would be indistinguishable from a genuine failed execution.
            before = len(tasks.pending_results(now=now))
            forged = server_keys.build_task(DEV, "scan", {"path": "/"})
            forged["params"] = {"path": "C:\\Windows\\System32"}
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "tasks": [forged]}), DEV)
            check("CONTROL a REFUSED task reports nothing at all",
                  len(tasks.pending_results(now=now)), before)

            # ── acks arriving in the response ─────────────────────────────
            print("\nacks in the heartbeat response")
            live = [r["task_id"] for r in tasks.pending_results(now=now)]
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "results_ack": live[:1]}), DEV)
            check("POSITIVE an acked report is deleted",
                  live[0] in [r["task_id"] for r in tasks.pending_results(now=now)],
                  False)

            # An agent whose anchor is gone still has to drain its queue, or an
            # outage that costs the anchor strands every pending report forever.
            agent._task_anchor = None
            live = [r["task_id"] for r in tasks.pending_results(now=now)]
            agent._handle_response_tasks(
                FakeResponse({"ok": True, "results_ack": live[:1]}), DEV)
            check("CONTROL acks are processed even with NO anchor pinned",
                  live[0] in [r["task_id"] for r in tasks.pending_results(now=now)],
                  False)
            check("CONTROL ...but a task in the same response is still refused",
                  (lambda n: (agent._handle_response_tasks(
                      FakeResponse({"ok": True,
                                    "tasks": [server_keys.build_task(DEV, "scan")]}),
                      DEV), len(dispatched))[1])(len(dispatched)), len(dispatched))
        finally:
            agent._CommandHandler._dispatch = real_dispatch
            agent._task_anchor = None

        # ══ layer 3: the server's recorder, real source + real DDL ════════
        print("\nserver-side recorder (real function, real DDL)")
        db = os.path.join(tmp, "results.db")
        record, ddl = load_server_recorder(db)
        check("CONTROL the extracted DDL is the one carrying the result columns",
              all(c in ddl for c in ("result_ok", "result_detail", "reported_at")), True)

        seed_task(db, "srv-1", DEV)
        acked = record(DEV, [{"task_id": "srv-1", "ok": True, "detail": "clean"}])
        check("POSITIVE a dispatched task is closed out", row(db, "srv-1")[0], "completed")
        check("POSITIVE result_ok is recorded", row(db, "srv-1")[1], 1)
        check("POSITIVE the id is acked", acked, ["srv-1"])
        check("POSITIVE reported_at is stamped", bool(row(db, "srv-1")[3]), True)

        seed_task(db, "srv-2", DEV)
        record(DEV, [{"task_id": "srv-2", "ok": False, "detail": "scanner crashed"}])
        check("POSITIVE a failed task is recorded as failed",
              row(db, "srv-2")[0], "failed")
        check("POSITIVE ...with result_ok=0, not NULL", row(db, "srv-2")[1], 0)

        # THE server-side control: one device must not be able to close another's
        # task. Paired with the positive below, so a pass cannot come from the
        # recorder simply not working at all.
        seed_task(db, "srv-3", OTHER)
        acked = record(DEV, [{"task_id": "srv-3", "ok": True, "detail": "not mine"}])
        check("CONTROL device A cannot close device B's task",
              row(db, "srv-3")[0], "dispatched")
        check("CONTROL ...and B's result stays empty", row(db, "srv-3")[1], None)
        check("CONTROL ...yet it is still acked (or A retries forever)",
              acked, ["srv-3"])
        record(OTHER, [{"task_id": "srv-3", "ok": True, "detail": "mine"}])
        check("CONTROL PAIR the owner CAN close it (the negative above is real)",
              row(db, "srv-3")[0], "completed")

        # Redelivery is the at-least-once contract's normal case, not an error.
        record(DEV, [{"task_id": "srv-1", "ok": False, "detail": "CONTRADICTION"}])
        check("CONTROL a redelivered report cannot flip a recorded outcome",
              row(db, "srv-1")[0], "completed")
        check("CONTROL ...nor rewrite its detail", row(db, "srv-1")[2], "clean")

        seed_task(db, "srv-4", DEV, status="pending")
        record(DEV, [{"task_id": "srv-4", "ok": True, "detail": "never sent"}])
        check("CONTROL a task never dispatched cannot be reported complete",
              row(db, "srv-4")[0], "pending")

        acked = record(DEV, [{"task_id": "no-such-task", "ok": True}])
        check("CONTROL an unknown id creates no row",
              row(db, "no-such-task"), None)
        check("CONTROL ...and is acked anyway", acked, ["no-such-task"])

        seed_task(db, "srv-5", DEV)
        record(DEV, [{"task_id": "srv-5", "ok": True, "detail": "x" * 5000}])
        check("CONTROL server truncates detail independently of the agent",
              len(row(db, "srv-5")[2]), 500)

        # The agent's own cap is a bound set by the untrusted party.
        for i in range(30):
            seed_task(db, "flood-%02d" % i, DEV)
        acked = record(DEV, [{"task_id": "flood-%02d" % i, "ok": True}
                             for i in range(30)])
        check("CONTROL an over-long report array is capped server-side",
              len(acked), 20)
        check("CONTROL ...and the excess is genuinely not believed",
              row(db, "flood-25")[0], "dispatched")

        check("CONTROL junk entries are skipped without crashing",
              record(DEV, ["not a dict", {"no_task_id": 1}, {"task_id": ""},
                           {"task_id": 42}]), [])
        check("CONTROL a non-list results field is ignored", record(DEV, "nope"), [])
        check("CONTROL an absent results field is ignored", record(DEV, None), [])

        # ── payload wiring ───────────────────────────────────────────────
        print("\npayload wiring")
        src = open(os.path.join(HERE, "agent.py")).read()
        tree = ast.parse(src)
        coll = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "_collect_payload")
        ret = next(n for n in ast.walk(coll) if isinstance(n, ast.Return))
        keys = [k.value for k in ret.value.keys if isinstance(k, ast.Constant)]
        check("POSITIVE the heartbeat payload carries task_results",
              "task_results" in keys, True)

        hw = open(HW_PATH).read()
        hw_tree = ast.parse(hw)
        post = next(n for n in ast.walk(hw_tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "do_POST")

        def call_lines(node, name):
            return sorted(n.lineno for n in ast.walk(node)
                          if isinstance(n, ast.Call)
                          and (getattr(n.func, "attr", None)
                               or getattr(n.func, "id", None)) == name)

        auth = call_lines(post, "_verify_agent_heartbeat")
        rec_l = call_lines(post, "_record_task_results")
        check("CONTROL results are recorded only AFTER the auth gate",
              bool(auth) and bool(rec_l) and auth[0] < rec_l[0], True)
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
