#!/usr/bin/env python3
"""Server key rotation: authorised by the old key, PROVING possession of the new.

Run: python3 nemesis_agent/test_key_rotation.py

Two checks carry this design, and both are ones a silently-skipped implementation
would pass:

  1. PROOF OF POSSESSION. The envelope signature only proves the server ASKED for
     the change. If the new public key it hands out has no matching private half
     on the server — a typo, a truncated file, the wrong key pasted in — every
     device that honours it is permanently unreachable, because the key that
     could have rescued them is the one they just discarded. A verifier that
     skips the PoP looks identical to one that checks it, right up to that point.

  2. ROTATION NEVER REACHES _dispatch. The command listener on 127.0.0.1:5002 is
     unauthenticated. An action reachable from the dispatcher is an action any
     local process can invoke, and re-anchoring trust is the last thing that
     should be available that way.

All key material is generated into a throwaway temp directory.
"""
import ast
import base64
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, "/opt/nemesis/alert_manager")

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_results = []
DEV = "device-under-test"


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def reason(fn):
    try:
        fn()
    except Exception as e:
        return getattr(e, "reason", type(e).__name__)
    return "ACCEPTED"


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def main():
    tmp = tempfile.mkdtemp(prefix="nemesis-rotation-")
    try:
        import nemesis_paths
        import server_keys
        nemesis_paths.data_dir = lambda: tmp
        server_keys.ensure_server_keypair()

        import config
        config.CONF_PATH = os.path.join(tmp, "nemesis_agent.conf")
        os.makedirs(config.keys_dir(), exist_ok=True)
        import enrollment
        import tasks
        import agent

        old_fp = server_keys.current_fingerprint()
        anchor_path = enrollment._server_key_path()

        def anchor_bytes():
            try:
                with open(anchor_path, "rb") as fh:
                    return fh.read()
            except FileNotFoundError:
                return None

        # Pin the current key, as an installer would.
        enrollment.pin_server_key(server_keys.public_key_b64())
        check("SETUP the agent is anchored to the current key",
              enrollment.server_key_fingerprint(), old_fp)

        # ── staging ───────────────────────────────────────────────────────
        print("staging")
        check("CONTROL nothing is staged initially",
              server_keys.staged_fingerprint(), None)
        staged = server_keys.stage_new_keypair()
        new_fp = staged["fingerprint"]
        check("POSITIVE a new pair is staged", server_keys.staged_fingerprint(), new_fp)
        check("CONTROL the staged key is genuinely different", new_fp == old_fp, False)
        check("CONTROL the CURRENT key is untouched by staging",
              server_keys.current_fingerprint(), old_fp)
        check("CONTROL staging twice is refused (in-flight tasks would break)",
              reason(server_keys.stage_new_keypair), "RuntimeError")
        check("CONTROL the staged private key is not world-readable",
              oct(os.stat(server_keys._path(
                  server_keys.NEW_PRIVATE_NAME)).st_mode)[-3:], "600")

        # ── the happy path ────────────────────────────────────────────────
        print("\na genuine rotation")
        agent._task_anchor = enrollment.pinned_server_key()
        env = server_keys.build_rotation_task(DEV)
        check("POSITIVE the envelope verifies against the OLD anchor",
              tasks.verify_task(dict(env), DEV, agent._task_anchor)["action"],
              tasks.ROTATE_ACTION)
        check("POSITIVE proof of possession verifies",
              tasks.verify_rotation(env, DEV) is not None, True)

        before = anchor_bytes()
        agent._handle_response_tasks(FakeResponse({"ok": True, "tasks": [env]}), DEV)
        check("POSITIVE the anchor is now the new key",
              enrollment.server_key_fingerprint(), new_fp)
        check("POSITIVE ...on disk, so it survives a restart",
              enrollment.server_key_fingerprint(), new_fp)
        check("POSITIVE ...and in memory, so no restart is needed",
              tasks._canonical_bytes({"a": 1}) is not None
              and agent._task_anchor is not None, True)
        import hashlib
        check("POSITIVE the in-memory anchor IS the new key",
              hashlib.sha256(agent._task_anchor.public_bytes(
                  serialization.Encoding.DER,
                  serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
              new_fp)
        check("POSITIVE the previous anchor is kept for recovery",
              os.path.exists(anchor_path + ".prev"), True)
        check("CONTROL ...and it is the key we were on before",
              open(anchor_path + ".prev", "rb").read(), before)

        # After cutover the new key signs; the old must stop being accepted.
        server_keys.cutover()
        check("POSITIVE cutover makes the staged key current",
              server_keys.current_fingerprint(), new_fp)
        check("POSITIVE the previous keypair is retained", server_keys.have_prev_keypair(), True)
        good = server_keys.build_task(DEV, "ping")
        check("POSITIVE a task signed by the NEW key verifies",
              tasks.verify_task(dict(good), DEV, agent._task_anchor)["action"], "ping")
        old_signed = dict(good)
        old_signed["signature"] = server_keys.sign_task(
            {k: v for k, v in good.items() if k != "signature"},
            key_path=server_keys._path(server_keys.PREV_PRIVATE_NAME))
        check("CONTROL a task signed by the OLD key is now REJECTED",
              reason(lambda: tasks.verify_task(old_signed, DEV, agent._task_anchor)),
              "bad_signature")

        # ── THE control: proof of possession ──────────────────────────────
        print("\nproof of possession (the check that prevents bricking)")
        # Fresh agent state anchored to the current key.
        os.remove(anchor_path)
        enrollment.pin_server_key(server_keys.public_key_b64())
        agent._task_anchor = enrollment.pinned_server_key()
        server_keys.abort_rotation()
        staged2 = server_keys.stage_new_keypair()
        fp2 = staged2["fingerprint"]

        def rotation_with(mutate, sign_with=None):
            """A rotation task, re-signed AFTER mutation with the key the agent
            currently trusts — so the envelope signature is always valid and only
            the PoP is at issue. Signing with a key the agent does not trust
            would make every check below pass for the wrong reason (bad_signature
            rather than bad PoP), which is a control that cannot fail."""
            e = server_keys.build_rotation_task(DEV)
            mutate(e)
            e.pop("signature", None)
            e["signature"] = server_keys.sign_task(e, key_path=sign_with)
            return e

        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_b64 = base64.b64encode(rogue.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

        def swap_key(e):
            e["params"]["new_public_key"] = rogue_b64
            e["params"]["new_key_sha256"] = server_keys.key_fingerprint(
                rogue.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo))
        bad = rotation_with(swap_key)
        check("CONTROL a valid envelope with a MISMATCHED PoP is refused",
              reason(lambda: tasks.verify_rotation(bad, DEV)), "bad_proof_of_possession")

        anchor_before = anchor_bytes()
        agent._handle_response_tasks(FakeResponse({"ok": True, "tasks": [bad]}), DEV)
        check("CONTROL ...and the anchor is byte-identical afterwards",
              anchor_bytes(), anchor_before)

        # A PoP lifted from another device's rotation must not transfer.
        other = server_keys.build_rotation_task("someone-else")
        lifted = rotation_with(lambda e: e["params"].__setitem__("pop", other["params"]["pop"]))
        check("CONTROL a PoP lifted from ANOTHER DEVICE is refused",
              reason(lambda: tasks.verify_rotation(lifted, DEV)),
              "bad_proof_of_possession")

        # ...nor from a different task to the same device.
        other_task = server_keys.build_rotation_task(DEV)
        lifted2 = rotation_with(
            lambda e: e["params"].__setitem__("pop", other_task["params"]["pop"]))
        check("CONTROL a PoP from a DIFFERENT TASK to this device is refused",
              reason(lambda: tasks.verify_rotation(lifted2, DEV)),
              "bad_proof_of_possession")

        # The declared fingerprint must match the key it accompanies.
        wrong_fp = rotation_with(
            lambda e: e["params"].__setitem__("new_key_sha256", "0" * 64))
        check("CONTROL a fingerprint that does not match its key is refused",
              reason(lambda: tasks.verify_rotation(wrong_fp, DEV)), "rotation_malformed")

        for label, mut in (
            ("garbage key", lambda e: e["params"].__setitem__("new_public_key", "!!!!")),
            ("absent key", lambda e: e["params"].pop("new_public_key")),
            ("absent pop", lambda e: e["params"].pop("pop")),
            ("no params", lambda e: e.__setitem__("params", None)),
        ):
            m = rotation_with(mut)
            check("CONTROL %s is refused" % label,
                  reason(lambda m=m: tasks.verify_rotation(m, DEV)), "rotation_malformed")

        agent._handle_response_tasks(
            FakeResponse({"ok": True, "tasks": [rotation_with(
                lambda e: e["params"].__setitem__("new_public_key", "!!!!"))]}), DEV)
        check("CONTROL no malformed key ever reaches disk",
              anchor_bytes(), anchor_before)
        check("CONTROL ...and no .tmp anchor is left behind",
              os.path.exists(anchor_path + ".tmp"), False)

        # ── rotation must never be reachable from the dispatcher ──────────
        print("\nrotation is unreachable from the unauthenticated loopback")
        r = agent._CommandHandler._dispatch(None, tasks.ROTATE_ACTION, {
            "new_public_key": rogue_b64, "new_key_sha256": "x", "pop": "x"})
        check("CONTROL _dispatch does not know the rotation action",
              "unknown action" in str(r.get("error", "")), True)
        check("CONTROL ...and the anchor is untouched", anchor_bytes(), anchor_before)

        src = open(os.path.join(HERE, "agent.py")).read()
        tree = ast.parse(src)
        disp = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "_dispatch")
        # Compare STRING CONSTANTS in the dispatcher, not a substring of the file:
        # the action name appears in prose and in the handler, so a text search
        # finds it regardless and reports the opposite of the truth.
        consts = {n.value for n in ast.walk(disp)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        check("CONTROL the dispatcher has no branch for the rotation action",
              tasks.ROTATE_ACTION in consts, False)

        handler = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                       and n.name == "_handle_response_tasks")
        calls = {getattr(n.func, "attr", None) or getattr(n.func, "id", None)
                 for n in ast.walk(handler) if isinstance(n, ast.Call)}
        check("CONTROL the verified path is the one that rotates",
              "_rotate_server_anchor" in calls, True)
        rot = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                   and n.name == "_rotate_server_anchor")
        rot_calls = [getattr(n.func, "attr", None) or getattr(n.func, "id", None)
                     for n in ast.walk(rot) if isinstance(n, ast.Call)]
        check("CONTROL PoP is verified before the anchor is written",
              rot_calls.index("verify_rotation") < rot_calls.index("replace_server_key"),
              True)

        # ── no-op: a rotation redelivered to a device already on that key ──
        print("\nno-op rotation (redelivery to an already-rotated device)")
        server_keys.abort_rotation()
        os.remove(anchor_path)
        enrollment.pin_server_key(server_keys.public_key_b64())
        agent._task_anchor = enrollment.pinned_server_key()
        st_noop = server_keys.stage_new_keypair()
        first = server_keys.build_rotation_task(DEV)
        agent._handle_response_tasks(FakeResponse({"ok": True, "tasks": [first]}), DEV)
        check("SETUP the device rotated to the staged key",
              enrollment.server_key_fingerprint(), st_noop["fingerprint"])
        # A DIFFERENT task_id for the same rotation — the claim store does not
        # block it, so the no-op branch is what must handle it.
        again = server_keys.build_rotation_task(
            DEV, sign_with=server_keys._path(server_keys.NEW_PRIVATE_NAME))
        res = agent._rotate_server_anchor(again, DEV)
        check("CONTROL rotating to the key already held reports rotated=False",
              res.get("rotated"), False)
        check("CONTROL ...but is not reported as an error", res.get("ok"), True)
        check("CONTROL ...and the anchor is unchanged",
              enrollment.server_key_fingerprint(), st_noop["fingerprint"])

        # ── the gap this suite found: which key signs an ORDINARY task ────
        # A device that rotates BEFORE cutover trusts the staged key while the
        # server still signs everything else with the current one. Signing by
        # habit rather than by device leaves it untaskable for the whole window.
        print("\nsigning key follows the device, not the server")
        cur_fp = server_keys.current_fingerprint()
        check("CONTROL a device on the current key -> sign with current",
              server_keys.signing_key_for_fingerprint(cur_fp), None)
        check("CONTROL a device that never rotated -> sign with current",
              server_keys.signing_key_for_fingerprint(None), None)
        check("POSITIVE a device on the STAGED key -> sign with the staged key",
              server_keys.signing_key_for_fingerprint(st_noop["fingerprint"]),
              server_keys._path(server_keys.NEW_PRIVATE_NAME))
        check("CONTROL an unrecognised fingerprint -> current, never an outage",
              server_keys.signing_key_for_fingerprint("f" * 64), None)

        # Behavioural: the rotated device must actually ACCEPT that task.
        signer = server_keys.signing_key_for_fingerprint(
            enrollment.server_key_fingerprint())
        t = server_keys.build_task(DEV, "ping", sign_with=signer)
        check("POSITIVE a rotated device accepts a task signed for its anchor",
              tasks.verify_task(dict(t), DEV, agent._task_anchor)["action"], "ping")
        habit = server_keys.build_task(DEV, "ping")
        check("CONTROL ...and would have REJECTED one signed with the current key",
              reason(lambda: tasks.verify_task(habit, DEV, agent._task_anchor)),
              "bad_signature")
        server_keys.cutover()
        check("POSITIVE after cutover a straggler on the old key is still reachable",
              server_keys.signing_key_for_fingerprint(cur_fp),
              server_keys._path(server_keys.PREV_PRIVATE_NAME))

        # ── defence-in-depth layers, exercised on their OWN terms ────────
        # Both of these were found by mutation testing: the product code was
        # correct, but nothing proved it. replace_server_key's parse guard is
        # unreachable through a rotation (verify_rotation rejects a malformed key
        # first), and the post-write mismatch branch never fires unless a bad
        # write is injected. An untested safety check is indistinguishable from
        # an absent one.
        print("\ndefence in depth (layers the happy path never reaches)")
        keep = anchor_bytes()
        check("CONTROL replace_server_key refuses garbage on its own",
              enrollment.replace_server_key(b"-----BEGIN PUBLIC KEY-----\nnope\n"),
              False)
        check("CONTROL ...leaving the anchor byte-identical", anchor_bytes(), keep)
        check("CONTROL ...and no .tmp anchor behind",
              os.path.exists(anchor_path + ".tmp"), False)
        check("CONTROL replace_server_key accepts a REAL key (the negative is real)",
              enrollment.replace_server_key(keep), True)

        # Inject a write that claims success but lands the wrong bytes.
        real_replace = enrollment.replace_server_key
        server_keys.abort_rotation()
        st_bad = server_keys.stage_new_keypair()
        rot = server_keys.build_rotation_task(
            DEV, sign_with=server_keys.signing_key_for_fingerprint(
                enrollment.server_key_fingerprint()))
        agent._task_anchor = enrollment.pinned_server_key()
        before_bad = anchor_bytes()

        def lying_replace(pem):
            real_replace(before_bad)        # writes the OLD key, reports success
            return True
        enrollment.replace_server_key = lying_replace
        try:
            res = agent._rotate_server_anchor(rot, DEV)
        finally:
            enrollment.replace_server_key = real_replace
        check("CONTROL a write that lands the WRONG bytes is caught",
              res.get("error"), "post_write_mismatch")
        check("CONTROL ...detected from a fresh read of the anchor",
              enrollment.server_key_fingerprint() == st_bad["fingerprint"], False)
        check("CONTROL ...and it is NOT reported as a success", res.get("ok"), False)
        check("CONTROL ...the in-memory anchor was not advanced either",
              hashlib.sha256(agent._task_anchor.public_bytes(
                  serialization.Encoding.DER,
                  serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
              == st_bad["fingerprint"], False)
        server_keys.abort_rotation()

        # ── the outcome reaches the result channel ────────────────────────
        print("\nthe outcome is reported (step 4 Part A)")
        rdir = tasks._results_dir()
        if os.path.isdir(rdir):
            for f in os.listdir(rdir):
                os.remove(os.path.join(rdir, f))
        server_keys.abort_rotation()
        st = server_keys.stage_new_keypair()
        env = server_keys.build_rotation_task(DEV)
        agent._handle_response_tasks(FakeResponse({"ok": True, "tasks": [env]}), DEV)
        rep = {r["task_id"]: r for r in tasks.pending_results()}
        check("POSITIVE a successful rotation is reported ok",
              rep.get(env["task_id"], {}).get("ok"), True)
        check("POSITIVE ...and the anchor really did change",
              enrollment.server_key_fingerprint(), st["fingerprint"])

        bad2 = rotation_with(swap_key, sign_with=server_keys.signing_key_for_fingerprint(
            enrollment.server_key_fingerprint()))
        agent._handle_response_tasks(FakeResponse({"ok": True, "tasks": [bad2]}), DEV)
        rep = {r["task_id"]: r for r in tasks.pending_results()}
        check("CONTROL a refused rotation is reported as FAILED",
              rep.get(bad2["task_id"], {}).get("ok"), False)
        check("CONTROL ...naming the reason",
              rep.get(bad2["task_id"], {}).get("detail"), "bad_proof_of_possession")
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
