#!/usr/bin/env python3
"""Ruleset updates install only bytes the server actually signed for.

Run: python3 nemesis_agent/test_rules_integrity.py

THE BUG THIS EXISTS TO PREVENT, reproduced rather than described: the product's
own /api/agent/rules is not in dashboard's _AUTH_EXEMPT, so it 302s to the login
page. requests follows redirects by default, so the agent saw HTTP 200 with 2756
bytes of HTML. The old _update_suricata_rules never checked status and wrote
r.content straight over the live ruleset, then logged "Updated rules for
profile=office". Detection silently off, logs green. Confirmed live 2026-08-03.

Every fetch here goes to a throwaway HTTP server on 127.0.0.1 started by this
test — nothing touches the dashboard or the live ruleset.
"""
import hashlib
import http.server
import json
import os
import shutil
import socket
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, "/opt/nemesis/alert_manager")

_results = []
GOOD_RULES = (b'alert tcp any any -> any 80 (msg:"test data 2026-08-03 rule";'
              b' sid:1000001; rev:1;)\n')
LOGIN_HTML = b"<!doctype html>\n<html lang=\"en\">\n<head><title>Sign in</title>\n" + b"x" * 200


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


class Handler(http.server.BaseHTTPRequestHandler):
    """Serves the exact conditions the agent has to survive."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/good":
            self._send(200, GOOD_RULES)
        elif self.path == "/tampered":
            self._send(200, GOOD_RULES.replace(b"1000001", b"9999999"))
        elif self.path == "/short":
            self._send(200, GOOD_RULES[:10])
        elif self.path == "/huge":
            self._send(200, b"x" * (len(GOOD_RULES) + 5000))
        elif self.path == "/login-redirect":
            # THE live bug: 302 -> a login page that answers 200.
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        elif self.path == "/login":
            self._send(200, LOGIN_HTML)
        elif self.path == "/notfound":
            self._send(404, b'{"error":"no rules"}')
        elif self.path == "/boom":
            self._send(500, b"internal error")
        else:
            self._send(404, b"?")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    tmp = tempfile.mkdtemp(prefix="nemesis-rules-")
    port = free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % port

    try:
        import config
        config.CONF_PATH = os.path.join(tmp, "nemesis_agent.conf")
        import agent
        import rules_dist

        # Point the agent's ruleset directory at the throwaway tree.
        agent._HERE = tmp
        agent._conf = {"device_id": "d", "nemesis_ip": "127.0.0.1"}
        rules_dir = os.path.join(tmp, "suricata_rules")
        dest = os.path.join(rules_dir, "office.rules")

        good_sha = hashlib.sha256(GOOD_RULES).hexdigest()
        good_size = len(GOOD_RULES)

        def upd(url, sha=good_sha, size=good_size, profile="office"):
            return agent._update_suricata_rules(base + url, sha, size, profile)

        def on_disk():
            try:
                with open(dest, "rb") as fh:
                    return fh.read()
            except FileNotFoundError:
                return None

        # ── the positive, first: everything below must be measured against a
        #    path that genuinely works, or the refusals prove nothing ────────
        print("a genuine ruleset")
        r = upd("/good")
        check("POSITIVE a matching digest installs", r["ok"], True)
        check("POSITIVE the installed bytes are the signed bytes", on_disk(), GOOD_RULES)
        check("POSITIVE the reported digest matches", r["sha256"], good_sha)
        check("POSITIVE no .tmp is left behind",
              os.path.exists(dest + ".tmp"), False)

        # ── THE regression: the live bug, reproduced ──────────────────────
        print("\nthe live bug: a login page served as a ruleset")
        r = upd("/login-redirect")
        check("CONTROL a 302-to-login is REFUSED, not followed",
              r["error"], "http_status_302")
        check("CONTROL ...and the real ruleset is untouched", on_disk(), GOOD_RULES)
        # Prove the old failure mode is genuinely impossible now: even fetched
        # directly, the login page cannot match a ruleset digest.
        r = agent._update_suricata_rules(base + "/login", good_sha, good_size, "office")
        check("CONTROL the login page itself cannot pass as rules",
              r["error"] in ("size_mismatch", "digest_mismatch"), True)
        check("CONTROL ...ruleset still untouched", on_disk(), GOOD_RULES)

        # ── content authenticity ──────────────────────────────────────────
        print("\ncontent authenticity")
        r = upd("/tampered")
        check("CONTROL one altered byte is refused", r["error"], "digest_mismatch")
        check("CONTROL ...leaving the old ruleset byte-identical",
              on_disk(), GOOD_RULES)
        check("CONTROL the refusal reports what it actually got",
              len(r.get("received_sha256", "")), 64)

        r = upd("/short")
        check("CONTROL a truncated body is refused", r["error"], "size_mismatch")
        check("CONTROL ...old ruleset intact", on_disk(), GOOD_RULES)

        r = upd("/huge")
        check("CONTROL an oversized body is refused", r["error"], "size_mismatch")
        check("CONTROL ...aborted mid-stream, not buffered whole",
              r["received"] <= good_size + agent.RULES_CHUNK, True)
        check("CONTROL ...old ruleset intact", on_disk(), GOOD_RULES)

        # ── the mandatory digest: what closes the loopback path ───────────
        print("\nthe digest is mandatory (closes the unauthenticated loopback)")
        for label, sha in (("absent", None), ("empty", ""),
                           ("too short", "abc123"), ("not hex", "z" * 64)):
            r = agent._update_suricata_rules(base + "/good", sha, good_size, "office")
            check("CONTROL a %s digest is refused" % label,
                  r["error"], "digest_required")
        check("CONTROL ...ruleset untouched throughout", on_disk(), GOOD_RULES)

        # The loopback listener is unauthenticated, so this is the actual
        # attack path — a local process calling update_rules with its own URL.
        r = agent._CommandHandler._dispatch(
            None, "update_rules", {"rules_url": base + "/tampered"})
        check("CONTROL an unauthenticated loopback call cannot install rules",
              r["ok"], False)
        check("CONTROL ...refused for want of a digest", r["error"], "digest_required")
        check("CONTROL ...ruleset untouched", on_disk(), GOOD_RULES)

        # ── other refusals ────────────────────────────────────────────────
        print("\nremaining refusals")
        r = upd("/notfound")
        check("CONTROL a 404 body is refused", r["error"], "http_status_404")
        r = upd("/boom")
        check("CONTROL a 500 body is refused", r["error"], "http_status_500")
        check("CONTROL ...old ruleset intact after both", on_disk(), GOOD_RULES)

        r = agent._update_suricata_rules("file:///etc/passwd", good_sha, good_size)
        check("CONTROL a non-http scheme is refused", r["error"], "bad_scheme")
        r = agent._update_suricata_rules("", good_sha, good_size)
        check("CONTROL an empty url is refused", r["error"], "no_rules_url")
        r = agent._update_suricata_rules(base + "/good", good_sha, None)
        check("CONTROL a missing size is refused", r["error"], "size_required")
        r = agent._update_suricata_rules(base + "/good", good_sha, 0)
        check("CONTROL a zero size is refused", r["error"], "size_required")
        r = agent._update_suricata_rules(base + "/good", good_sha,
                                         agent.MAX_RULES_BYTES + 1)
        check("CONTROL an over-cap declared size is refused before fetching",
              r["error"], "too_large_declared")
        r = agent._update_suricata_rules("http://127.0.0.1:1/good", good_sha, good_size)
        check("CONTROL an unreachable server is refused, not defaulted",
              r["error"], "fetch_failed")
        check("CONTROL ruleset survived every refusal above", on_disk(), GOOD_RULES)

        # ── the result is REPORTED, not swallowed ─────────────────────────
        print("\noutcomes reach the result channel (step 4 Part A)")
        import tasks
        for f in os.listdir(tasks._results_dir()) if os.path.isdir(
                tasks._results_dir()) else []:
            os.remove(os.path.join(tasks._results_dir(), f))
        r = agent._CommandHandler._dispatch(
            None, "update_rules", {"rules_url": base + "/good"})
        check("CONTROL _dispatch returns the REAL outcome, not {'ok':True}",
              r["ok"], False)
        r2 = agent._CommandHandler._dispatch(
            None, "update_rules", {"rules_url": base + "/good",
                                   "sha256": good_sha, "size": good_size,
                                   "profile": "office"})
        check("POSITIVE ...and a genuine success still reports ok", r2["ok"], True)

        # ── post-write verification restores rather than leaving a gap ────
        print("\npost-write verification")
        real_open = open

        # Simulate the write landing corrupted (bad disk, full filesystem):
        # the check must catch it from a FRESH READ and restore the previous
        # ruleset rather than leaving unverified content installed.
        marker = b"PREVIOUS RULESET\n"
        with real_open(dest, "wb") as fh:
            fh.write(marker)
        orig_replace = os.replace

        # Fires ONCE. A persistent injector would also corrupt the restore's own
        # replace() call, so the control could only ever report "not restored" --
        # an instrument with a single possible answer. Modelling one transient
        # bad write is both realistic and actually falsifiable.
        fired = []

        def corrupting_replace(src, dst):
            orig_replace(src, dst)
            if dst.endswith("office.rules") and not fired:
                fired.append(True)
                with real_open(dst, "wb") as fh:
                    fh.write(b"CORRUPTED ON DISK\n")
        os.replace = corrupting_replace
        try:
            r = upd("/good")
        finally:
            os.replace = orig_replace
        check("CONTROL a corrupted post-write is detected from a fresh read",
              r["error"], "post_write_mismatch")
        check("CONTROL ...and the previous ruleset is restored", on_disk(), marker)
        check("CONTROL ...the restore is REPORTED, not assumed", r.get("restored"), True)
        check("CONTROL ...the backup copy is not consumed by restoring",
              os.path.exists(dest + ".prev"), True)
        check("CONTROL ...no .tmp left behind", os.path.exists(dest + ".tmp"), False)
        check("CONTROL ...no .restore left behind",
              os.path.exists(dest + ".restore"), False)
        check("CONTROL the injector actually fired (the sabotage was real)",
              len(fired), 1)

        # ── the server-side resolver ──────────────────────────────────────
        print("\nserver-side resolver")
        fake = os.path.join(tmp, "srv")
        os.makedirs(fake, exist_ok=True)
        rules_dist.RULES_SEARCH_PATHS = (os.path.join(fake, "{profile}.rules"),)
        with real_open(os.path.join(fake, "office.rules"), "wb") as fh:
            fh.write(GOOD_RULES)
        d = rules_dist.rules_digest("office")
        check("POSITIVE the resolver digests the served bytes", d["sha256"], good_sha)
        check("POSITIVE ...and reports their size", d["size"], good_size)
        check("CONTROL the digest matches what the agent computes",
              d["sha256"], hashlib.sha256(GOOD_RULES).hexdigest())

        def raises(fn):
            try:
                fn()
            except rules_dist.RulesUnavailable as e:
                return "RulesUnavailable"
            except Exception as e:
                return type(e).__name__
            return "RETURNED"

        check("CONTROL an unknown profile RAISES, never returns a default",
              raises(lambda: rules_dist.rules_digest("../../etc/passwd")),
              "RulesUnavailable")
        check("CONTROL a missing ruleset RAISES", raises(
            lambda: rules_dist.rules_digest("roaming")), "RulesUnavailable")
        with real_open(os.path.join(fake, "roaming.rules"), "wb") as fh:
            fh.write(b"")
        check("CONTROL an EMPTY ruleset is refused (it detects nothing)",
              raises(lambda: rules_dist.rules_digest("roaming")), "RulesUnavailable")
    finally:
        srv.shutdown()
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
