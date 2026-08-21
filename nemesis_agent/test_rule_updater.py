"""Tests for rule_updater — engine-agnostic ruleset distribution.

Real local HTTP server (not a mock) serves the rulesets, so the fetch/digest/size/
redirect paths are exercised for real. The property tested hardest is the one that
makes fleet distribution SAFE: a ruleset that fails the compile-check NEVER replaces
the working one. A distribution channel that can push a broken ruleset fleet-wide
is the failure hinge (b)'s compile-check-before-activate exists to prevent.

Run: python3 nemesis_agent/test_rule_updater.py
"""
import hashlib
import http.server
import os
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import rule_updater as ru                                    # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


class _Server:
    """Serves a controllable body at /rules, and a redirect at /redir."""

    def __init__(self):
        self.body = b"rule content v1"
        self.status = 200
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/redir":
                    self.send_response(302)
                    self.send_header("Location", "http://example.com/x")
                    self.end_headers()
                    return
                self.send_response(outer.status)
                self.send_header("Content-Length", len(outer.body))
                self.end_headers()
                if outer.status == 200:
                    self.wfile.write(outer.body)

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, path="/rules"):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def stop(self):
        self.srv.shutdown()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    srv = _Server()
    d = tempfile.mkdtemp(prefix="ru-test-")
    dest = os.path.join(d, "engine.rules")
    try:
        print("happy path — valid digest+size+compile-check -> activated, correct bytes")
        srv.body = b"good ruleset v1"
        res = ru.update_ruleset("falco", srv.url(), sha(srv.body), len(srv.body), dest,
                                compile_check=lambda p: (True, "ok"),
                                activate=lambda: None)
        check("ok", res["ok"], True)
        check("activated", res["activated"], True)
        check("the bytes on disk are the served bytes",
              open(dest, "rb").read(), b"good ruleset v1")
        check("no .prev/.incoming left behind",
              any(os.path.exists(dest + s) for s in (".prev", ".incoming")), False)

        print("\ndigest is MANDATORY and CHECKED")
        check("missing digest -> refused",
              ru.update_ruleset("falco", srv.url(), None, 10, dest)["error"],
              "digest_required")
        check("wrong-length digest -> refused",
              ru.update_ruleset("falco", srv.url(), "abc", 10, dest)["error"],
              "digest_required")
        srv.body = b"tampered"
        check("digest mismatch -> refused",
              ru.update_ruleset("falco", srv.url(), sha(b"different"), len(srv.body),
                                dest)["error"], "digest_mismatch")

        print("\nsize + transport guards")
        srv.body = b"12345"
        check("size mismatch -> refused",
              ru.update_ruleset("falco", srv.url(), sha(srv.body), 999, dest)["error"],
              "size_mismatch")
        srv.status = 404
        check("non-200 -> http_status refused",
              ru.update_ruleset("falco", srv.url(), sha(b"x"), 1, dest)["error"],
              "http_status_404")
        srv.status = 200
        check("a REDIRECT is refused, not followed",
              ru.update_ruleset("falco", srv.url("/redir"), sha(b"x"), 1, dest)["error"],
              "http_status_302")

        print("\nTHE FLEET-SAFETY PROPERTY: a failing compile-check leaves the good "
              "ruleset UNTOUCHED")
        # install a known-good ruleset first
        srv.body = b"known good"
        ru.update_ruleset("falco", srv.url(), sha(srv.body), len(srv.body), dest,
                          compile_check=lambda p: (True, "ok"))
        check("good ruleset in force", open(dest, "rb").read(), b"known good")
        # now push one that FAILS compile-check
        srv.body = b"broken ruleset that will not compile"
        res = ru.update_ruleset("falco", srv.url(), sha(srv.body), len(srv.body), dest,
                                compile_check=lambda p: (False, "syntax error line 3"))
        check("a non-compiling ruleset is refused", res["error"], "compile_check_failed")
        check("...and the GOOD ruleset is still in force (never replaced)",
              open(dest, "rb").read(), b"known good")
        check("...no .incoming left behind", os.path.exists(dest + ".incoming"), False)
        # a compile-check that RAISES is treated as failure, same protection
        res = ru.update_ruleset("falco", srv.url(), sha(srv.body), len(srv.body), dest,
                                compile_check=lambda p: (_ for _ in ()).throw(RuntimeError()))
        check("a compile-check that raises -> refused, good ruleset kept",
              (res["error"], open(dest, "rb").read()),
              ("compile_check_failed", b"known good"))

        print("\nactivate() failure -> rules installed + verified, activated=False")
        srv.body = b"new rules, reload will fail"
        res = ru.update_ruleset("falco", srv.url(), sha(srv.body), len(srv.body), dest,
                                compile_check=lambda p: (True, "ok"),
                                activate=lambda: (_ for _ in ()).throw(RuntimeError("reload")))
        check("install still succeeds", res["ok"], True)
        check("...but activated is False with the reason",
              (res["activated"], "reload" in res.get("activate_error", "")), (False, True))
        check("...and the new rules ARE on disk (install completed before reload)",
              open(dest, "rb").read(), b"new rules, reload will fail")

        print("\nno-validator engine activates unchecked, but says so (logged)")
        srv.body = b"unchecked"
        res = ru.update_ruleset("suricata", srv.url(), sha(srv.body), len(srv.body), dest,
                                compile_check=None)
        check("unchecked install still works", res["ok"], True)
    finally:
        srv.stop()

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
