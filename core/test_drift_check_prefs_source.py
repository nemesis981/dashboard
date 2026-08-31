"""Where nemesis-drift-check gets its prefs from. Executes the script against a fake
tailscaled socket.

WHY THIS FILE EXISTS. The first real deployment (2026-08-31) reported UNDETERMINED on
netfilter_mode forever. The checker shelled out to `tailscale`, which on this box is a
snap at /snap/bin -- a directory absent from systemd's default PATH. FileNotFoundError
was swallowed by a bare `except Exception`, and the check blamed the daemon.

Nothing in the old suite could have caught that: every test fed prefs in as a literal
string, so the branch was proven correct while the thing that SUPPLIES it was broken.
These tests exercise the supply path itself.

The load-bearing one is `test_works_with_no_tailscale_binary_on_path`: it proves the
checker reads the mode with an EMPTY PATH, which is a behavioural proof of CLI
independence rather than a grep for the word "subprocess".
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_SCRIPT = os.path.join(_REPO, "scripts", "nemesis-drift-check")

_fail = []
_count = 0
EXPECTED_CHECKS = 11

_GOOD_RULES = """\
-A ufw-before-input -i lo -j ACCEPT
# NEMESIS-TAILNET-ANTISPOOF
-A ufw-before-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
"""


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


class FakeTailscaled(object):
    """A unix socket that answers /localapi/v0/prefs. Serves ONE request then stops."""

    def __init__(self, tmp, status=200, body=None):
        self.path = os.path.join(tmp, "tailscaled.sock")
        self.status = status
        self.body = body if body is not None else json.dumps({"NetfilterMode": 1})
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.srv.accept()
            conn.recv(65536)
            payload = self.body.encode()
            head = ("HTTP/1.1 %d X\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                    % (self.status, len(payload))).encode()
            conn.sendall(head + payload)
            conn.close()
        except Exception:                                           # noqa: BLE001
            pass

    def close(self):
        try:
            self.srv.close()
        except Exception:                                           # noqa: BLE001
            pass


def _run(tmp, sock_path, env_extra=None):
    """Run the checker; return its parsed fact file."""
    status = os.path.join(tmp, "status.json")
    rules = os.path.join(tmp, "before.rules")
    with open(rules, "w", encoding="utf-8") as fh:
        fh.write(_GOOD_RULES)
    env = dict(os.environ)
    env.update({"NEMESIS_DRIFT_STATUS": status, "NEMESIS_UFW_RULES": rules,
                "NEMESIS_TAILSCALED_SOCKET": sock_path})
    if env_extra:
        env.update(env_extra)
    subprocess.run([sys.executable, _SCRIPT], env=env, cwd=tmp,
                   capture_output=True, text=True, timeout=60)
    if not os.path.exists(status):
        return None
    with open(status, encoding="utf-8") as fh:
        return json.load(fh)


def test_reads_prefs_from_the_socket():
    print("\n[the daemon answers -> the mode is actually read]")
    tmp = tempfile.mkdtemp(prefix="drift-sock-")
    srv = FakeTailscaled(tmp)
    try:
        p = _run(tmp, srv.path)
        check("wrote a fact file", p is not None, True)
        if p:
            check("netfilter_mode is OK, not undetermined",
                  p["checks"]["netfilter_mode"]["status"], "ok")
            check("overall verdict is ok", p["verdict"], "ok")
    finally:
        srv.close()


def test_works_with_no_tailscale_binary_on_path():
    print("\n[THE REGRESSION: an empty PATH must not affect the result]")
    tmp = tempfile.mkdtemp(prefix="drift-nopath-")
    srv = FakeTailscaled(tmp)
    try:
        # PATH="" makes every CLI unreachable. The old implementation reported
        # UNDETERMINED here -- which is exactly what production did.
        p = _run(tmp, srv.path, {"PATH": ""})
        check("still reads the mode with PATH empty",
              p["checks"]["netfilter_mode"]["status"], "ok")
        check("...and does not blame the daemon",
              "did not answer" in p["checks"]["netfilter_mode"]["detail"], False)
    finally:
        srv.close()


def test_missing_socket_names_itself():
    print("\n[no socket -> undetermined, and the reason NAMES the path it tried]")
    tmp = tempfile.mkdtemp(prefix="drift-nosock-")
    missing = os.path.join(tmp, "absent.sock")
    p = _run(tmp, missing)
    check("undetermined, never ok", p["checks"]["netfilter_mode"]["status"], "undetermined")
    check("the reason names the missing socket",
          missing in p["checks"]["netfilter_mode"]["detail"], True)
    check("exit code says cannot-verify", p["exit_code"], 2)


def test_bad_http_status_is_not_a_pass():
    print("\n[daemon answers 500 -> undetermined, and says so]")
    tmp = tempfile.mkdtemp(prefix="drift-500-")
    srv = FakeTailscaled(tmp, status=500, body="nope")
    try:
        p = _run(tmp, srv.path)
        check("undetermined", p["checks"]["netfilter_mode"]["status"], "undetermined")
        check("the detail reports the HTTP status",
              "500" in p["checks"]["netfilter_mode"]["detail"], True)
        check("...and it is not silently treated as drift",
              p["checks"]["netfilter_mode"]["status"] == "drifted", False)
    finally:
        srv.close()


if __name__ == "__main__":
    print("nemesis-drift-check prefs source (executed against a fake tailscaled)")
    test_reads_prefs_from_the_socket()
    test_works_with_no_tailscale_binary_on_path()
    test_missing_socket_names_itself()
    test_bad_http_status_is_not_a_pass()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
