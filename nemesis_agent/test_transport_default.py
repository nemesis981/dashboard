#!/usr/bin/env python3
"""Transport-default guard: agents must not silently end up on a cleartext target.

Run: python3 nemesis_agent/test_transport_default.py

dashboard.py is not imported (it builds a live Flask app). _classify_transport is
a pure function, so it is extracted verbatim from the source and executed here --
the same technique used for _verify_enroll_signature, so what is tested is the
shipped code rather than a copy that can drift from it.
"""
import ast
import ipaddress
import os
import re
import sys

DASHBOARD = "/opt/nemesis/dashboard.py"
JS = "/opt/nemesis/static/agent-enroll.js"
HW = "/opt/nemesis/core_module/hw_monitor/hw_monitor.py"

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def extract(src_path, func_name, extra_ns=None):
    lines = open(src_path).read().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("def %s(" % func_name))
    end = start + 1
    while end < len(lines) and (lines[end].startswith("    ") or not lines[end].strip()):
        end += 1
    ns = dict(extra_ns or {})
    exec(compile("\n".join(lines[start:end]), src_path, "exec"), ns)
    return ns[func_name]


def main():
    src = open(DASHBOARD).read()
    ns = {"ipaddress": ipaddress,
          "_TAILNET_CGNAT": ipaddress.ip_network("100.64.0.0/10")}
    classify = extract(DASHBOARD, "_classify_transport", ns)
    print("extracted _classify_transport verbatim from dashboard.py\n")

    print("classification — must distinguish, not always agree")
    check("POSITIVE a tailnet CGNAT address is tailnet",
          classify("100.101.102.103")[0], "tailnet")
    check("POSITIVE loopback counts as safe (never leaves the box)",
          classify("127.0.0.1")[0], "tailnet")
    check("CONTROL a LAN address is cleartext",
          classify("192.168.1.50")[0], "cleartext")
    check("CONTROL another private range is cleartext",
          classify("10.20.30.40")[0], "cleartext")
    check("CONTROL a public address is cleartext",
          classify("203.0.113.9")[0], "cleartext")
    check("CONTROL the CGNAT boundary is respected (100.63.x is NOT tailnet)",
          classify("100.63.255.255")[0], "cleartext")
    check("CONTROL the other CGNAT boundary is inside",
          classify("100.127.255.254")[0], "tailnet")

    print("\nit must refuse to guess rather than assume safety")
    check("CONTROL a hostname is 'unknown', not assumed tailnet",
          classify("nemesis.example.internal")[0], "unknown")
    check("CONTROL an empty host is 'unknown'", classify("")[0], "unknown")
    check("CONTROL 'unknown' is never silently treated as tailnet",
          classify("some-host")[0] == "tailnet", False)

    print("\nit tolerates the shapes a real URL arrives in")
    check("scheme and path are stripped",
          classify("http://100.101.102.103/install/x")[0], "tailnet")
    check("a port is stripped", classify("192.168.1.50:5000")[0], "cleartext")
    check("scheme + port together",
          classify("http://192.168.1.50:5000")[0], "cleartext")

    print("\nthe env override must win over request context")
    body = src[src.index("def _nemesis_tailnet_host"):]
    body = body[:body.index("\ndef ")] if "\ndef " in body else body
    check("configured address returns BEFORE request.host is consulted",
          body.index("return configured.split") < body.index("request.host"), True)
    check("a non-tailnet fallback is logged, not silent",
          "log.warning" in body, True)
    check("the LAN-only fallback is retained (not a hard failure)",
          "raise" in body, False)

    print("\noperator-facing warning at generate time")
    gen = src[src.index("def api_agent_installer_generate"):]
    gen = gen[:gen.index("\n@app.route")]
    check("the generate response carries a transport verdict",
          '"transport": _t_verdict' in gen, True)
    check("and a human-readable warning field",
          '"transport_warning": transport_warning' in gen, True)
    check("cleartext produces a non-empty warning",
          'if _t_verdict == "cleartext"' in gen, True)
    check("CONTROL 'unknown' also warns (absence of proof is not proof)",
          'elif _t_verdict == "unknown"' in gen, True)

    js = open(JS).read()
    check("the UI renders the transport warning",
          "d.transport_warning" in js, True)
    check("CONTROL it is a separate banner, not folded into keyNote",
          js.index("transportNote") < js.index("out.innerHTML = transportNote"), True)

    # The _verify_agent_heartbeat docstring update is NOT part of this commit:
    # hw_monitor.py currently carries another window's uncommitted disk-capacity
    # work, and staging that file wholesale would sweep it in. The docstring text
    # is handed to Window 2 to apply once that lands. Asserted here only that the
    # existing caveat is still present and was not disturbed.
    print("\nexisting confidentiality caveat left intact")
    hw = open(HW).read()
    check("_verify_agent_heartbeat still states there is no confidentiality",
          "NO CONFIDENTIALITY" in hw, True)

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
