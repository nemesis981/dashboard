#!/usr/bin/env python3
"""Cross-namespace error-code registry + collision guard (R4, 2026-08-22).

The error-code system grew to ~15 catalog namespaces with NO single check preventing two
namespaces from declaring the same code, or a stray/typo namespace from slipping in. The
per-namespace phantom check in agent_errors is real but local. This adds the DECIDABLE
cross-namespace guarantees:

  * NO DUPLICATE CODE  -- a full code (E-NS-NNN) declared as a catalog key in two places is
    a collision; two subsystems recording "the same" error mean different things and a
    reader cannot tell them apart.
  * NO UNREGISTERED NAMESPACE -- every declared code's prefix must be in REGISTERED_NAMESPACES,
    so a typo ("E-AGNET-001") or an ad-hoc prefix is caught rather than silently minted.

HONEST SCOPE (measured 2026-08-22): this scans CATALOG-KEY declarations (`"E-NS-NNN":` dict
keys) in non-test .py files. It deliberately does NOT attempt a tree-wide phantom check
(declared-but-never-recorded) across every call signature (record / record_error /
report_gui_error / constant-passed codes) -- that cannot be done reliably by static scan and
a checker that misses constant-passed codes would report FALSE phantoms, the broken-
instrument class this project forbids. Phantom coverage stays per-namespace (agent_errors)
until a robust cross-signature approach exists. This covers what is decidable, and says so.
"""
import os
import re
import sys

REGISTERED_NAMESPACES = frozenset({
    "AGENT", "RAMREC", "LOOKUP", "HWMON", "HW", "WATCHDOG", "TLS", "MALWARE", "DIAG",
    "DASH", "ANOMALY", "TICKETS", "REDACT", "FWD", "DM", "DHCP", "CONSENT", "CONN",
    "TEST",
    # Added 2026-08-23: both namespaces shipped while this file sat uncommitted, and
    # the checker correctly reported them as unregistered on the first run against
    # current HEAD. Registering them here is the fix -- the list is the source of
    # truth for what a legitimate namespace is, so a real new one must be added to
    # it rather than the check being loosened.
    "NETPROBE",     # modules/netprobe/module.py (81ca877)
    "RBAC",         # dashboard.py role gate (91833d9)
})

_CODE_KEY = re.compile(r'^\s*"(E-([A-Z]+)-\d+)"\s*:')
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scan(root=None):
    root = root or _ROOT
    decls = {}
    for dirpath, dirs, files in os.walk(root):
        if "__pycache__" in dirpath or os.sep + ".git" in dirpath:
            continue
        for fn in files:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8") as fh:
                    for n, line in enumerate(fh, 1):
                        m = _CODE_KEY.match(line)
                        if m:
                            decls.setdefault(m.group(1), []).append(
                                "%s:%d" % (os.path.relpath(path, root), n))
            except OSError:
                continue
    return decls


def check(root=None):
    decls = scan(root)
    findings = []
    for code, sites in sorted(decls.items()):
        if len(sites) > 1:
            findings.append(("COLLISION", "%s declared in %d places: %s"
                             % (code, len(sites), ", ".join(sites))))
        ns = code.split("-")[1]
        if ns not in REGISTERED_NAMESPACES:
            findings.append(("UNREGISTERED", "%s uses namespace %r not in "
                             "REGISTERED_NAMESPACES (%s)" % (code, ns, sites[0])))
    return findings, decls


def main():
    findings, decls = check()
    ns_counts = {}
    for code in decls:
        ns_counts[code.split("-")[1]] = ns_counts.get(code.split("-")[1], 0) + 1
    print("error-code registry: %d codes across %d namespaces" % (len(decls), len(ns_counts)))
    for ns in sorted(ns_counts):
        print("  E-%-10s %d" % (ns, ns_counts[ns]))
    print()
    if not findings:
        print("CLEAN: no duplicate codes, no unregistered namespaces.")
        return 0
    print("FINDINGS (%d):" % len(findings))
    for sev, msg in findings:
        print("  [%s] %s" % (sev, msg))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
