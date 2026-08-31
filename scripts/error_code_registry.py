#!/usr/bin/env python3
"""Cross-namespace error-code registry + collision guard (R4, 2026-08-22).

The error-code system grew to ~15 catalog namespaces with NO single check preventing two
namespaces from declaring the same code, or a stray/typo namespace from slipping in. The
per-namespace phantom check in agent_errors is real but local. This adds the DECIDABLE
cross-namespace guarantees:

  * NO DUPLICATE CODE  -- a full code (E-NS-NNN) declared in two places is a collision;
    two subsystems recording "the same" error mean different things and a reader cannot
    tell them apart.
  * NO UNREGISTERED NAMESPACE -- every declared code's prefix must be in REGISTERED_NAMESPACES,
    so a typo ("E-AGNET-001") or an ad-hoc prefix is caught rather than silently minted.
  * NO UNREAD FILE -- a source file that could not be opened is REPORTED, not skipped.

HONEST SCOPE (measured 2026-08-22, CORRECTED 2026-08-31): this scans DECLARATIONS in
non-test .py files, in BOTH styles the codebase actually uses -- catalog dict keys
(`"E-NS-NNN":`) and module-level constants (`E_NAME = "E-NS-NNN"`).

⚠ THE ORIGINAL VERSION SCANNED ONLY THE FIRST STYLE, AND THE COST WAS NOT THEORETICAL.
DHCP, CONSENT and CONN declare their codes as constants, so 24 production codes -- roughly
a quarter of the tree -- were invisible to every run, while DHCP and CONSENT sat in
REGISTERED_NAMESPACES looking covered. The script printed an unqualified "CLEAN: no
duplicate codes" the whole time. That is precisely the instrument-that-cannot-fail shape
this project forbids, in the very tool written to police it, and it survived because the
paragraph you are reading described the limitation only as it applied to the PHANTOM check
(below) and not to the duplicate/namespace guarantees the output was actually asserting.

Still deliberately OUT of scope: a tree-wide phantom check (declared-but-never-recorded)
across every call signature (record / record_error / report_gui_error / constant-passed
codes). That cannot be done reliably by static scan, and a checker that misses
constant-passed codes would report FALSE phantoms. Phantom coverage stays per-namespace
(agent_errors) until a robust cross-signature approach exists. This covers what is
decidable, and now says so accurately.
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
    # Added 2026-08-31: the email-security pipeline had ZERO structured errors
    # across 20 files -- its terminal watcher states, credential exception
    # classes and fail-closed refusals lived only in logs and in-memory state,
    # so a restart erased every record that a mailbox had ever failed.
    "EMAIL",        # modules/email_security/errors.py
    # Added 2026-08-31: the LAN-integrity detector had no catalog at all, and
    # every failure in it makes the detector see LESS while still reporting --
    # an empty result read as reassurance.
    "LANINT",       # modules/lan_integrity/module.py
})

#: Style 1 -- a catalog dict key:   "E-NS-001": ("desc", "HIGH", "class")
_CODE_KEY = re.compile(r'^\s*"(E-([A-Z]+)-\d+)"\s*:')

#: Style 2 -- a module-level constant:   E_CONFIG_INVALID = "E-DHCP-001"
#:
#: ⛔ THIS WAS THE BLIND SPOT, AND IT WAS A BIG ONE. Until 2026-08-31 only
#: style 1 was matched, so THREE ENTIRE NAMESPACES were invisible to this
#: checker: DHCP (16 codes), CONSENT (6) and CONN (2) -- 24 production codes.
#: Both DHCP and CONSENT are listed in REGISTERED_NAMESPACES, so they had been
#: registered in the expectation of being covered, and were not. Worse, the
#: output printed an unqualified "CLEAN: no duplicate codes", a guarantee this
#: script could not actually make for a quarter of the codes in the tree.
#:
#: Anchored to an UPPERCASE name at the start of a line so it matches a
#: DECLARATION and not a use: `record_error(conn, "E-DHCP-001")` and
#: `if code == "E-DHCP-001"` are both correctly ignored. Verified against the
#: real tree: DHCP declares each code once as a constant and then references
#: the CONSTANT in its catalog tuple, so nothing is double-counted.
_CODE_CONST = re.compile(r'^[A-Z_][A-Z0-9_]*\s*=\s*"(E-([A-Z]+)-\d+)"')

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scan(root=None):
    """(decls, unreadable). `unreadable` is the files that could not be read.

    ⚠ AN UNREADABLE FILE USED TO BE SKIPPED SILENTLY (`except OSError:
    continue`), which is the same defect class this script exists to police: a
    file it could not open contributed no codes, and the run still printed
    CLEAN. A collision hiding in an unreadable file would have been reported as
    its absence. They are now returned and surfaced by the caller.
    """
    root = root or _ROOT
    decls = {}
    unreadable = []
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
                        m = _CODE_KEY.match(line) or _CODE_CONST.match(line)
                        if m:
                            decls.setdefault(m.group(1), []).append(
                                "%s:%d" % (os.path.relpath(path, root), n))
            except OSError as exc:
                unreadable.append("%s (%s)" % (os.path.relpath(path, root),
                                               type(exc).__name__))
    return decls, unreadable


def check(root=None):
    decls, unreadable = scan(root)
    findings = []
    for path in unreadable:
        # Surfaced, not swallowed: a file this scan could not read may contain
        # the very collision it is meant to find, so the run must not be
        # reported as complete.
        findings.append(("UNREADABLE", "%s could not be read, so its codes were "
                                       "NOT checked" % path))
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
        print("CLEAN: no duplicate codes, no unregistered namespaces,\n"
              "       every source file readable.\n"
              "       Scanned BOTH declaration styles: catalog dict keys and\n"
              "       module-level constants (the latter was invisible until\n"
              "       2026-08-31, hiding 24 codes across DHCP/CONSENT/CONN).")
        return 0
    print("FINDINGS (%d):" % len(findings))
    for sev, msg in findings:
        print("  [%s] %s" % (sev, msg))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
