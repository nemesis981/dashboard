#!/usr/bin/env python3
"""Provenance must survive the Retry button.

Run: python3 nemesis_agent/test_provenance_retry.py

Regression cover for the bug found during Tier C on 2026-08-03: `_run()` is
re-entered from the top by Retry, so re-probing on the second attempt answers
the wrong question — attempt 1 had already installed Tailscale, so attempt 2
recorded it as the user's own and the uninstaller then refused to remove it.

installer_gui imports tkinter at module level, which is absent on this build
host, so the probe method is extracted and exercised against a minimal stub
rather than a real InstallerApp. That keeps the test honest about what it
covers: the caching CONTROL FLOW, not the GUI.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "installer_gui.py")
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


class FakeApp:
    """Minimal stand-in: the probe only needs these three collaborators."""

    _provenance_probed = False

    def __init__(self, world):
        self.world = world          # mutable "is it installed?" state
        self.ts_probes = 0
        self.pawnio_probes = 0
        self.logs = []

    def _tailscale_installed(self):
        self.ts_probes += 1
        return self.world["tailscale"]

    def _pawnio_present(self):
        self.pawnio_probes += 1
        return self.world["pawnio"]

    def _ilog(self, msg):
        self.logs.append(msg)


def load_probe():
    """Extract _probe_preinstall_state from installer_gui.py without importing it."""
    tree = ast.parse(open(SRC).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_probe_preinstall_state":
            mod = ast.Module(body=[node], type_ignores=[])
            ns = {}
            exec(compile(ast.fix_missing_locations(mod), SRC, "exec"), ns)
            return ns["_probe_preinstall_state"]
    raise SystemExit("FATAL: _probe_preinstall_state not found")


def main():
    probe = load_probe()
    print("extracted _probe_preinstall_state verbatim from installer_gui.py\n")

    # ── the scenario that produced the bug ────────────────────────────────
    print("retry after an attempt that installed Tailscale")
    world = {"tailscale": False, "pawnio": False}    # clean machine
    app = FakeApp(world)

    probe(app)                                       # attempt 1: nothing installed yet
    check("POSITIVE first probe sees a clean machine", app._ts_pre_existing, False)

    # attempt 1 installs Tailscale + PawnIO, then fails later (reachability)
    world["tailscale"] = True
    world["pawnio"] = True

    probe(app)                                       # attempt 2, via Retry
    check("CONTROL retry does NOT flip tailscale to pre-existing",
          app._ts_pre_existing, False)
    check("CONTROL retry does NOT flip pawnio to pre-existing",
          app._pawnio_pre_existing, False)
    check("CONTROL the world was not re-probed at all", app.ts_probes, 1)
    check("the reuse is logged, not silent", any("reusing" in m for m in app.logs), True)

    probe(app); probe(app)                           # repeated retries
    check("CONTROL still stable after further retries", app._ts_pre_existing, False)
    check("CONTROL still exactly one probe", app.ts_probes, 1)

    # ── the case that must still report TRUE ─────────────────────────────
    print("\na genuinely pre-existing install must still be respected")
    app2 = FakeApp({"tailscale": True, "pawnio": True})
    probe(app2)
    check("POSITIVE user's own tailscale is recorded as pre-existing",
          app2._ts_pre_existing, True)
    check("POSITIVE user's own pawnio is recorded as pre-existing",
          app2._pawnio_pre_existing, True)

    # ── the cache must not leak between installer processes ──────────────
    print("\nthe cache is per-process, not global")
    app3 = FakeApp({"tailscale": True, "pawnio": False})
    probe(app3)
    check("CONTROL a fresh app probes independently of earlier ones",
          app3._ts_pre_existing, True)
    check("CONTROL and it did probe (not reuse app1's answer)", app3.ts_probes, 1)

    # ── the guard exists as a class attribute, defaulting False ──────────
    print("\nguard declaration")
    src = open(SRC).read()
    check("_provenance_probed declared at class level",
          "_provenance_probed = False" in src, True)
    check("CONTROL the probe checks it before probing",
          src.index("if self._provenance_probed") < src.index("self._ts_pre_existing ="),
          True)

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
