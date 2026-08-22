"""Check: dependency preflight — are the external binaries this code calls present?

THE BUG CLASS THIS EXISTS FOR
    Python code shells out to a binary that is not installed. Nothing fails until
    the exact moment that path runs, which for a recovery or export path may be
    the worst possible moment — the ISO builder shipped with a missing dependency
    discovered only when someone tried to build an ISO.

    `subprocess` failing on a missing binary is not loud in this codebase either:
    the shared `_run` helper maps `FileNotFoundError` to rc=127 and a string, so a
    missing tool arrives at the caller looking like a command that ran and failed.

WHY MOST "MISSING" BINARIES ARE NOT FINDINGS
    A naive scan of this repo finds ~30 invoked binaries and reports a third of
    them absent — which would be a flood of false positives, and a tool nobody
    reads after the first run. Three distinct reasons a binary can be legitimately
    absent:

      * **Wrong platform.** `schtasks`, `powershell`, `icacls`, `ipconfig`,
        `winget` and `taskkill` are called by the WINDOWS agent. They are
        correctly absent on a Linux appliance and their absence means nothing.
      * **Optional by design.** The VPN probes are plugins with an explicit
        skip-if-absent contract: `piactl`, `mullvad`, `protonvpn-cli` are present
        only if the operator uses that provider. `vpn_status.py` already
        distinguishes UNAVAILABLE from PROBE-FAILED for exactly this reason.
      * **Test-only.** A binary invoked solely from a test file is not a runtime
        dependency of the appliance.

    So this check classifies before it reports, and only a REQUIRED binary that is
    missing is a finding. The other categories are counted and named, so the
    operator can see they were considered rather than silently dropped.

Read-only: parses source and looks up executables on PATH. Runs nothing.
"""

import os
import re
import shutil
import sys

try:                                    # normal package import
    from . import canary as _canary_harness
except ImportError:                     # loaded by file path (tests, direct run)
    # The checks are documented as independently runnable, and the test suites
    # load them via spec_from_file_location -- neither has package context, so a
    # bare relative import fails. Falling back keeps all three entry points
    # working: `import diagnostics`, `python3 -m diagnostics.<id>`, and a direct
    # path load.
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import canary as _canary_harness

META = {
    "id": "dependency_preflight",
    "name": "Dependency Preflight",
    "icon": "🧰",
    "descriptions": {
        "beginner": "Checks that the external command-line tools Nemesis relies "
                    "on are actually installed, so a feature does not fail the "
                    "first time you use it. Tools that are optional, or meant for "
                    "Windows devices, are not counted as missing.",
        "intermediate": "Scans subprocess call sites for invoked executables, "
                        "classifies each as required / optional / "
                        "platform-specific / test-only, and reports only REQUIRED "
                        "binaries absent from PATH.",
        "pro": "Static extraction of argv[0] from subprocess call sites, "
               "classified before reporting. Absent optional or cross-platform "
               "tools are counted, not flagged — a missing skip-if-absent plugin "
               "is not a fault.",
    },
}

_OK = "ok"
_MISSING = "missing"
_PROBE_FAILED = "probe-failed"
_TAGS = {_OK: "OK", _MISSING: "MISSING", _PROBE_FAILED: "PROBE-FAILED"}


def _section(label, state, detail=""):
    """One labeled line. An unrecognised state raises rather than rendering OK."""
    return f"[{_TAGS[state]}] {label}" + (f": {detail}" if detail else "")


# ── Classification ───────────────────────────────────────────────────────────

CAT_REQUIRED = "required"
CAT_OPTIONAL = "optional"
CAT_PLATFORM = "platform"
CAT_TEST = "test-only"

#: Called by the Windows agent / Windows tooling. Absent on a Linux appliance by
#: definition, so their absence carries no information at all.
_WINDOWS_BINARIES = frozenset({
    "schtasks", "powershell", "powershell.exe", "icacls", "ipconfig", "winget",
    "taskkill", "reg", "wmic", "sc", "netsh", "cmd", "cmd.exe", "wevtutil",
})

#: Optional by design — each has an explicit skip-if-absent contract. A missing
#: one means "the operator does not use that provider", not "something is broken".
_OPTIONAL_BINARIES = frozenset({
    "piactl", "mullvad", "protonvpn-cli", "wg", "tailscale",
    "nvidia-smi", "sensors", "VBoxManage", "node", "clamdscan",
})

#: Path fragments whose files are not part of the running appliance.
_TEST_PATH_HINTS = ("/test_", "test_", "/tests/", "synthetic_samples",
                    "windows_agent/", "/tools/")

_SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv"}

#: argv[0] as a literal in a subprocess call.
_CALL_RE = re.compile(
    r"""subprocess\.(?:run|Popen|check_output|call|check_call)\(\s*\[\s*
        ["'](?P<bin>[A-Za-z0-9_./-]+)["']""",
    re.VERBOSE)


def classify(binary, source_path):
    """Which category this invocation falls into. Pure."""
    name = os.path.basename(binary)
    rel = source_path.replace(os.sep, "/")
    if name in _WINDOWS_BINARIES:
        return CAT_PLATFORM
    if any(h in rel for h in _TEST_PATH_HINTS):
        return CAT_TEST
    if name in _OPTIONAL_BINARIES:
        return CAT_OPTIONAL
    return CAT_REQUIRED


def scan(root, opener=None):
    """{binary: {"category": str, "sites": int}} across the tree. Pure but for reads.

    A binary invoked from several places takes the STRONGEST category it appears
    under: something called from both a test and the running appliance is a real
    dependency, and classifying it test-only because a test also uses it would
    hide a genuine gap.
    """
    strength = {CAT_TEST: 0, CAT_PLATFORM: 1, CAT_OPTIONAL: 2, CAT_REQUIRED: 3}
    found = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                if opener is not None:
                    text = opener(path)
                else:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
            except OSError:
                continue
            if "subprocess" not in text:
                continue
            rel = os.path.relpath(path, root)
            for m in _CALL_RE.finditer(text):
                b = m.group("bin")
                cat = classify(b, rel)
                cur = found.get(b)
                if cur is None:
                    found[b] = {"category": cat, "sites": 1}
                else:
                    cur["sites"] += 1
                    if strength[cat] > strength[cur["category"]]:
                        cur["category"] = cat
    return found


def present(binary, which=None):
    """Is this executable resolvable? Absolute paths are checked directly."""
    which = which or shutil.which
    if binary.startswith("/"):
        return os.path.exists(binary) and os.access(binary, os.X_OK)
    return which(binary) is not None


def evaluate(found, which=None):
    """Split scanned binaries into missing-required and benignly-absent. Pure."""
    missing_required, absent_benign, ok_count = [], {}, 0
    for b, info in sorted(found.items()):
        if present(b, which=which):
            ok_count += 1
            continue
        if info["category"] == CAT_REQUIRED:
            missing_required.append((b, info["sites"]))
        else:
            absent_benign.setdefault(info["category"], []).append(b)
    return {"missing_required": missing_required, "absent_benign": absent_benign,
            "present": ok_count, "total": len(found)}


# ── Canary ───────────────────────────────────────────────────────────────────

def _fixture_call(binary):
    """Source text for a canary fixture that invokes `binary`.

    The call is ASSEMBLED, never written literally in this file. This module
    scans the whole repo for subprocess call sites — INCLUDING its own source —
    so a literal fixture here is picked up as a real call site and the fake
    binary is reported as a missing REQUIRED dependency on every production run.
    It was, on the first run: `dualuse (2 call sites)` appeared in the live
    output, sourced from this very canary.

    The same trap caught `schema_drift.py`, which scans for DDL. Any diagnostic
    that greps the tree will match its own fixtures unless they are assembled.
    """
    return ('import %s\n%s.run(["%s", "-h"])\n'
            % ("subprocess", "subprocess", binary))


def _canary():
    """Returns (ok, detail). Never raises. Runs on EVERY invocation."""
    try:
        # Classification must distinguish all four categories.
        cases = [
            ("systemctl", "dashboard.py", CAT_REQUIRED),
            ("schtasks", "dashboard.py", CAT_PLATFORM),
            ("mullvad", "dashboard.py", CAT_OPTIONAL),
            ("nmap", "diagnostics/test_thing.py", CAT_TEST),
            ("nmap", "windows_agent/setup.py", CAT_TEST),
        ]
        for b, path, want in cases:
            got = classify(b, path)
            if got != want:
                return False, ("classify(%r, %r) = %r, expected %r" % (b, path, got, want))

        # A present REQUIRED binary must not be reported.
        ev = evaluate({"here": {"category": CAT_REQUIRED, "sites": 1}},
                      which=lambda n: "/usr/bin/" + n)
        if ev["missing_required"]:
            return False, "a PRESENT required binary was reported missing"
        if ev["present"] != 1:
            return False, "a present binary was not counted"

        # An absent REQUIRED binary must be reported.
        ev = evaluate({"gone": {"category": CAT_REQUIRED, "sites": 2}},
                      which=lambda n: None)
        if not ev["missing_required"]:
            return False, ("an ABSENT required binary was not reported -- this "
                           "check would pass on a box missing its dependencies")

        # An absent OPTIONAL or PLATFORM binary must NOT be reported as missing.
        ev = evaluate({"vpnthing": {"category": CAT_OPTIONAL, "sites": 1},
                       "winthing": {"category": CAT_PLATFORM, "sites": 1}},
                      which=lambda n: None)
        if ev["missing_required"]:
            return False, ("an optional/platform binary was reported as a missing "
                           "dependency -- this floods the report with tools that "
                           "are absent by design")
        if set(ev["absent_benign"]) != {CAT_OPTIONAL, CAT_PLATFORM}:
            return False, "benign absences were not counted per category"

        # Strongest-category wins: a binary used by BOTH a test and real code is
        # a real dependency.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "sub"), exist_ok=True)
            with open(os.path.join(d, "test_x.py"), "w") as fh:
                fh.write(_fixture_call("dualuse"))
            with open(os.path.join(d, "sub", "real.py"), "w") as fh:
                fh.write(_fixture_call("dualuse"))
            got = scan(d)
            if "dualuse" not in got:
                return False, "the scanner found no call sites at all"
            if got["dualuse"]["category"] != CAT_REQUIRED:
                return False, ("a binary used by real code AND a test was "
                               "classified %r -- a genuine dependency would be "
                               "hidden" % got["dualuse"]["category"])
            if got["dualuse"]["sites"] != 2:
                return False, "call sites were not counted across files"

        # An absolute path must be checked on disk, not on PATH.
        if not present("/bin/sh", which=lambda n: None):
            return False, "an absolute path that exists was reported absent"
        if present("/definitely/not/here/xyz", which=lambda n: "/usr/bin/x"):
            return False, ("a non-existent absolute path was reported present -- "
                           "PATH lookup was used instead of the filesystem")
        return True, "known-good and 7 known-bad cases behaved correctly"
    except Exception as e:                                   # noqa: BLE001
        return False, "canary itself failed: %s: %s" % (type(e).__name__, e)


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run() -> dict:
    """Entry point. The harness runs the canary and suppresses the
    verdict entirely if it fails -- see diagnostics/canary.py."""
    return _canary_harness.guard(META, _canary, _produce,
                                 subject="dependencies")


def _produce(detail):
    sections = [_section("canary self-test", _OK, detail)]
    try:
        found = scan(_repo_root())
    except Exception as e:                                   # noqa: BLE001
        return {
            "id": META["id"], "name": META["name"], "icon": META["icon"],
            "status": "error",
            "summary": "Could not scan for dependencies",
            "output": "\n".join(sections + [
                _section("source scan", _PROBE_FAILED, type(e).__name__)]),
        }

    ev = evaluate(found)
    sections.append(_section(
        "binaries invoked by this codebase", _OK,
        "%d distinct, %d resolvable on this host" % (ev["total"], ev["present"])))

    if ev["missing_required"]:
        lines = ["%s (%d call site%s)" % (b, n, "" if n == 1 else "s")
                 for b, n in ev["missing_required"]]
        sections.append(_section(
            "REQUIRED binaries not found", _MISSING,
            "%d — the code paths calling these will fail when reached:\n    %s"
            % (len(lines), "\n    ".join(lines))))
    else:
        sections.append(_section("every required binary is present", _OK))

    # Counted and named, never silently dropped: an operator should be able to see
    # that these were considered and deliberately not treated as faults.
    for cat, label in ((CAT_OPTIONAL, "optional (skip-if-absent by design)"),
                       (CAT_PLATFORM, "for the Windows agent, not this host"),
                       (CAT_TEST, "used only by tests")):
        names = ev["absent_benign"].get(cat)
        if names:
            sections.append(_section(
                "absent but expected — %s" % label, _OK,
                "%d: %s" % (len(names), ", ".join(sorted(names)))))

    n = len(ev["missing_required"])
    return {
        "id": META["id"], "name": META["name"], "icon": META["icon"],
        "status": "warn" if n else "ok",
        "summary": ("%d required binary/binaries missing" % n) if n
                   else "All required external tools are present",
        "output": "\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
