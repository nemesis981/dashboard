"""Tailscale packaging independence — proves Nemesis works with Tailscale from apt OR snap.

WHY THIS FILE EXISTS. Snap packaging has already broken this codebase TWICE, in two
unrelated subsystems, from one packaging choice:

  1. MagicDNS: strict confinement blocks tailscaled creating
     /etc/resolv.pre-tailscale-backup.conf, so its DNS takeover ABORTS and has never
     once succeeded. Every tailnet-only link the appliance emits is broken.
  2. The netfilter drift checker reported UNDETERMINED forever on its first real
     deployment (2026-08-31): it shelled out to `tailscale`, a snap at /snap/bin, a
     directory absent from systemd's default PATH. FileNotFoundError was swallowed by a
     bare `except Exception` and the check blamed the daemon.

The fix for (2) was not "add /snap/bin to PATH" -- running a snap needs snap-confine,
which refuses to start inside the mount namespace the unit's own hardening creates. The
CLI dependency was removed instead.

These tests exist so the MIGRATION to apt cannot silently regress any of that, and so a
FUTURE change to Tailscale's packaging is caught here rather than in production.

STANDARD FOR EVERY CHECK IN THIS FILE, inherited from
test_drift_check_prefs_source.py::test_works_with_no_tailscale_binary_on_path:
exercise the BEHAVIOUR, do not grep for a string. Where a structural assertion is
genuinely the right instrument (an argv shape, a scan over the repo), it is paired with
a POSITIVE CONTROL proving the instrument can actually detect the thing it reports
absent -- an empty result and a broken detector are otherwise indistinguishable.

Pure tests. No root, no network, no live tailscaled.
"""
import ast
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

_fail = []
_count = 0
EXPECTED_CHECKS = 28

SNAP_SOCK = "/var/snap/tailscale/common/socket/tailscaled.sock"
APT_SOCK = "/var/run/tailscale/tailscaled.sock"
RUN_SOCK = "/run/tailscale/tailscaled.sock"

# Sites where a literal snap path is CORRECT and expected. Anything outside this set is
# a new hardcoded assumption and fails the guard below.
SNAP_PATH_ALLOWLIST = {
    "scripts/deploy_drift_check.sh",              # candidate list, snap LAST (by design)
    "core/netfilter_drift.py",                    # explanatory comment only
    "core/test_drift_check_prefs_source.py",      # documents the 2026-08-31 failure
    "core/test_tailscale_packaging_independence.py",  # this file
}


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _read(rel):
    """Read a repo file. Returns '' when unreadable -- callers assert on content, so an
    unreadable file DEGRADES THE VALUE and fails its check rather than skipping it."""
    try:
        with open(os.path.join(REPO, rel), "r", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def _code_strings(src):
    """Every string literal that reaches RUNTIME -- docstrings excluded.

    A plain `"systemctl" in source` check is the wrong instrument here and produced a
    false failure while this file was being written: netfilter_drift.py's own module
    docstring contains the sentence "NO `systemctl is-active tailscaled` ANYWHERE IN
    HERE, deliberately", so the grep matched the prose DECLARING the absence and
    reported it as presence. Parse instead of grep.

    Returns ["<unparseable>"] on a parse failure so the caller's assertion FAILS rather
    than silently passing on an empty list -- an unreadable input must never round down
    to healthy.
    """
    try:
        tree = ast.parse(src)
    except Exception:
        return ["<unparseable>"]
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docs.add(id(body[0].value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in docs]


# --------------------------------------------------------------------------
# 1. Socket discovery must prefer the native/apt path over the snap path.
# --------------------------------------------------------------------------

def _candidate_order(script_text):
    """Extract the socket candidate list from deploy_drift_check.sh, in order."""
    m = re.search(r"for c in (.+?); do", script_text, re.S)
    if not m:
        return []
    return re.findall(r"(/\S*tailscaled\.sock)", m.group(1))


def _pick(candidates, existing):
    """Reimplements the script's 'first candidate that exists wins' loop."""
    for c in candidates:
        if c in existing:
            return c
    return ""


def test_socket_discovery_order():
    print("\n[socket discovery: apt path must win, snap path retained for mixed fleets]")
    order = _candidate_order(_read("scripts/deploy_drift_check.sh"))
    check("candidate list is parseable and non-empty", len(order) > 0, True)
    check("includes the apt/native socket path", APT_SOCK in order, True)
    check("includes /run variant", RUN_SOCK in order, True)
    check("still includes the snap path (mixed fleets)", SNAP_SOCK in order, True)
    # THE load-bearing ordering property: native before snap.
    i_apt = order.index(APT_SOCK) if APT_SOCK in order else 99
    i_snap = order.index(SNAP_SOCK) if SNAP_SOCK in order else -1
    check("native path is ordered BEFORE the snap path", i_apt < i_snap, True)


def test_socket_discovery_behaviour():
    print("\n[socket discovery: behavioural, all four world-states]")
    order = _candidate_order(_read("scripts/deploy_drift_check.sh"))
    check("both present -> apt wins (the migration overlap case)",
          _pick(order, {APT_SOCK, SNAP_SOCK}), APT_SOCK)
    check("only apt present -> apt chosen (POST-migration)",
          _pick(order, {APT_SOCK}), APT_SOCK)
    check("only snap present -> snap chosen (PRE-migration, back-compat)",
          _pick(order, {SNAP_SOCK}), SNAP_SOCK)
    check("neither present -> empty, caller warns and fails closed",
          _pick(order, set()), "")


# --------------------------------------------------------------------------
# 2. netfilter_drift must not depend on the CLI or on a systemd unit name.
# --------------------------------------------------------------------------

def test_netfilter_drift_is_packaging_agnostic():
    print("\n[netfilter_drift: identical verdict with and without a tailscale binary]")
    import netfilter_drift as D
    prefs = '{"NetfilterMode": 1}'

    with_path = D.check_netfilter_mode(prefs)[0]
    saved = os.environ.get("PATH", "")
    try:
        os.environ["PATH"] = ""          # no tailscale binary reachable, at all
        without_path = D.check_netfilter_mode(prefs)[0]
    finally:
        os.environ["PATH"] = saved

    check("verdict with a normal PATH is OK", with_path, D.OK)
    check("verdict with an EMPTY PATH is identical (CLI-independent)",
          without_path, with_path)

    # POSITIVE CONTROL first: prove the instrument can SEE a systemctl call before
    # trusting it to report one absent. Known-bad and known-good in one sample.
    probe = _code_strings(
        '"""docstring mentioning systemctl only."""\nimport subprocess\nsubprocess.run(["systemctl", "is-active", "x"])\n')
    check("CONTROL: instrument detects a real systemctl call",
          any("systemctl" in x for x in probe), True)
    check("CONTROL: instrument ignores a docstring mention",
          any("docstring mentioning" in x for x in probe), False)

    strings = _code_strings(_read("core/netfilter_drift.py"))
    check("no systemctl proxy in executable code",
          any("systemctl" in x for x in strings), False)
    check("no snap path in executable code",
          any("/snap/" in x for x in strings), False)
    check("unreadable prefs -> UNDETERMINED, never OK",
          D.check_netfilter_mode("")[0], D.UNDETERMINED)


# --------------------------------------------------------------------------
# 3. Binary invocation must be PATH-resolved, never a hardcoded location.
# --------------------------------------------------------------------------

def _fake_tailscale(dirpath):
    p = os.path.join(dirpath, "tailscale")
    with open(p, "w") as fh:
        fh.write("#!/bin/sh\necho 'fake-peer.example.ts.net endpoint: 1.2.3.4:41641'\n")
    os.chmod(p, 0o755)
    return p


def test_probe_resolves_binary_anywhere():
    print("\n[_probe_tailscale: finds the binary wherever packaging puts it]")
    from modules.diagnostics import watcher
    saved = os.environ.get("PATH", "")
    found_a = found_b = None
    absent = "sentinel"
    try:
        with tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            _fake_tailscale(da)
            os.environ["PATH"] = da
            found_a = watcher._probe_tailscale()

            _fake_tailscale(db)
            os.environ["PATH"] = db      # DIFFERENT dir: proves path-independence
            found_b = watcher._probe_tailscale()

            os.environ["PATH"] = ""      # nothing on PATH at all
            absent = watcher._probe_tailscale()
    finally:
        os.environ["PATH"] = saved

    check("resolves a binary in an arbitrary dir (A)", found_a is not None, True)
    check("resolves it again from a DIFFERENT dir (B)", found_b is not None, True)
    check("returns None when absent -- no crash, no false 'connected'", absent, None)


def test_invocations_are_bare_names():
    print("\n[callers invoke a bare name, never an absolute packaging path]")
    for rel in ("dashboard.py", "core/rp_identity.py"):
        src = _read(rel)
        hits = re.findall(r'subprocess\.run\(\s*\[\s*["\']([^"\']*tailscale[^"\']*)["\']', src)
        # A hardcoded absolute path here would break on the other packaging.
        bare = all(h == "tailscale" for h in hits) and len(hits) > 0
        check("%s invokes bare 'tailscale' (found %d)" % (rel, len(hits)), bare, True)


# --------------------------------------------------------------------------
# 4. tailscale_api talks to the cloud only -- packaging cannot affect it.
# --------------------------------------------------------------------------

def test_tailscale_api_is_cloud_only():
    print("\n[tailscale_api: cloud REST only, no local binary or socket]")
    src = _read("alert_manager/tailscale_api.py")
    check("uses the Tailscale cloud API", "api.tailscale.com" in src, True)
    check("no /var/snap reference", "/var/snap" in src, False)
    check("no /snap/bin reference", "/snap/bin" in src, False)
    check("no local socket path", "tailscaled.sock" in src, False)


# --------------------------------------------------------------------------
# 5. FUTURE-REGRESSION GUARD -- no NEW hardcoded snap paths anywhere in the repo.
# --------------------------------------------------------------------------

def _scan_repo():
    scanned, offenders, control = 0, [], False
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "__pycache__", "node_modules", ".venv")]
        for fn in files:
            if not fn.endswith((".py", ".sh", ".js", ".html")):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, REPO)
            try:
                with open(full, "r", errors="replace") as fh:
                    text = fh.read()
            except Exception:
                continue
            scanned += 1
            if "/var/snap/tailscale" in text or "/snap/bin/tailscale" in text:
                if rel == "scripts/deploy_drift_check.sh":
                    control = True          # positive control: detector demonstrably works
                if rel not in SNAP_PATH_ALLOWLIST:
                    offenders.append(rel)
    return scanned, offenders, control


def test_no_new_hardcoded_snap_paths():
    print("\n[guard: a NEW hardcoded snap path anywhere in the repo fails here]")
    scanned, offenders, control = _scan_repo()
    # Liveness: a scan that read nothing would report "no offenders" and mean nothing.
    check("scan actually read a plausible number of files", scanned > 50, True)
    # Positive control: prove the detector CAN find a snap path before trusting a zero.
    check("detector finds the known snap path in deploy_drift_check.sh", control, True)
    check("no snap paths outside the allowlist (offenders=%r)" % (offenders,),
          offenders, [])


if __name__ == "__main__":
    print("Tailscale packaging independence — apt/snap agnostic behaviour")
    test_socket_discovery_order()
    test_socket_discovery_behaviour()
    test_netfilter_drift_is_packaging_agnostic()
    test_probe_resolves_binary_anywhere()
    test_invocations_are_bare_names()
    test_tailscale_api_is_cloud_only()
    test_no_new_hardcoded_snap_paths()
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
