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
import shutil
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

_fail = []
_count = 0
EXPECTED_CHECKS = 96

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
    # tailscale_packaging() must name /var/snap/tailscale to DETECT a snap install.
    # Legitimate and required: it is used for REPORTING which packaging is present,
    # never to decide whether to act. Added to the allowlist deliberately after this
    # guard flagged it -- which is the guard working, not a false positive.
    "core/vpn_dns_guard.py",
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


# --------------------------------------------------------------------------
# 6. MagicDNS conflict guard (vpn_dns_guard) -- EVERY branch is FORCED.
#    Added 2026-09-01. A branch that is merely reachable is not covered: the
#    standing check is "name the test that forces execution down this path".
# --------------------------------------------------------------------------

def _guard():
    import vpn_dns_guard
    return vpn_dns_guard


_resolv_seq = [0]


def _resolv(tmpdir, lines):
    """Write a resolv.conf fixture to a UNIQUE path.

    It previously reused one filename per tempdir, so a second fixture silently
    OVERWROTE the first and two differently-named variables referred to the same
    file -- the 'exclusive' case was actually reading the 'mixed' content and the
    probe short-circuited before its query ran. The tell was the call count: 0
    probes on a path that must make 2.
    """
    _resolv_seq[0] += 1
    p = os.path.join(tmpdir, "resolv.%d.conf" % _resolv_seq[0])
    with open(p, "w") as fh:
        fh.write(lines)
    return p


def test_packaging_detection_forced():
    print("\n[packaging detection: each branch FORCED, not merely reachable]")
    G = _guard()
    real_which, real_realpath, real_isdir = shutil.which, os.path.realpath, os.path.isdir
    try:
        shutil.which = lambda n: "/snap/bin/tailscale"
        os.path.realpath = lambda p: "/snap/tailscale/154/bin/tailscale"
        os.path.isdir = lambda p: False
        check("snap binary path -> 'snap'", G.tailscale_packaging(), "snap")

        shutil.which = lambda n: "/usr/bin/tailscale"
        os.path.realpath = lambda p: "/usr/bin/tailscale"
        os.path.isdir = lambda p: False
        check("apt binary path -> 'apt'", G.tailscale_packaging(), "apt")

        os.path.isdir = lambda p: p == "/var/snap/tailscale"
        check("/var/snap present overrides to 'snap'", G.tailscale_packaging(), "snap")

        shutil.which = lambda n: None
        check("no binary -> 'absent'", G.tailscale_packaging(), "absent")
    finally:
        shutil.which, os.path.realpath, os.path.isdir = real_which, real_realpath, real_isdir


def test_resolv_exclusivity():
    print("\n[resolv.conf exclusivity: unreadable must NOT read as 'not exclusive']")
    G = _guard()
    with tempfile.TemporaryDirectory() as d:
        check("only tailscale servers -> True",
              G.resolv_is_exclusively_tailscale(
                  _resolv(d, "nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\n")), True)
        check("tailscale + pi-hole -> False",
              G.resolv_is_exclusively_tailscale(
                  _resolv(d, "nameserver 100.100.100.100\nnameserver 127.0.0.1\n")), False)
        check("pi-hole only -> False",
              G.resolv_is_exclusively_tailscale(_resolv(d, "nameserver 127.0.0.1\n")), False)
        check("no nameservers -> False",
              G.resolv_is_exclusively_tailscale(_resolv(d, "# nothing\n")), False)
    check("UNREADABLE -> None (fails closed, never False)",
          G.resolv_is_exclusively_tailscale("/nonexistent/resolv.conf"), None)


def test_conflict_branches_forced():
    print("\n[conflict probe: all six branches forced via injected query]")
    G = _guard()
    yes = lambda *a, **k: True
    no = lambda *a, **k: False
    unk = lambda *a, **k: None
    with tempfile.TemporaryDirectory() as d:
        excl = _resolv(d, "nameserver 100.100.100.100\n")
        mixed = _resolv(d, "nameserver 127.0.0.1\n")

        r = G.magicdns_conflict(query=yes, resolv_path="/nonexistent/x")
        check("unreadable resolv.conf -> conflict None", r["conflict"], None)

        r = G.magicdns_conflict(query=no, resolv_path=mixed)
        check("NOT exclusive (the SNAP shape) -> conflict False", r["conflict"], False)
        check("...and the reason names the snap case",
              "snap install" in r["reason"], True)

        r = G.magicdns_conflict(query=yes, resolv_path=excl)
        check("exclusive + resolver ANSWERS -> conflict False", r["conflict"], False)

        r = G.magicdns_conflict(query=no, resolv_path=excl)
        check("exclusive + both silent -> conflict None (positive control)",
              r["conflict"], None)
        check("...and the reason names the POSITIVE CONTROL",
              "POSITIVE CONTROL" in r["reason"], True)

        calls = {"n": 0}
        def ts_down_fallback_up(server, *a, **k):
            calls["n"] += 1
            return False if server == G.TS_MAGIC_V4 else True
        r = G.magicdns_conflict(query=ts_down_fallback_up, resolv_path=excl)
        check("exclusive + ts silent + fallback answers -> conflict TRUE",
              r["conflict"], True)
        check("...and it probed BOTH resolvers (control really ran)", calls["n"], 2)

        r = G.magicdns_conflict(query=unk, resolv_path=excl)
        check("probe undeterminable -> conflict None (fails closed)", r["conflict"], None)


def test_snap_can_never_conflict():
    print("\n[SNAP: the condition cannot arise -- no-op BY CONSTRUCTION]")
    G = _guard()
    # Under snap the takeover is blocked, so resolv.conf is never exclusively
    # Tailscale's. Whatever the resolvers do, the guard must not fire.
    with tempfile.TemporaryDirectory() as d:
        snap_shape = _resolv(d, "nameserver 127.0.0.1\nnameserver 10.0.0.243\n")
        for label, q in (("all silent", lambda *a, **k: False),
                         ("all answering", lambda *a, **k: True),
                         ("undeterminable", lambda *a, **k: None)):
            r = G.magicdns_conflict(query=q, resolv_path=snap_shape)
            check("snap shape, %-14s -> conflict False" % label, r["conflict"], False)


def test_guard_uses_no_unit_name_proxy():
    print("\n[the snap unit-name trap is avoided in executable code]")
    strings = _code_strings(_read("core/vpn_dns_guard.py"))
    check("no 'systemctl is-active' proxy in executable code",
          any("is-active" in x for x in strings), False)
    check("no bare 'tailscaled' unit name in executable code",
          any(x.strip() == "tailscaled" for x in strings), False)


# --------------------------------------------------------------------------
# 7. nemesis_fwd magicdns_switch -- the PRIVILEGED actuator (fifth peer).
#    Added 2026-09-01. The load-bearing property is that the HELPER re-measures
#    and refuses when its own verdict disagrees with the caller's request.
# --------------------------------------------------------------------------

def _fwd():
    sys.path.insert(0, os.path.join(REPO, "alert_manager"))
    import nemesis_fwd
    return nemesis_fwd


class _FakeProbe:
    """Stands in for vpn_dns_guard so every verdict can be FORCED."""
    def __init__(self, conflict, packaging="apt", reason="forced"):
        self._v = {"conflict": conflict, "packaging": packaging, "reason": reason}
    def magicdns_conflict(self, *a, **k):
        return dict(self._v)


def _run_op(F, enable, conflict, packaging="apt", owned=False,
            pref_after=None, cli="/usr/bin/tailscale", set_rc=0):
    """Invoke op_magicdns_switch with every external dependency forced."""
    import subprocess as _sp
    saved = (sys.modules.get("vpn_dns_guard"), F._tailscale_bin,
             F._magicdns_state_read, F._magicdns_state_write,
             F._magicdns_read_pref, F._errors_record, _sp.run)
    recorded = []
    try:
        sys.modules["vpn_dns_guard"] = _FakeProbe(conflict, packaging)
        F._tailscale_bin = lambda: cli
        F._magicdns_state_read = lambda: {"disabled_by_guard": owned}
        F._magicdns_state_write = lambda st: True
        F._magicdns_read_pref = lambda exe: (enable if pref_after is None else pref_after)
        F._errors_record = lambda code, ctx=None: recorded.append(code)

        class _R:
            def __init__(self): self.returncode = set_rc; self.stdout = "{}"; self.stderr = ""
        _sp.run = lambda *a, **k: _R()
        return F.op_magicdns_switch({"enable": enable}), recorded
    finally:
        (mod, tb, sr, sw, rp, er, spr) = saved
        if mod is None:
            sys.modules.pop("vpn_dns_guard", None)
        else:
            sys.modules["vpn_dns_guard"] = mod
        F._tailscale_bin, F._magicdns_state_read = tb, sr
        F._magicdns_state_write, F._magicdns_read_pref = sw, rp
        F._errors_record, _sp.run = er, spr


def test_fwd_registry_wiring():
    print("\n[fwd: the fifth peer is wired in every registry, and ONLY that op]")
    F = _fwd()
    check("op is dispatchable", callable(F.OPS.get("magicdns_switch")), True)
    check("op is in WRITE_OPS", "magicdns_switch" in F.WRITE_OPS, True)
    check("vpn-dns-guard grants EXACTLY one op",
          F.PEER_POLICY["vpn-dns-guard"]["ops"], {"magicdns_switch"})
    check("that peer requires no credential (unattended)",
          F.PEER_POLICY["vpn-dns-guard"]["require_credential"], False)
    check("audit actor is the peer name",
          F.PEER_POLICY["vpn-dns-guard"]["audit_actor"], "vpn-dns-guard")
    others = [n for n, p in F.PEER_POLICY.items()
              if n != "vpn-dns-guard" and "magicdns_switch" in p["ops"]]
    check("NO other peer was granted it", others, [])
    check("NOT token-exempt (peer-gated, not token-gated)",
          "magicdns_switch" in F.NO_CREDENTIAL_OPS, False)
    check("audit action is dns_-prefixed, not fw_",
          F.audit_action_for("magicdns_switch"), "dns_magicdns_switch")


def test_fwd_rejects_bad_params():
    print("\n[fwd: parameter validation is helper-side]")
    F = _fwd()
    for bad in ("false", 0, 1, None, [], {}):
        try:
            F.op_magicdns_switch({"enable": bad})
            ok = False
        except Exception as exc:
            ok = exc.__class__.__name__ == "Denied"
        check("non-bool enable=%-6r rejected" % (bad,), ok, True)


def test_fwd_refuses_when_its_own_measurement_disagrees():
    print("\n[fwd: THE load-bearing property -- helper re-measures, caller does not decide]")
    F = _fwd()
    res, rec = _run_op(F, enable=False, conflict=False)
    check("disable refused when helper sees NO conflict", res.get("refused"), True)
    check("...and it did NOT report success", res.get("ok"), False)
    check("...and it recorded E-MAGICDNS-001", "E-MAGICDNS-001" in rec, True)

    res, rec = _run_op(F, enable=False, conflict=None)
    check("disable refused when conflict UNDETERMINED (fails closed)",
          res.get("refused"), True)


def test_fwd_snap_refuses_and_says_so():
    print("\n[fwd: SNAP -- refuses AND reports 'does not apply', never silent]")
    F = _fwd()
    res, rec = _run_op(F, enable=False, conflict=False, packaging="snap")
    check("snap: refused", res.get("refused"), True)
    check("snap: reason says CONDITION DOES NOT APPLY",
          "DOES NOT APPLY" in (res.get("reason") or ""), True)
    check("snap: reason explains confinement blocks the takeover",
          "confinement" in (res.get("reason") or ""), True)
    check("snap: packaging reported back to the caller", res.get("packaging"), "snap")


def test_fwd_never_reenables_what_it_did_not_disable():
    print("\n[fwd: a human-set value is never overridden]")
    F = _fwd()
    res, rec = _run_op(F, enable=True, conflict=False, owned=False)
    check("enable refused when helper did not disable it", res.get("refused"), True)
    check("...reason names it as not ours", "did not disable" in (res.get("reason") or ""), True)
    res, rec = _run_op(F, enable=True, conflict=True, owned=True)
    check("enable refused while the conflict is STILL present", res.get("refused"), True)


def test_fwd_verifies_the_change_took():
    print("\n[fwd: a CLAIMED change is not a change]")
    F = _fwd()
    res, rec = _run_op(F, enable=False, conflict=True, pref_after=True)
    check("pref did not actually change -> ok False", res.get("ok"), False)
    check("...and recorded E-MAGICDNS-002", "E-MAGICDNS-002" in rec, True)
    res, rec = _run_op(F, enable=False, conflict=True, pref_after=None)
    check("happy path: conflict real -> applied and verified", res.get("ok"), True)
    check("...and reported verified=True", res.get("verified"), True)


def test_fwd_cli_absent_fails_closed():
    print("\n[fwd: no tailscale CLI -> explicit failure, never a silent success]")
    F = _fwd()
    res, rec = _run_op(F, enable=False, conflict=True, cli=None)
    check("missing CLI -> ok False", res.get("ok"), False)
    check("...and recorded E-MAGICDNS-003", "E-MAGICDNS-003" in rec, True)


# --------------------------------------------------------------------------
# 8. CALL-SITE REACHABILITY -- "does production actually RUN this?"
#
# ⛔ WHY THIS SECTION EXISTS. On 2026-09-01 the MagicDNS guard shipped, passed 82
# checks, deployed cleanly, and DID NOTHING during a live test that produced a real
# DNS outage: evaluate_magicdns() had NO CALLER. Every one of those 82 checks
# invoked the functions DIRECTLY, so the suite proved the mechanism WORKS and never
# proved it RUNS. The identical defect had been fixed in this repo one day earlier
# (66ba78e, "wire drift_watch into the diagnostics watcher -- it had no caller").
#
# A test that calls a function cannot see a missing call site. Only a structural
# assertion over the source can. These are those assertions.
# --------------------------------------------------------------------------

def _calls_within(rel_path, caller, callee):
    """True if `caller`'s body contains a call to `callee`.

    Counts BOTH bare calls (`f()`) and attribute calls (`mod.f()`), because the
    helper reaches its re-validation through a lazily-imported module.
    Returns None if the file or the caller cannot be found -- which FAILS the
    assertion rather than passing it, since 'not found' must never read as 'fine'.
    """
    src = _read(rel_path)
    if not src:
        return None
    try:
        tree = ast.parse(src)
    except Exception:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == caller:
            for c in ast.walk(node):
                if not isinstance(c, ast.Call):
                    continue
                f = c.func
                if isinstance(f, ast.Name) and f.id == callee:
                    return True
                if isinstance(f, ast.Attribute) and f.attr == callee:
                    return True
            return False
    return None


def test_callsite_control():
    print("\n[CONTROL: the call-site checker can actually detect ABSENCE]")
    # Known-present and known-absent, proven before the real assertions are trusted.
    check("detects a call that IS there (reconcile -> detect_tunnel)",
          _calls_within("core/vpn_dns_guard.py", "reconcile", "detect_tunnel"), True)
    check("detects a call that is NOT there",
          _calls_within("core/vpn_dns_guard.py", "reconcile", "no_such_function_xyz"), False)
    check("missing caller -> None, never True",
          _calls_within("core/vpn_dns_guard.py", "no_such_caller_xyz", "anything"), None)
    check("missing file -> None, never True",
          _calls_within("core/no_such_file_xyz.py", "a", "b"), None)


def test_magicdns_guard_is_reachable_from_the_service_loop():
    print("\n[THE BUG THAT SHIPPED: the guard must be reachable from main_loop]")
    G = "core/vpn_dns_guard.py"
    # The whole chain, link by link. Any single break makes the guard dead code.
    check("main_loop() -> reconcile()", _calls_within(G, "main_loop", "reconcile"), True)
    check("reconcile() -> evaluate_magicdns()   <-- THE MISSING LINK",
          _calls_within(G, "reconcile", "evaluate_magicdns"), True)
    check("evaluate_magicdns() -> magicdns_conflict()",
          _calls_within(G, "evaluate_magicdns", "magicdns_conflict"), True)
    check("evaluate_magicdns() -> _magicdns_ask_helper()",
          _calls_within(G, "evaluate_magicdns", "_magicdns_ask_helper"), True)
    check("_magicdns_ask_helper() -> magicdns_switch() (the client wrapper)",
          _calls_within(G, "_magicdns_ask_helper", "magicdns_switch"), True)


def test_helper_revalidation_has_a_call_site():
    print("\n[the helper's RE-VALIDATION must actually run, not merely exist]")
    F = "alert_manager/nemesis_fwd.py"
    check("op_magicdns_switch() -> magicdns_conflict()  (re-validation)",
          _calls_within(F, "op_magicdns_switch", "magicdns_conflict"), True)
    check("op_magicdns_switch() -> _magicdns_read_pref() (verify-after-act)",
          _calls_within(F, "op_magicdns_switch", "_magicdns_read_pref"), True)
    check("op_magicdns_switch() -> _magicdns_state_read() (own-change check)",
          _calls_within(F, "op_magicdns_switch", "_magicdns_state_read"), True)
    check("op_magicdns_switch() -> _errors_record() (failures are recorded)",
          _calls_within(F, "op_magicdns_switch", "_errors_record"), True)
    # And it must be dispatchable -- reachable from the wire, not just defined.
    fwd = _fwd()
    check("op is reachable from the OPS dispatch table",
          fwd.OPS.get("magicdns_switch") is fwd.op_magicdns_switch, True)


if __name__ == "__main__":
    print("Tailscale packaging independence — apt/snap agnostic behaviour")
    test_socket_discovery_order()
    test_socket_discovery_behaviour()
    test_netfilter_drift_is_packaging_agnostic()
    test_probe_resolves_binary_anywhere()
    test_invocations_are_bare_names()
    test_tailscale_api_is_cloud_only()
    test_no_new_hardcoded_snap_paths()
    test_packaging_detection_forced()
    test_resolv_exclusivity()
    test_conflict_branches_forced()
    test_snap_can_never_conflict()
    test_guard_uses_no_unit_name_proxy()
    test_fwd_registry_wiring()
    test_fwd_rejects_bad_params()
    test_fwd_refuses_when_its_own_measurement_disagrees()
    test_fwd_snap_refuses_and_says_so()
    test_fwd_never_reenables_what_it_did_not_disable()
    test_fwd_verifies_the_change_took()
    test_fwd_cli_absent_fails_closed()
    test_callsite_control()
    test_magicdns_guard_is_reachable_from_the_service_loop()
    test_helper_revalidation_has_a_call_site()
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
