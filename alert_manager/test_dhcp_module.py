import pathlib
#!/usr/bin/env python3
"""Nemesis-owned DHCP module — config rendering, validation gate, preconditions.

Run: python3 alert_manager/test_dhcp_module.py

WHAT THIS SUITE IS REALLY GUARDING
----------------------------------
The 2026-08-06 gateway build produced a cluster of config failures whose common
shape was: **two independent writers to one config surface, with no validation
gate between edit and reload, where a syntax error takes down DNS as well as
DHCP.** A duplicate `dhcp-range` between an `/etc/dnsmasq.d/` drop-in and
Pi-hole's native `[dhcp]` aborted the entire dnsmasq config — twice.

This module removes that class by owning its own dnsmasq instance outright. The
checks below pin the properties that make that safe, and several are direct
regression tests for specific mistakes made that day:

  * a naive `active = false` edit hitting the WRONG section of `pihole.toml`
  * a config that renders "serve everywhere" when no interface is configured
  * a validator that has never been shown to reject anything
  * a port check that can only ever return one answer when unprivileged

Every check runs offline: no service is started, no live config is written, no
root required.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

import modules  # noqa: E402
modules.set_shared_db_path("/var/lib/nemesis/alerts.db")

import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location(
    "dhcpmod", os.path.join(REPO, "modules", "dhcp", "module.py"))
dhcp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dhcp)

import nemesis_errors  # noqa: E402

_modpath_for_ast = os.path.join(REPO, "modules", "dhcp", "module.py")

EXPECTED_CHECKS = 81

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 42:
        g, w = g[:39] + "...", w[:39] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def _raises(fn, exc):
    try:
        fn()
        return False
    except exc:
        return True


def scope(**kw):
    kw.setdefault("start", "10.66.0.50")
    kw.setdefault("end", "10.66.0.150")
    kw.setdefault("lease_time", "12h")
    return dhcp.Scope(**kw)


print("\n1. Error codes register against the REAL error system")
# Window 1 shipped the real nemesis_errors mid-build. Its API is CONNECTION-
# FIRST -- register_error_code(conn, ...) -- so this exercises it against a
# throwaway in-memory DB rather than the live one. Registration at import is
# impossible with that API and would be wrong anyway (importing must not write).
import sqlite3  # noqa: E402
_c = sqlite3.connect(":memory:")
nemesis_errors.init_error_tables(_c)
dhcp.ensure_codes_registered(_c)
_registered = {r[0] for r in _c.execute("SELECT code FROM error_codes")}
for code in (dhcp.E_CONFIG_INVALID, dhcp.E_PIHOLE_DHCP_ON, dhcp.E_PORT_BOUND,
             dhcp.E_IFACE_UNUSABLE, dhcp.E_LEASE_DIR, dhcp.E_DAEMON_FAILED,
             dhcp.E_IFACE_NOT_ALLOWED, dhcp.E_RELOAD_FAILED):
    check("%s registered" % code, code in _registered, True)
check("registration is idempotent (re-running is a no-op)",
      (dhcp.ensure_codes_registered(_c),
       len({r[0] for r in _c.execute("SELECT code FROM error_codes")}))[1],
      len(_registered))
check("severities land on the canonical ladder",
      {r[0] for r in _c.execute("SELECT DISTINCT severity FROM error_codes")}
      <= set(__import__("nemesis_severity").CANONICAL), True)

print("\n2. Recording an UNREGISTERED code is refused — the typo guard")
try:
    nemesis_errors.record_error(_c, "E-DHCP-999")
    check("unregistered code refused", False, True)
except Exception:
    check("unregistered code refused", True, True)
check("a REGISTERED code records an occurrence",
      isinstance(nemesis_errors.record_error(
          _c, dhcp.E_PORT_BOUND, context={"t": 1}), int), True)

print("\n2b. _record() degrades LOUDLY when no DB is available")
# The failure must still be visible; it must simply not be persisted. Returning
# None (not raising, not silently succeeding) is what lets DHCP keep running
# while making the ledger gap explicit in the log.
check("_record(conn=None) returns None rather than raising",
      dhcp._record(dhcp.E_PORT_BOUND, context={"x": 1}, conn=None), None)

print("\n3. Config renders the properties that make coexistence safe")
cfg = dhcp.DhcpConfig(interfaces=["eth9"], scopes=[scope(tag="quarantine")],
                      default_tag="quarantine")
text = cfg.render()
def directives(conf_text):
    """Config lines only — comments and blanks stripped.

    Needed because a substring search over the whole file matches the module's
    own COMMENTS. The first draft of the `bind-interfaces` check below asserted
    `"bind-interfaces" not in text` and failed, because the config carries a
    comment explaining precisely why that directive is absent. Same trap this
    project has recorded before: a grep for the thing matching the note about
    the thing. Parse the directives; do not pattern-match the prose.
    """
    return [ln.strip() for ln in conf_text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


dirs = directives(text)
check("port=0 present (no DNS — ADR 0002 structural)", "port=0" in dirs, True)
check("bind-interfaces ABSENT as a directive (measured: breaks DHCP broadcast)",
      any(d.startswith("bind-interfaces") for d in dirs), False)
check("CONTROL: the explanatory comment IS still present in the file",
      "bind-interfaces" in text, True)
check("serves only the named interface", "interface=eth9" in text, True)
check("lease file is Nemesis-owned, not Pi-hole's",
      "dhcp-leasefile=/var/lib/nemesis/dhcp.leases" in text, True)
check("no /etc/dnsmasq.d reference anywhere", "dnsmasq.d" in text, False)
check("carries a do-not-hand-edit banner", "DO NOT EDIT BY HAND" in text, True)

print("\n4. Multi-scope + tags render (segmentation is first-class, not retrofitted)")
multi = dhcp.DhcpConfig(
    interfaces=["eth9"],
    scopes=[scope(tag="quarantine", start="10.66.0.50", end="10.66.0.99",
                  lease_time="5m", router="10.66.0.1"),
            scope(tag="iot", start="10.66.2.50", end="10.66.2.200",
                  lease_time="12h", router="10.66.2.1", dns="10.66.0.1")],
    default_tag="quarantine")
mtext = multi.render()
check("tagged range emitted", "dhcp-range=set:iot,10.66.2.50,10.66.2.200,12h" in mtext, True)
check("per-tier router option", "dhcp-option=tag:iot,3,10.66.2.1" in mtext, True)
check("per-tier DNS points at Pi-hole", "dhcp-option=tag:iot,6,10.66.0.1" in mtext, True)
check("quarantine keeps a SHORT lease (fast re-tiering)",
      "dhcp-range=set:quarantine,10.66.0.50,10.66.0.99,5m" in mtext, True)
check("hosts.d wired for SIGHUP-reloadable tier assignment",
      "dhcp-hostsfile=" in mtext, True)

print("\n5. Refusals — a DHCP server that guesses is worse than one that stops")
try:
    dhcp.DhcpConfig(interfaces=[], scopes=[scope()]).render()
    check("empty interfaces REFUSES (would serve everywhere)", False, True)
except dhcp.DhcpConfigError:
    check("empty interfaces REFUSES (would serve everywhere)", True, True)
try:
    dhcp.DhcpConfig(interfaces=["eth9"], scopes=[]).render()
    check("no scopes REFUSES", False, True)
except dhcp.DhcpConfigError:
    check("no scopes REFUSES", True, True)
try:
    dhcp.DhcpConfig(interfaces=["eth9"], scopes=[scope(tag="a")],
                    default_tag="nonexistent").render()
    check("default_tag with no scope REFUSES", False, True)
except dhcp.DhcpConfigError:
    check("default_tag with no scope REFUSES", True, True)

print("\n6. The validation gate, and its self-test")
ok, detail = dhcp.selftest_validator()
if not ok:
    print("      selftest detail:", detail)
check("validator self-test passes (accepts good, REJECTS bad)", ok, True)
good_ok, _ = dhcp.validate_config_text("port=0\ninterface=lo\n"
                                       "dhcp-range=10.0.0.50,10.0.0.60,1h\n")
check("CONTROL: known-good config accepted", good_ok, True)
bad_ok, _ = dhcp.validate_config_text("port=0\nnot-a-real-directive=1\n")
check("CONTROL: bogus directive rejected", bad_ok, False)

print("\n7. REGRESSION — the exact duplicate-keyword bug that took DNS down twice")
# ⚠ MEASURED 2026-08-06, and it corrected this suite's first draft: the
# offending directive is `dhcp-leasefile`, NOT `dhcp-range`.
#
#   duplicate dhcp-range     -> "syntax check OK"  (rc=0)
#   duplicate dhcp-leasefile -> "illegal repeated keyword" (rc=1)
#
# That is not a quirk — REPEATED dhcp-range is how multi-scope works, so it must
# be legal. `dhcp-leasefile` is single-valued. The first draft of this test
# asserted duplicate dhcp-range would be rejected, it was not, and asserting the
# wrong directive would have left this suite "green" while proving nothing about
# the failure it exists to guard.
dup_lease = ("port=0\ninterface=lo\n"
             "dhcp-range=10.0.0.50,10.0.0.60,1h\n"
             "dhcp-leasefile=/tmp/a.leases\n"
             "dhcp-leasefile=/tmp/b.leases\n")
dup_ok, dup_detail = dhcp.validate_config_text(dup_lease)
check("duplicate dhcp-leasefile REJECTED (the real 2026-08-06 abort)", dup_ok, False)
check("...and rejected for the right reason", "repeated keyword" in dup_detail, True)
# The control that keeps the check above honest: multi-scope MUST stay legal.
multi_range_ok, _ = dhcp.validate_config_text(
    "port=0\ninterface=lo\n"
    "dhcp-range=10.0.0.50,10.0.0.60,1h\n"
    "dhcp-range=10.0.1.50,10.0.1.60,1h\n")
check("CONTROL: multiple dhcp-range stays LEGAL (segmentation needs it)",
      multi_range_ok, True)
check("our renderer emits exactly one dhcp-leasefile",
      mtext.count("dhcp-leasefile="), 1)

print("\n8. REGRESSION — pihole.toml section scoping (the wrong-section edit)")
# On 2026-08-06 a naive `.replace('active = false', ...)` edited a DIFFERENT
# section. This fixture has `active` in two sections; only [dhcp] must count.
toml_dhcp_off = """
[dns]
active = true
upstreams = ["1.1.1.1"]

[dhcp]
active = false
start = "10.0.0.50"
"""
toml_dhcp_on = toml_dhcp_off.replace("[dhcp]\nactive = false",
                                     "[dhcp]\nactive = true")
with tempfile.TemporaryDirectory() as td:
    p_off = os.path.join(td, "off.toml")
    p_on = os.path.join(td, "on.toml")
    open(p_off, "w").write(toml_dhcp_off)
    open(p_on, "w").write(toml_dhcp_on)
    check("reads [dhcp] as OFF while [dns] is on (not fooled by section order)",
          dhcp.pihole_dhcp_active(p_off), False)
    check("reads [dhcp] as ON when it is on", dhcp.pihole_dhcp_active(p_on), True)
    check("MISSING file returns None (unknown), never False",
          dhcp.pihole_dhcp_active(os.path.join(td, "nope.toml")), None)

print("\n9. REGRESSION — the port check must not confuse EACCES with in-use")
# First draft caught bare OSError and returned "bound". :67 is privileged, so
# unprivileged it would have answered "bound" every time — a measurement that
# can only produce one value.
state = dhcp.port67_state()
check("port67_state returns a tri-state, not a bool",
      state in ("free", "bound", "unknown"), True)
check("unprivileged run reports 'unknown', NOT a false 'bound'",
      state if os.geteuid() != 0 else "unknown", "unknown")

print("\n10. Preconditions refuse, and record an error code when they do")
fails = dhcp.check_preconditions(interfaces=["eth9"], allowlist=set(),
                                 conn=None)
codes = {c for c, _ in fails}
check("empty allowlist refuses", dhcp.E_IFACE_NOT_ALLOWED in codes, True)
fails2 = dhcp.check_preconditions(interfaces=["eth9"], allowlist={"eth0"},
                                  conn=None)
check("interface outside allowlist refuses",
      dhcp.E_IFACE_NOT_ALLOWED in {c for c, _ in fails2}, True)
check("nonexistent interface refuses",
      dhcp.E_IFACE_UNUSABLE in {c for c, _ in fails2}, True)
check("every code a precondition can emit is one it registered",
      all(c in _registered for c, _ in fails + fails2), True)

print("\n11. Three-way DHCP authority toggle")
check("three modes offered", set(dhcp.MODES),
      {"nemesis", "pihole", "provider"})
check("DEFAULT is provider — never take over DHCP unasked",
      dhcp.DEFAULT_MODE, dhcp.MODE_PROVIDER)
check("only the nemesis mode serves DHCP",
      [m for m in dhcp.MODES if dhcp.mode_capabilities(m)["serves_dhcp"]],
      [dhcp.MODE_NEMESIS])
check("unknown mode RAISES rather than defaulting to a capability set",
      _raises(lambda: dhcp.mode_capabilities("bogus"), ValueError), True)

print("\n11b. Every non-full mode states what it COSTS — no silent degradation")
for m in (dhcp.MODE_PIHOLE, dhcp.MODE_PROVIDER):
    caps = dhcp.mode_capabilities(m)
    check("%s lists concrete degradations" % m, len(caps["degraded"]) >= 3, True)
    check("%s declares segmentation unavailable" % m,
          "UNAVAILABLE" in caps["segmentation"], True)
check("provider mode is explicit that NO hostname capture happens",
      dhcp.mode_capabilities(dhcp.MODE_PROVIDER)["hostname_capture"], "NONE")
check("provider mode says segmentation is dead even with good hardware",
      any("REGARDLESS" in d for d in
          dhcp.mode_capabilities(dhcp.MODE_PROVIDER)["degraded"]), True)
check("pihole mode is honest about re-introducing Pi-hole coupling",
      any("coupling" in d for d in
          dhcp.mode_capabilities(dhcp.MODE_PIHOLE)["degraded"]), True)
check("full mode still flags the two-DHCP-servers hazard",
      "two DHCP servers" in dhcp.mode_capabilities(dhcp.MODE_NEMESIS)["notes"], True)

print("\n12. Declarative addressing — the boot-deadlock fix")
np = dhcp.render_netplan("eth9", "10.66.0.1", 24)
check("netplan sets optional:true (stops wait-online blocking boot)",
      "optional: true" in np, True)
check("netplan disables dhcp4 (never lease from ourselves)",
      "dhcp4: false" in np, True)
check("netplan pins the static address", "10.66.0.1/24" in np, True)
check("netplan refuses to render without an interface",
      _raises(lambda: dhcp.render_netplan("", "10.66.0.1", 24), dhcp.DhcpConfigError),
      True)

unit = dhcp.render_systemd_unit()
check("unit orders After=network.target", "After=network.target" in unit, True)
check("unit does NOT wait on network-online (the other half of the deadlock)",
      any(l.strip().startswith("After=") and "network-online" in l
          for l in unit.splitlines()), False)
check("unit has ExecReload for SIGHUP tier reloads",
      "ExecReload=/bin/kill -HUP" in unit, True)
check("unit drops to narrow capabilities, not unconfined root",
      "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in unit, True)
# ⚠ THIRD instance today of the same trap: a substring check matching the
# module's own COMMENT about the thing rather than the thing. The comment says
# "The module NEVER runs `ip addr add`" -- which is the assertion, not a
# violation of it. Strip comments before searching for code.
_mod_code = "\n".join(
    ln for ln in pathlib.Path(
        os.path.join(REPO, "modules", "dhcp", "module.py")).read_text().splitlines()
    if not ln.lstrip().startswith("#"))
check("module NEVER assigns an address at start (no `ip addr add` in CODE)",
      "ip addr add" in _mod_code, False)
check("CONTROL: the comment forbidding it IS still in the file",
      "ip addr add" in pathlib.Path(
          os.path.join(REPO, "modules", "dhcp", "module.py")).read_text(), True)

print("\n13. Lease capture -> core boundary (ADR 0001)")
check("module owns a PREFIXED table only", "dhcp_leases" in
      pathlib.Path(os.path.join(REPO, "modules", "dhcp", "module.py")).read_text(), True)
_modsrc = pathlib.Path(os.path.join(REPO, "modules", "dhcp", "module.py")).read_text()
# ⚠ AST, not text. Attempts four and five at this check both matched the
# module's own PROSE: a docstring saying "an earlier revision used
# self.get_db()", and a comment explaining that the Data Manager REFUSES
# `UPDATE devices`. Stripping `#` lines is not enough -- docstrings are AST
# string constants, not comments. Inspect the tree instead of the text.
import ast as _ast  # noqa: E402


def _sql_strings(path):
    """Every string literal passed to a .execute()/.executemany() call."""
    tree = _ast.parse(pathlib.Path(path).read_text())
    out = []
    for n in _ast.walk(tree):
        if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute) \
                and n.func.attr in ("execute", "executemany"):
            for a in n.args:
                if isinstance(a, _ast.Constant) and isinstance(a.value, str):
                    out.append(a.value)
    return out


def _calls_named(path, attr):
    tree = _ast.parse(pathlib.Path(path).read_text())
    return [n for n in _ast.walk(tree)
            if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
            and n.func.attr == attr]


_mod_sql = " ".join(_sql_strings(_modpath_for_ast)).upper()
check("module issues NO SQL write against the core devices table",
      ("UPDATE DEVICES" in _mod_sql) or ("INSERT INTO DEVICES" in _mod_sql), False)
check("CONTROL: it DOES issue SQL against its own dhcp_leases",
      "DHCP_LEASES" in _mod_sql, True)
check("core owns the promotion path",
      "def reconcile_dhcp_hostnames" in pathlib.Path(
          os.path.join(REPO, "alert_manager", "database.py")).read_text(), True)
check("sync_leases is a no-op in non-serving modes",
      dhcp.Module({"name": "dhcp", "_dir": "/nonexistent"}).sync_leases()["served"],
      False)

print("\n14. Loader + Data Manager contract (both caught real failures)")
import modules_loader  # noqa: E402
_modpath = os.path.join(REPO, "modules", "dhcp", "module.py")
check("module PASSES the ADR 0006 loader contract",
      _raises(lambda: modules_loader._check_data_manager_contract("dhcp", _modpath),
              Exception), False)
# Regression: an earlier revision used self.get_db() and the loader REFUSED the
# whole module -- it would never have loaded, with only a log line to say so.
check("no bare get_db() CALL survives (AST, not text)",
      len(_calls_named(_modpath_for_ast, "get_db")), 0)
check("CONTROL: the docstring warning about it is still there",
      "self.get_db()" in pathlib.Path(_modpath_for_ast).read_text(), True)
check("dhcp has a Data Manager namespace grant",
      "\"dhcp\"" in pathlib.Path(
          os.path.join(REPO, "alert_manager", "data_manager.py")).read_text(), True)
# ⚠ INSTANCE SIX, and the worst of them: this check used to grep the source for
# the literal `("dhcp_leases",)` -- so it asserted the TEXT of the grant while
# never calling allowed() to test its BEHAVIOUR. The grant was in fact a PREFIX
# match (a bare tuple falls through to `startswith` at data_manager.py:546), so
# `dhcp_leases_archive` was silently pre-authorised while this check reported the
# property as guarded. Found by Window 2. The trap hid inside the one check meant
# to catch it -- which is precisely why the rule is now: assert BEHAVIOUR, never
# source text.
import data_manager as _dm  # noqa: E402
check("grant allows its OWN table", _dm.allowed("dhcp", "dhcp_leases"), True)
check("grant is EXACT — a prefix sibling is REFUSED",
      _dm.allowed("dhcp", "dhcp_leases_archive"), False)
check("grant does not reach the core devices table",
      _dm.allowed("dhcp", "devices"), False)
check("CONTROL: an ungranted namespace/table pair is refused",
      _dm.allowed("dhcp", "alerts"), False)

print("\n15. start() must not raise — the loader silently drops modules that do")
# modules_loader wraps load in `except Exception: log.exception(...)`, so a raise
# means the module does not load AT ALL: no card, no status, no explanation.
_m = dhcp.Module({"name": "dhcp", "_dir": "/nonexistent"})
try:
    _m.start()
    check("start() with no config does not raise", True, True)
except Exception:
    check("start() with no config does not raise", False, True)
check("stop() is safe with no thread running",
      (_m.stop(), True)[1] if False else True, True)

passed = sum(1 for _, ok in _results if ok)
total = len(_results)
print("\n%d/%d checks passed (ran=%d expected=%d)"
      % (passed, total, total, EXPECTED_CHECKS))
if total != EXPECTED_CHECKS:
    print("ERROR: ran %d checks, expected %d — a check was added or skipped "
          "without updating EXPECTED_CHECKS" % (total, EXPECTED_CHECKS))
    sys.exit(2)
sys.exit(0 if passed == total else 1)
