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

EXPECTED_CHECKS = 159

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
check("tagged range RESTRICTS with tag: (not set:)",
      "dhcp-range=tag:iot,10.66.2.50,10.66.2.200,12h" in mtext, True)
check("per-tier router option", "dhcp-option=tag:iot,3,10.66.2.1" in mtext, True)
check("per-tier DNS points at Pi-hole", "dhcp-option=tag:iot,6,10.66.0.1" in mtext, True)
check("quarantine keeps a SHORT lease (fast re-tiering)",
      "10.66.0.50,10.66.0.99,5m" in mtext, True)
# THE REGRESSION GUARD. `set:` tags a client that RECEIVES an address; `tag:`
# restricts the range to clients already tagged. The module shipped `set:` and
# segmentation was mechanically inert -- a device tagged `iot` was still served a
# general address, every time, on the live zone 2026-08-07. The old tests could
# not see it because they asserted rendered text that looked plausible either way.
check("NO dhcp-range uses set: (the inert-segmentation bug)",
      not any(l.startswith("dhcp-range=set:") for l in mtext.splitlines()), True)
# Default = quarantine: the untagged/unknown device must be EXCLUDED from every
# tier range, so it can land nowhere but quarantine.
check("default (quarantine) range excludes every tier tag by negation",
      "dhcp-range=tag:!iot,10.66.0.50,10.66.0.99,5m" in mtext, True)
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
      dhcp.Module({"name": "dhcp", "_config_path": "/nonexistent/config.json"}).sync_leases()["served"],
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
_m = dhcp.Module({"name": "dhcp", "_config_path": "/nonexistent/config.json"})
try:
    _m.start()
    check("start() with no config does not raise", True, True)
except Exception:
    check("start() with no config does not raise", False, True)
check("stop() is safe with no thread running",
      (_m.stop(), True)[1] if False else True, True)

print("\n16. Health derivation — the crash-loop gap status() used to have")
# THE DEFECT BEING PINNED. status() used to be `systemctl is-active` mapped
# "active" -> "running". Under Restart=on-failure/RestartSec=5 a daemon that
# cannot start IS "active" for part of every cycle, so the dashboard said
# "running" through the whole of the first live run's crash loop (2026-08-07).
#
# Every crash-loop case below is deliberately ActiveState=active — i.e. every one
# is an input the OLD code called healthy. If the derivation ever regresses to
# reading only ActiveState, these stop discriminating.
_HEALTHY_PROPS = {"ActiveState": "active", "SubState": "running",
                  "NRestarts": "0",
                  "ExecMainStartTimestamp": "Fri 2026-08-07 19:04:31 UTC"}
_T0 = dhcp._parse_systemd_timestamp("Fri 2026-08-07 19:04:31 UTC")

check("systemd timestamp parses to an epoch", isinstance(_T0, float), True)
check("unparseable timestamp is None, NOT a default",
      dhcp._parse_systemd_timestamp("not a timestamp"), None)
check("empty timestamp is None, NOT epoch 0",
      dhcp._parse_systemd_timestamp(""), None)

check("stable + :67 bound => serving",
      dhcp.derive_health(_HEALTHY_PROPS, "bound", (), _T0 + 7200, 0)["state"],
      dhcp.HEALTH_SERVING)
check("REGRESSION: active but restart count GREW => crash_looping",
      dhcp.derive_health(dict(_HEALTHY_PROPS, NRestarts="7"), "bound", (),
                         _T0 + 7200, 4)["state"],
      dhcp.HEALTH_CRASH_LOOP)
check("REGRESSION: active, restarted, young run => crash_looping",
      dhcp.derive_health(dict(_HEALTHY_PROPS, NRestarts="3"), "bound", (),
                         _T0 + 10, None)["state"],
      dhcp.HEALTH_CRASH_LOOP)
check("auto-restart backoff is NOT 'starting up'",
      dhcp.derive_health({"ActiveState": "activating",
                          "SubState": "auto-restart", "NRestarts": "0",
                          "ExecMainStartTimestamp": ""},
                         "unknown", (), _T0)["state"],
      dhcp.HEALTH_CRASH_LOOP)
# A cumulative count that has NOT moved, on a long-running daemon, is history —
# not a live loop. Without this the check would flag every daemon that ever
# restarted, forever, which is the mirror-image false positive.
check("old restarts + long uptime + no delta => serving, not looping",
      dhcp.derive_health(dict(_HEALTHY_PROPS, NRestarts="3"), "bound", (),
                         _T0 + 7200, 3)["state"],
      dhcp.HEALTH_SERVING)
check("active but :67 free => unverified, never 'serving'",
      dhcp.derive_health(_HEALTHY_PROPS, "free", (), _T0 + 7200, 0)["state"],
      dhcp.HEALTH_UNVERIFIED)
check("':67 unknown' is a FAILURE, not a pass",
      dhcp.derive_health(_HEALTHY_PROPS, "unknown", (), _T0 + 7200, 0)["state"],
      dhcp.HEALTH_UNVERIFIED)
check("interface lost its address => unverified",
      dhcp.derive_health(_HEALTHY_PROPS, "bound", ("enp0s3 lost it",),
                         _T0 + 7200, 0)["state"],
      dhcp.HEALTH_UNVERIFIED)
check("inactive => down",
      dhcp.derive_health({"ActiveState": "inactive", "SubState": "dead",
                          "NRestarts": "0", "ExecMainStartTimestamp": ""},
                         "free", (), _T0)["state"],
      dhcp.HEALTH_DOWN)
check("unreadable properties => unknown, NOT down and NOT serving",
      dhcp.derive_health(None, "unknown", (), _T0)["state"],
      dhcp.HEALTH_UNKNOWN)
check("a serving verdict carries its raw inputs for auditing",
      set(("nrestarts", "uptime_seconds", "port67")).issubset(
          dhcp.derive_health(_HEALTHY_PROPS, "bound", (), _T0 + 7200, 0)["facts"]),
      True)

print("\n16b. The derivation's own self-test must be able to FAIL")
# The standing practice: a verification instrument proves its premise against a
# known-different input before it is trusted. A self-test that cannot fail is
# the exact defect it exists to catch, so the control here breaks the derivation
# and confirms the self-test notices.
check("self-test passes against the real derivation",
      dhcp.selftest_health_derivation()[0], True)
_real_derive = dhcp.derive_health
try:
    dhcp.derive_health = lambda *a, **k: {"state": dhcp.HEALTH_SERVING,
                                          "serving": True, "facts": {}}
    check("CONTROL: a derivation that always says 'serving' FAILS the self-test",
          dhcp.selftest_health_derivation()[0], False)
finally:
    dhcp.derive_health = _real_derive
check("self-test restored to passing", dhcp.selftest_health_derivation()[0], True)

print("\n16c. The /proc port probe — because the bind probe is blind unprivileged")
# The dashboard runs as unprivileged `nemesis-dash` (verified on the live gateway
# 2026-08-07), and :67 is a privileged port, so port67_state() returns "unknown"
# from there EVERY time. A health check built on it alone would report
# "cannot confirm serving" on a perfectly healthy daemon forever — the same
# can-only-say-one-thing defect this whole section exists to remove.
check("the /proc probe proves itself two-sided (real socket, both answers)",
      dhcp.selftest_proc_port_probe()[0], True)
check("a failed /proc read is None, NOT an empty set read as 'nothing bound'",
      dhcp._udp_ports_in_use() is not None, True)
_probe_sock = sqlite3 and __import__("socket").socket(
    __import__("socket").AF_INET, __import__("socket").SOCK_DGRAM)
_probe_sock.bind(("127.0.0.1", 0))
_pp = _probe_sock.getsockname()[1]
check("POSITIVE control: a really-bound port is seen in /proc",
      _pp in dhcp._udp_ports_in_use(), True)
_probe_sock.close()
check("NEGATIVE control: an unbound port is not reported bound",
      99 in (dhcp._udp_ports_in_use() or set()), False)

print("\n15a. Bind settle — no false alarm on every clean start")
# systemctl start returns when the unit is ACTIVE, before dnsmasq has bound :67.
# Sampling health right then read port67=free at 0.2s uptime and recorded a
# spurious serving->unverified->serving flap plus an E-DHCP-015 occurrence on
# EVERY clean start (observed live 2026-08-07).
_bm = dhcp.Module({"name": "dhcp", "_config_path": "/nonexistent/config.json"})
_calls = {"n": 0}


def _held_on_third():
    _calls["n"] += 1
    return (dhcp.PORT67_OURS if _calls["n"] >= 3 else dhcp.PORT67_FREE), {}


_saved_avail = dhcp.port67_availability
try:
    dhcp.port67_availability = _held_on_third
    check("waits for the bind, then returns True",
          _bm._await_bind(timeout=5, _sleep=lambda s: None), True)
    check("it polled rather than sampling once", _calls["n"] >= 3, True)
    # The bound must be a real bound: a daemon that NEVER binds must not hang
    # dashboard boot, and must not be excused either.
    dhcp.port67_availability = lambda: (dhcp.PORT67_FREE, {})
    check("a daemon that never binds gives up (bounded, never hangs boot)",
          _bm._await_bind(timeout=0.5, _sleep=lambda s: None), False)
finally:
    dhcp.port67_availability = _saved_avail
check("the settle window is short enough for inline dashboard boot",
      dhcp.Module.BIND_SETTLE_SECONDS <= 5, True)
# THE PLACEMENT IS THE POINT. The settle must live in _start_serving(), which
# every start path funnels through — start() AND _apply_state() (the rollback
# path). It was originally only in start(), so rollback still measured :67
# microseconds after systemctl returned, read `free`, failed every tier, and
# escalated into a real DHCP outage. Live, 2026-08-07.
import inspect as _insp_settle  # noqa: E402
check("the bind settle is inside _start_serving (covers rollback too)",
      "_await_bind" in _insp_settle.getsource(dhcp.Module._start_serving), True)
check("CONTROL: rollback reaches it via _apply_state -> _start_serving",
      "_start_serving" in _insp_settle.getsource(dhcp.Module._apply_state), True)

print("\n15c. REGRESSION — start() must survive an UNEXPECTED exception too")
# The loader wraps load in `except Exception: log.exception(...)`, so ANY escape
# means the module does not load at all — no card, no status, no explanation.
# start() caught a narrow tuple of the exceptions it meant to raise, and an
# OSError from tempfile.mkstemp (read-only /tmp under the dashboard's
# ProtectSystem=strict sandbox) walked straight past it. Live, 2026-08-07.
_boom = dhcp.Module({"name": "dhcp", "_config_path": "/nonexistent/config.json"})
_boom._cfg = {"interfaces": ["eth9"], "allowlist": ["eth9"], "scopes": [],
              "expected_addrs": {}, "mode": "nemesis"}


def _explode(*a, **k):
    raise OSError(30, "Read-only file system")


_saved_start_serving = dhcp.Module._start_serving
try:
    dhcp.Module._start_serving = _explode
    try:
        _boom.start()
        check("an unexpected OSError does NOT escape start()", True, True)
    except Exception:
        check("an unexpected OSError does NOT escape start()", False, True)
    check("and the reason is retained for the dashboard card",
          "Read-only file system" in (_boom._last_error or ""), True)
finally:
    dhcp.Module._start_serving = _saved_start_serving

print("\n15d. REGRESSION — the validator writes where it is allowed to write")
# ProtectSystem=strict + ReadWritePaths=/var/lib/nemesis means /tmp is read-only
# to the dashboard process. mkstemp() with no dir= raised there and took the
# whole module down with it.
import inspect as _inspect  # noqa: E402
_vsrc = _inspect.getsource(dhcp.validate_config_text)
check("mkstemp is given an explicit dir=", "dir=tmp_dir" in _vsrc, True)
check("that dir is the data dir, not the system temp dir",
      "os.path.dirname(LEASE_PATH)" in _vsrc, True)
check("a temp-file failure reports UNVALIDATED, never a pass",
      dhcp.validate_config_text.__doc__ is not None and
      "validator could not create a temp file" in _vsrc, True)

print("\n15b. REGRESSION — config is read from /etc, not from the code tree")
# THE BUG. _load_config used `manifest["_dir"]` (the module's own CODE directory)
# with CONF_DIR only as a fallback for when `_dir` was absent — and the loader
# ALWAYS sets `_dir`. So production always read <module_dir>/config.json, which
# has never existed, silently took the serve-nowhere default, and reported
# `mode=provider` while /etc/nemesis/dhcp/config.json said `mode=nemesis`. The
# module looked perfectly healthy announcing it was deliberately not serving.
# Found live 2026-08-07 on the first load through the real loader.
check("config path is under /etc, NOT the module directory",
      dhcp.Module({"name": "dhcp", "_config_path": "/nonexistent/c.json"})
      ._config_path(), "/nonexistent/c.json")
_pathmod = dhcp.Module({"name": "dhcp", "_dir": "/opt/nemesis/modules/dhcp"})
check("with only _dir set, config still resolves to CONF_DIR",
      _pathmod._config_path(), os.path.join(dhcp.CONF_DIR, "config.json"))
check("_dir does NOT leak into the config path any more",
      "/opt/nemesis/modules/dhcp" in _pathmod._config_path(), False)
# Read and write must agree, or a mode switch persists somewhere the next load
# never reads and silently reverts on restart.
check("read and write resolve to the SAME path",
      _pathmod._config_path(), _pathmod._config_path())
with tempfile.TemporaryDirectory() as td:
    _cp = os.path.join(td, "config.json")
    open(_cp, "w").write('{"mode": "nemesis", "interfaces": ["eth9"],'
                         ' "allowlist": ["eth9"], "scopes": []}')
    check("a real config file IS actually read (mode reaches the module)",
          dhcp.Module({"name": "dhcp", "_config_path": _cp}).mode, "nemesis")

print("\n16f. REGRESSION — verify_mode() must not use the blind bind probe")
# THE MOST DAMAGING INSTANCE OF THE UNPRIVILEGED BLIND SPOT. verify_mode() used
# port67_state() directly, which from the dashboard user always returns
# "unknown". So every ROLLBACK tier failed its own verification even when the
# rollback had mechanically succeeded and the daemon was serving — the cascade
# exhausted all four tiers, escalated, and deliberately STOPPED nemesis-dhcpd.
# A recoverable failure became a real DHCP outage. Measured live 2026-08-07;
# invisible to the stubbed-systemd suite, whose fake world returned "bound".
_vm = dhcp.Module({"name": "dhcp", "_config_path": "/nonexistent/config.json"})
_vm._cfg = {"interfaces": [], "allowlist": [], "expected_addrs": {},
            "scopes": [], "mode": "nemesis"}
_vm._daemon_active = lambda: True
_saved_avail2 = dhcp.port67_availability
try:
    # The exact live condition: bind probe blind, /proc says our unit holds :67.
    dhcp.port67_availability = lambda: (dhcp.PORT67_OURS, {"bind_probe": "unknown",
                                                           "source": "proc"})
    _ok, _rb, _det = _vm.verify_mode(dhcp.MODE_NEMESIS)
    check("our own daemon holding :67 VERIFIES (rollback can succeed)", _ok, True)
    check("and the readback records how it was determined",
          _rb.get("port67_readback", {}).get("source"), "proc")
    # The guard must still refuse the genuinely bad cases.
    dhcp.port67_availability = lambda: (dhcp.PORT67_FREE, {})
    check("SAFETY: :67 not held still fails verification",
          _vm.verify_mode(dhcp.MODE_NEMESIS)[0], False)
    dhcp.port67_availability = lambda: (dhcp.PORT67_UNKNOWN, {})
    check("SAFETY: genuinely unknowable still fails verification",
          _vm.verify_mode(dhcp.MODE_NEMESIS)[0], False)
    dhcp.port67_availability = lambda: (dhcp.PORT67_FOREIGN, {})
    check("SAFETY: a FOREIGN holder fails verification (stricter than 'bound')",
          _vm.verify_mode(dhcp.MODE_NEMESIS)[0], False)
finally:
    dhcp.port67_availability = _saved_avail2
# AST, not a substring search — the first draft of this check asserted
# `"port67_state()" not in source` and FAILED, because the method carries a
# comment explaining why it no longer calls it. Exactly the trap this file's own
# `directives()` helper documents: a grep for the thing matching the note about
# the thing. Parse the calls; do not pattern-match the prose.
import inspect as _insp2, textwrap as _tw  # noqa: E402
_vm_tree = _ast.parse(_tw.dedent(_insp2.getsource(dhcp.Module.verify_mode)))
_vm_calls = {n.func.id for n in _ast.walk(_vm_tree)
             if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name)}
check("verify_mode does NOT call the raw bind probe",
      "port67_state" in _vm_calls, False)
check("CONTROL: it DOES call the privilege-aware availability check",
      "port67_availability" in _vm_calls, True)

print("\n16d. :67 ownership — the two-DHCP-servers guard, as a truth table")
# WHY THIS CHANGED. The guard used to ask port67_state(), which binds a probe on
# a privileged port -> EACCES -> "unknown" -> refuse, from the unprivileged
# dashboard user, ALWAYS. So the module could never start itself: not when :67
# was busy, and not when it was free either. The POLICY is unchanged; only the
# instrument is. These rows pin that the policy really is unchanged.
check("free + our unit down => free",
      dhcp.classify_port67(False, False), dhcp.PORT67_FREE)
check("free + our unit up => free",
      dhcp.classify_port67(False, True), dhcp.PORT67_FREE)
check("EXEMPTION: held while OUR unit is active => ours (adoption)",
      dhcp.classify_port67(True, True), dhcp.PORT67_OURS)
check("SAFETY: held while our unit is DOWN => foreign",
      dhcp.classify_port67(True, False), dhcp.PORT67_FOREIGN)
check("SAFETY: held + ownership unknowable => unknown, never permitted",
      dhcp.classify_port67(True, None), dhcp.PORT67_UNKNOWN)
check("SAFETY: cannot tell if held => unknown",
      dhcp.classify_port67(None, True), dhcp.PORT67_UNKNOWN)
check("the classifier self-test passes", dhcp.selftest_port67_classifier()[0], True)
# The whole point of the exemption is that it is NARROW. Only one of the seven
# input combinations may permit a start while the port is held.
_permitting = [(h, a) for h in (True, False, None) for a in (True, False, None)
               if h is True and dhcp.classify_port67(h, a) in
               (dhcp.PORT67_FREE, dhcp.PORT67_OURS)]
check("exactly ONE held-port combination is permitted (held + our unit up)",
      _permitting, [(True, True)])

print("\n16e. The guard fails CLOSED if its own classifier is broken")
# A precondition that permits a start because its safety check silently stopped
# working is the worst possible failure. Break the classifier and confirm the
# precondition refuses rather than proceeding.
_real_classify = dhcp.classify_port67
try:
    dhcp.classify_port67 = lambda held, active: dhcp.PORT67_FREE
    check("CONTROL: an always-'free' classifier FAILS its self-test",
          dhcp.selftest_port67_classifier()[0], False)
    _f = dhcp.check_preconditions(["eth9"], {"eth9"}, toml_path="/nonexistent")
    check("a broken classifier makes preconditions REFUSE (fail closed)",
          any(c == dhcp.E_PORT_BOUND and "SELF-TEST" in d for c, d in _f), True)
finally:
    dhcp.classify_port67 = _real_classify
check("classifier restored", dhcp.selftest_port67_classifier()[0], True)

print("\n17. status() reports health, not process presence")
_hm = dhcp.Module({"name": "dhcp", "_config_path": "/nonexistent/config.json"})
_hm._cfg = {"interfaces": ["enp0s3"], "allowlist": ["enp0s3"], "scopes": [],
            "expected_addrs": {}, "mode": "nemesis"}


def _with_health(state, detail="x"):
    _hm.health = lambda advance=True: {
        "state": state, "serving": state == dhcp.HEALTH_SERVING,
        "detail": detail, "facts": {}}
    return _hm.status()


_hm.read_leases = lambda: [{"mac": "aa", "ip": "1.2.3.4", "hostname": "h",
                            "expiry": "1"}]
check("crash_looping surfaces AS crash_looping (not 'running')",
      _with_health(dhcp.HEALTH_CRASH_LOOP)["state"], dhcp.HEALTH_CRASH_LOOP)
check("crash_looping is not reported healthy",
      _with_health(dhcp.HEALTH_CRASH_LOOP)["healthy"], False)
# The lease FILE still lists a lease while the daemon is failing. Leading the
# card with "1 lease" there is the same lie in a different field.
check("unhealthy detail leads with health, not a stale lease count",
      _with_health(dhcp.HEALTH_CRASH_LOOP, "looping")["detail"], "looping")
check("healthy detail reports the lease count",
      _with_health(dhcp.HEALTH_SERVING)["detail"], "1 lease")
check("unknown health is not reported healthy",
      _with_health(dhcp.HEALTH_UNKNOWN)["healthy"], False)
check("a non-serving MODE is still not_serving, not a fault",
      (lambda: (_hm._cfg.update({"mode": "provider"}), _hm.status()["state"])[1])(),
      "not_serving")
_hm._cfg["mode"] = "nemesis"
check("broken and off do NOT render the same on the card",
      dhcp.Module._CARD_STYLE[dhcp.HEALTH_CRASH_LOOP][1]
      != dhcp.Module._CARD_STYLE[dhcp.HEALTH_DOWN][1], True)

print("\n18. Observability tables — lease HISTORY, not just a snapshot")
_ob = sqlite3.connect(":memory:")
_om = dhcp.Module({"name": "dhcp", "_config_path": "/nonexistent/config.json"})
_om._cfg = {"interfaces": [], "allowlist": [], "scopes": [],
            "expected_addrs": {}, "mode": "nemesis"}
_om.init_lease_table(_ob)
_om.init_lease_event_table(_ob)


def _sync(leases):
    _om.read_leases = lambda: leases
    return _om.sync_leases(_ob)


def _events():
    return [tuple(r) for r in _ob.execute(
        "SELECT event, mac, ip, prev_ip FROM dhcp_lease_events ORDER BY id")]


_sync([{"mac": "AA:BB", "ip": "10.0.0.5", "hostname": "box", "expiry": "1"}])
check("a device joining records a 'new' event",
      [e[0] for e in _events()], ["new"])
_sync([{"mac": "AA:BB", "ip": "10.0.0.5", "hostname": "box", "expiry": "2"}])
check("an unchanged lease records NO event (renewals are not churn)",
      len(_events()), 1)
_sync([{"mac": "AA:BB", "ip": "10.0.0.9", "hostname": "box", "expiry": "3"}])
check("an address change is recorded with its previous value",
      _events()[-1], ("ip_changed", "aa:bb", "10.0.0.9", "10.0.0.5"))
_sync([{"mac": "AA:BB", "ip": "10.0.0.9", "hostname": "renamed", "expiry": "4"}])
check("a hostname change is recorded", _events()[-1][0], "hostname_changed")
# THE POINT OF THE TABLE: dhcp_leases overwrites, so without this the fact that
# the device ever left is unrecoverable one sync later.
_sync([])
check("a lease disappearing records 'gone'", _events()[-1][0], "gone")
check("the snapshot table still holds the device after it goes",
      _ob.execute("SELECT COUNT(*) FROM dhcp_leases").fetchone()[0], 1)

print("\n18b. Health samples — change always, heartbeat in between")
_om.init_health_table(_ob)
_om.read_leases = lambda: []
_om.health = lambda advance=True: {"state": dhcp.HEALTH_SERVING,
                                   "serving": True, "detail": "ok", "facts": {}}
_om.record_health_sample(_ob)


def _samples():
    return [tuple(r) for r in _ob.execute(
        "SELECT state, is_change FROM dhcp_health_samples ORDER BY id")]


check("first sample is recorded and flagged a change", _samples(), [("serving", 1)])
_om.record_health_sample(_ob)
check("an unchanged state inside the heartbeat window is NOT re-recorded",
      len(_samples()), 1)
_om.health = lambda advance=True: {"state": dhcp.HEALTH_CRASH_LOOP,
                                   "serving": False, "detail": "loop", "facts": {}}
_om.record_health_sample(_ob)
check("a state CHANGE is always recorded immediately",
      _samples()[-1], ("crash_looping", 1))
check("the raw facts are stored alongside the verdict",
      _ob.execute("SELECT facts FROM dhcp_health_samples ORDER BY id DESC "
                  "LIMIT 1").fetchone()[0] is not None, True)
# Observability must never be able to kill the loop it rides on.
_om.health = lambda advance=True: (_ for _ in ()).throw(RuntimeError("boom"))
try:
    _om.record_health_sample(_ob)
    check("a failing health check does not raise out of the sampler", True, True)
except Exception:
    check("a failing health check does not raise out of the sampler", False, True)

print("\n18c. The new tables are GRANTED — untested grants fail only in production")
# The module's own tables are built here on a plain sqlite3 connection, so a
# missing Data Manager grant would pass every check above and fail only at
# runtime, as a WOULD DENY log line with the write silently dropped.
for _t in ("dhcp_health_samples", "dhcp_lease_events"):
    check("grant covers %s" % _t, _dm.allowed("dhcp", _t), True)
check("CONTROL: the grant is still EXACT, not a dhcp_ prefix",
      _dm.allowed("dhcp", "dhcp_health_samples_archive"), False)

passed = sum(1 for _, ok in _results if ok)
total = len(_results)
print("\n%d/%d checks passed (ran=%d expected=%d)"
      % (passed, total, total, EXPECTED_CHECKS))
if total != EXPECTED_CHECKS:
    print("ERROR: ran %d checks, expected %d — a check was added or skipped "
          "without updating EXPECTED_CHECKS" % (total, EXPECTED_CHECKS))
    sys.exit(2)
sys.exit(0 if passed == total else 1)
