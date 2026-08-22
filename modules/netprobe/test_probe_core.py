#!/usr/bin/env python3
"""Active network probes — and proof the target constraint actually constrains.

Run: python3 modules/netprobe/test_probe_core.py   (exit 0 = all pass)

THE SECURITY PROPERTY IS THE WHOLE POINT OF THIS FILE. Ping and traceroute are
ACTIVE — they emit packets at a chosen target. The diagnostics master plan gates
anything that tasks a remote machine behind an authorization + consent layer, and
that layer DOES NOT EXIST (verified 2026-08-22: `require_role`/`ROLE_*`/`is_admin`
return nothing repo-wide; the dashboard gate is binary). So rather than gating the
caller, these constrain the TARGET SPACE: a probe may only be aimed at a host
already in the LAN inventory or already enrolled as an approved agent.

That constraint is the entire safety argument, so it is tested first, hardest, and
from both directions — a check that only proved "known hosts are allowed" would
pass just as well for a tool that allowed everything.

FAIL CLOSED IS TESTED EXPLICITLY. An unreadable inventory must REFUSE. Resolving
it to "allow" would turn a transient DB error into an open probe tool pointed at
anything — the silent-default shape this codebase keeps finding, with the worst
possible blast radius.

PORT SCAN AND PACKET CAPTURE ARE NOT HERE, deliberately, and a test asserts the
module exposes no entry point for them. Target-space constraint is not a
sufficient control for either: a port scan against a known host is still a port
scan.

NO PACKETS ARE SENT. The inventory is a stub and every command runs through an
injected runner.
"""
import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))

_SRC = os.path.join(_HERE, "probe_core.py")
_spec = importlib.util.spec_from_file_location("probe_under_test", _SRC)
pc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pc)

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


INV = pc._FakeConn(lan=[("192.0.2.10", "printer", "Office Printer")],
                   agents=[("192.0.2.50", "laptop-1")])


def refused(target, conn=None):
    try:
        pc.authorise(target, conn or INV)
        return None
    except (pc.ProbeRefused, pc.InventoryUnavailable) as e:
        return str(e)


print("\n-- SECURITY: arbitrary targets are REFUSED --")
for hostile in ("8.8.8.8", "1.1.1.1", "example.com", "evil.example",
                "192.0.2.99", "10.0.0.1", "-h", "--flag", "", None,
                "192.0.2.10.evil.com", "printer.evil.com"):
    check("%r refused" % (hostile,), refused(hostile) is not None)

print("\n-- CONTROL: known hosts ARE permitted (or the above proves nothing) --")
for allowed in ("192.0.2.10", "printer", "PRINTER", "office printer",
                "192.0.2.50", "laptop-1"):
    check("%r permitted" % allowed, refused(allowed) is None, refused(allowed))
check("a pasted URL form of a known host still resolves",
      refused("http://192.0.2.10/status") is None)
check("authorisation reports the SOURCE (lan vs agent)",
      pc.authorise("192.0.2.50", INV)[1] == pc.SOURCE_AGENT)
check("...and distinguishes it from a LAN device",
      pc.authorise("192.0.2.10", INV)[1] == pc.SOURCE_LAN)
check("it returns a human label, not just an IP",
      pc.authorise("192.0.2.10", INV)[2] == "Office Printer")

print("\n-- FAIL CLOSED: an unreadable inventory refuses everything --")
broken = pc._FakeConn(raise_on_lan=True)
check("a known host is refused when the inventory cannot be read",
      refused("192.0.2.10", broken) is not None)
check("...and the reason says UNREADABLE, not 'unknown host'",
      "unreadable" in (refused("192.0.2.10", broken) or ""),
      refused("192.0.2.10", broken))
check("InventoryUnavailable is a DISTINCT exception from ProbeRefused",
      pc.InventoryUnavailable is not pc.ProbeRefused)
try:
    pc.load_inventory(broken)
    check("load_inventory raises on a broken read", False, "it returned")
except pc.InventoryUnavailable:
    check("load_inventory raises InventoryUnavailable", True)

print("\n-- an EMPTY inventory permits nothing (empty != allow-all) --")
empty = pc._FakeConn()
check("empty inventory refuses a plausible LAN IP",
      refused("192.0.2.10", empty) is not None)
check("empty inventory refuses everything tried",
      all(refused(t, empty) is not None
          for t in ("192.0.2.10", "printer", "8.8.8.8")))

print("\n-- the refusal explains policy, so it is actionable --")
msg = refused("8.8.8.8") or ""
check("it names the LAN inventory", "LAN inventory" in msg, msg)
check("it names enrolled agents", "enrolled agents" in msg, msg)
check("it says arbitrary targets are deliberate policy",
      "deliberately not permitted" in msg, msg)

print("\n-- commands are BOUNDED and shell-free --")
argv = pc.ping_argv("192.0.2.10")
check("ping argv is a list", isinstance(argv, list))
check("ping is count-bounded", "-c" in argv and str(pc.PING_COUNT) in argv)
check("ping is deadline-bounded", "-w" in argv)
check("ping ends option parsing with --",
      argv.index("--") < argv.index("192.0.2.10"), argv)
targv = pc.trace_argv("192.0.2.10")
check("trace is hop-bounded", "-m" in targv and str(pc.TRACE_MAX_HOPS) in targv)
check("trace ends option parsing with --", "--" in targv)
check("the bounds are module constants, not caller-supplied",
      pc.PING_COUNT <= 10 and pc.TRACE_MAX_HOPS <= 32,
      (pc.PING_COUNT, pc.TRACE_MAX_HOPS))

print("\n-- ping parsing never fabricates a verdict --")
OK = ("4 packets transmitted, 4 received, 0% packet loss, time 3005ms\n"
      "rtt min/avg/max/mdev = 0.312/0.451/0.602/0.101 ms")
DEAD = "4 packets transmitted, 0 received, 100% packet loss, time 3070ms"
LOSSY = "4 packets transmitted, 2 received, 50% packet loss, time 3070ms"
check("healthy parses", pc.parse_ping(OK)["loss_pct"] == 0.0)
check("dead parses as 100% loss", pc.parse_ping(DEAD)["loss_pct"] == 100.0)
check("partial loss parses", pc.parse_ping(LOSSY)["loss_pct"] == 50.0)
check("rtt extracted", pc.parse_ping(OK)["rtt_avg_ms"] == 0.451)
for junk in ("total nonsense", "", None, "ping: unknown host"):
    check("%r yields None, NOT zero-received" % (junk,), pc.parse_ping(junk) is None)

print("\n-- RTT rendering does not flatten sub-millisecond to zero --")
check("0.29ms reads as 'under 1 ms'", pc._fmt_ms(0.29) == "under 1 ms")
check("3.4ms keeps precision", pc._fmt_ms(3.4) == "3.4 ms")
check("42.7ms rounds", pc._fmt_ms(42.7) == "43 ms")
check("None is not rendered as a number", pc._fmt_ms(None) == "unknown")

print("\n-- tiering: three readers, and a failure is not a verdict --")
ex = pc.tier_ping("Printer", "192.0.2.10", pc.parse_ping(OK), OK)
check("all three tiers", set(ex) == set(pc.TIERS))
check("the three differ", len(set(ex.values())) == 3)
check("pro carries raw output", "packets transmitted" in ex["pro"])
check("beginner avoids raw output", "packets transmitted" not in ex["beginner"])
dead = pc.tier_ping("Printer", "192.0.2.10", pc.parse_ping(DEAD), DEAD)
check("a dead host gets a next step", "Next:" in dead["beginner"])
check("...and is not stated as definitely off",
      "may be switched off" in dead["beginner"])
lossy = pc.tier_ping("Printer", "192.0.2.10", pc.parse_ping(LOSSY), LOSSY)
check("partial loss is explained, not just numbered",
      "Intermittent" in lossy["beginner"])
fail = pc.tier_ping("Printer", "192.0.2.10", None, "", error="boom")
check("a FAILED probe is not reported as the device being off",
      "not the same as the device being off" in fail["beginner"])
check("CONTROL: a healthy host gets no next step", "Next:" not in ex["beginner"])

print("\n-- no probe reaches a subprocess without authorisation --")
calls = []
def spy(argv, timeout):
    calls.append(argv)
    return 0, OK
try:
    pc.run_ping("8.8.8.8", INV, runner=spy)
    check("run_ping refuses an unknown target", False, "it ran")
except pc.ProbeRefused:
    check("run_ping raises before running anything", True)
check("...and the runner was NEVER called", calls == [], calls)
try:
    pc.run_trace("8.8.8.8", INV, runner=spy)
    check("run_trace refuses an unknown target", False, "it ran")
except pc.ProbeRefused:
    check("run_trace raises before running anything", True)
check("...and still nothing ran", calls == [], calls)
r = pc.run_ping("192.0.2.10", INV, runner=spy)
check("CONTROL: an authorised target DOES run", len(calls) == 1, calls)
check("...and returns a result", r["stats"]["loss_pct"] == 0.0)

print("\n-- missing binaries are reported as error codes, distinctly --")
r = pc.run_ping("192.0.2.10", INV, runner=lambda a, t: (127, "<command not found>"))
check("absent ping -> E-NETPROBE-001",
      any(c == "E-NETPROBE-001" for c, _ in r["problems"]), r["problems"])
r = pc.run_ping("192.0.2.10", INV, runner=lambda a, t: (124, "<timed out>"))
check("ping timeout -> E-NETPROBE-002",
      any(c == "E-NETPROBE-002" for c, _ in r["problems"]), r["problems"])
r = pc.run_trace("192.0.2.10", INV, runner=lambda a, t: (127, "<command not found>"))
check("neither trace tool -> E-NETPROBE-003",
      any(c == "E-NETPROBE-003" for c, _ in r["problems"]), r["problems"])
check("CONTROL: a healthy ping reports no problems",
      pc.run_ping("192.0.2.10", INV, runner=lambda a, t: (0, OK))["problems"] == [])

print("\n-- HELD capabilities are absent, and stay absent --")
for banned in ("port_scan", "portscan", "scan_ports", "capture", "pcap",
               "tcpdump", "packet_capture"):
    check("no %s entry point exists" % banned, not hasattr(pc, banned))
src = open(_SRC, encoding="utf-8").read()
check("no nmap/tcpdump/tshark invocation anywhere in the module",
      not any(t in src for t in ('"nmap"', '"tcpdump"', '"tshark"')))

print("\n-- every code the core EMITS is declared, and means ONE thing --")
# This check exists because the first wiring pass used E-NETPROBE-004 for BOTH
# "path trace timed out" (in probe_core) and "unreadable inventory" (in
# module.py). Both files read correctly alone; only the pair was wrong, so no
# single-file check could have caught it.
_mod_src = open(os.path.join(_HERE, "module.py"), encoding="utf-8").read()
import re as _re
declared = set(_re.findall(r'"(E-NETPROBE-\d+)":', _mod_src))
emitted = set(_re.findall(r'\("(E-NETPROBE-\d+)"', src))
check("every emitted code is declared in module.py",
      emitted <= declared, sorted(emitted - declared))
check("CONTROL: codes are actually being emitted", len(emitted) >= 3, emitted)
for code in sorted(emitted):
    uses = _re.findall(r'\("%s", "([^"]+)"' % code, src)
    check("%s describes exactly one mechanism" % code,
          len(set(uses)) == 1, uses)
# The declaration must actually DESCRIBE what the core emits. A first version
# of this check compared only the first word and contained `or "the" == key[:3]`,
# which made it pass unconditionally -- verified by re-injecting the collision
# and watching it report zero failures. This one is verified the same way, by
# re-injection, and does fail.
_STOP = {"a", "an", "the", "is", "not", "its", "out", "of", "and", "or", "to",
         "was", "were", "be", "been", "could", "cannot", "without", "so", "no",
         "that", "for", "it", "this", "every", "any", "all"}


def _words(text):
    return {w for w in _re.findall(r"[a-z]+", text.lower())
            if w not in _STOP and len(w) > 2}


for code in sorted(emitted & declared):
    core_txt = " ".join(_re.findall(r'\("%s", "([^"]+)"' % code, src))
    decl = _re.search(r'"%s": \("((?:[^"\\]|\\.)*)"' % code, _mod_src)
    shared = _words(core_txt) & _words(decl.group(1) if decl else "")
    check("%s: the declaration describes what the core emits" % code,
          bool(decl) and bool(shared),
          "core=%r decl=%r shared=%s"
          % (core_txt, decl and decl.group(1)[:60], sorted(shared)))

print("\n-- MUTATION: the canary must CATCH each injected defect --")


def _load(text):
    """Mutants beside the real file — a /tmp copy cannot resolve the shared
    canary harness and would die before any mutation mattered."""
    fd, path = tempfile.mkstemp(suffix=".py", prefix="_mutant_", dir=_HERE)
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        spec = importlib.util.spec_from_file_location("pc_mutant", path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return True, None
    except Exception as exc:                                  # noqa: BLE001
        return False, exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


_ctl_ok, _ctl_exc = _load(src)
check("CONTROL: the unmutated source imports from the mutant path",
      _ctl_ok, "every catch below would be this instead: %r" % (_ctl_exc,))

MUTATIONS = [
    ("SECURITY: the inventory check is bypassed (any target allowed)",
     "    hit = inv.get(target)\n    if hit is None:",
     "    hit = inv.get(target) or (target, SOURCE_LAN, target)\n    if False:"),
    ("SECURITY: an unreadable inventory ALLOWS instead of refusing",
     '        raise InventoryUnavailable("LAN inventory unreadable: %s"\n                                   % type(exc).__name__)',
     "        rows = []"),
    ("SECURITY: the leading-dash guard is removed",
     '    if not text or len(text) > 253 or text.startswith("-"):',
     "    if not text or len(text) > 253:"),
    ("ping loses its count bound (unbounded flood)",
     '    return ["ping", "-n", "-c", str(int(count)), "-w", str(PING_DEADLINE), "--", ip]',
     '    return ["ping", "-n", "--", ip]'),
    ("trace loses its hop bound",
     '        return ["mtr", "--report", "--report-cycles", "1", "--no-dns",\n                "-m", str(TRACE_MAX_HOPS), "--", ip]',
     '        return ["mtr", "--report", "--", ip]'),
    ("unparseable ping output reports zero received (host looks dead)",
     "    m = _PING_STATS.search(output or \"\")\n    if not m:\n        return None",
     "    m = _PING_STATS.search(output or \"\")\n    if not m:\n        return {\"sent\": 4, \"received\": 0, \"loss_pct\": 100.0, \"rtt_avg_ms\": None}"),
    ("a failed probe is reported as the device being off",
     '        b = ("Could not test %s. That is not the same as the device being off — "',
     '        b = ("%s is not responding. ("'),
    ("sub-millisecond RTT is flattened to 0 ms again",
     '    if ms < 1:\n        return "under 1 ms"',
     "    if False:\n        return \"under 1 ms\""),
]

for label, old, new in MUTATIONS:
    if old not in src:
        check("MUTATION anchor present: %s" % label, False,
              "anchor not found -- this TEST is stale, not the code")
        continue
    if not _ctl_ok:
        check("canary catches: %s" % label, False, "SKIPPED - control failed")
        continue
    imported, _exc = _load(src.replace(old, new, 1))
    check("canary catches: %s" % label, not imported,
          "the mutated module imported cleanly - the canary is not measuring")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
