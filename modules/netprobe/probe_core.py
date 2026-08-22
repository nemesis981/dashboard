"""Active network probes (ping / path trace) — the pure core.

WHY THIS IS A SEPARATE MODULE FROM `lookup`
    `modules/lookup` is read-only by construction: dig and whois query FROM the
    appliance and task nothing. These probes are ACTIVE — they emit packets at a
    chosen target. That is a different security class, and putting them in the
    same module would make "lookup is read-only" a comment rather than a fact.
    The boundary is expressed in the architecture, not just in prose.

THE CONSTRAINT THAT MAKES THESE SAFE TO SHIP TODAY
    The diagnostics master plan gates anything that tasks a remote machine behind
    an authorization + consent layer. **That layer does not exist** — verified
    2026-08-22: `dashboard-roles-access-control.md` is "build NOT started", and
    `require_role` / `ROLE_*` / `is_admin` return nothing repo-wide. The dashboard
    gate is binary: any authenticated session has every privilege.

    So instead of gating the CALLER, these constrain the TARGET SPACE. A probe may
    only be aimed at a host this appliance already knows about — a row in the LAN
    inventory (`devices`) or an approved enrolled agent (`agent_devices`).

    That is the same move as the TLS port allowlist, and it is what makes the
    difference between a diagnostic and a weapon: pinging a printer you already
    own is not the same act as pinging an arbitrary internet host, and the
    attributable-traffic problem largely disappears when every possible target is
    already on your own network or already enrolled with you.

    **Port scan and packet capture are NOT here and must not be added.** They are
    held pending a deliberate decision about the gating layer. Target-space
    constraint is not sufficient for them: a port scan against a known host is
    still a port scan, and packet capture raises volume, retention and PII
    questions this constraint does not touch.

FAIL CLOSED, ALWAYS
    If the inventory cannot be read, the probe is REFUSED. An unreadable inventory
    resolving to "allow" would turn a DB hiccup into an open probe tool aimed at
    anything — the exact shape of every silent-default bug this codebase keeps
    finding, with the worst possible blast radius.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess

#: Hard cap per probe. An unbounded ping is a flood; an unbounded trace hangs a
#: request worker. Both are bounded here and the bound is not operator-settable,
#: because "how much traffic may I emit at a host" is not a preference.
PING_COUNT = 4
PING_DEADLINE = 6
TRACE_MAX_HOPS = 20
TRACE_TIMEOUT = 30

SOURCE_LAN = "lan-inventory"
SOURCE_AGENT = "enrolled-agent"


class ProbeRefused(Exception):
    """The target is not one this appliance may probe.

    An exception, never a result: every probe result shape is a legal answer
    about some host, so a returned refusal could be mistaken for a measurement.
    """


class InventoryUnavailable(Exception):
    """The inventory could not be read, so no target can be authorised.

    Distinct from ProbeRefused on purpose. "This host is not yours" and "I could
    not check whether it is yours" are different facts, and collapsing them would
    hide a broken inventory behind what looks like an ordinary refusal.
    """


def normalise_target(raw):
    """Trim a user-supplied target to a bare host. Returns '' if unusable.

    Refuses a leading dash. This is DEFENCE IN DEPTH, not the load-bearing
    control — argv already protects against shell metacharacters, every argv
    ends option parsing with "--", and authorise() refuses anything absent from
    the inventory, so "-h" would be rejected even without this line. It is kept
    because it is the last guard that survives if a future caller ever builds a
    command without "--", and it is pinned directly by the canary rather than
    through authorise(), which would pass whether the guard existed or not.
    """
    if raw is None:
        return ""
    text = str(raw).strip().lower()
    if not text or len(text) > 253 or text.startswith("-"):
        return ""
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0]
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.rstrip(".")


def load_inventory(conn):
    """{identifier: (ip, source, label)} of every probeable host.

    Raises InventoryUnavailable rather than returning {} on failure. An empty
    inventory is a legal state (nothing discovered yet) and would be
    indistinguishable from a failed read — and the failed read would then refuse
    everything, which looks like correct behaviour while the real cause is a
    broken database.
    """
    inv = {}
    try:
        rows = conn.execute(
            "SELECT ip, hostname, friendly_name FROM devices "
            "WHERE ip IS NOT NULL AND ip != ''").fetchall()
    except Exception as exc:                                 # noqa: BLE001
        raise InventoryUnavailable("LAN inventory unreadable: %s"
                                   % type(exc).__name__)
    for ip, hostname, friendly in rows:
        ip = (ip or "").strip().lower()
        if not ip:
            continue
        label = (friendly or hostname or ip).strip()
        inv[ip] = (ip, SOURCE_LAN, label)
        for alias in (hostname, friendly):
            a = (alias or "").strip().lower()
            if a and a != ip:
                inv.setdefault(a, (ip, SOURCE_LAN, label))

    try:
        rows = conn.execute(
            "SELECT ip_address, device_name FROM agent_devices "
            "WHERE enrollment_status='approved' "
            "AND ip_address IS NOT NULL AND ip_address != ''").fetchall()
    except Exception:                                        # noqa: BLE001
        # The agent table may legitimately not exist on a fresh install. The LAN
        # half already loaded, so this is a partial inventory, not a failure —
        # but it must not silently widen anything either, so it simply adds less.
        rows = []
    for ip, name in rows:
        ip = (ip or "").strip().lower()
        if not ip:
            continue
        label = (name or ip).strip()
        inv.setdefault(ip, (ip, SOURCE_AGENT, label))
        a = (name or "").strip().lower()
        if a and a != ip:
            inv.setdefault(a, (ip, SOURCE_AGENT, label))
    return inv


def authorise(raw, conn):
    """(ip, source, label) for a permitted target, else raise.

    THE security function. Every probe entry point goes through it, and nothing
    reaches a subprocess without it having returned.
    """
    target = normalise_target(raw)
    if not target:
        raise ProbeRefused("%r is not a usable host name or address" % (raw,))
    inv = load_inventory(conn)          # raises InventoryUnavailable, fails closed
    hit = inv.get(target)
    if hit is None:
        raise ProbeRefused(
            "%s is not a device this appliance knows about. Probes may only be "
            "aimed at hosts in the LAN inventory or at approved enrolled agents "
            "— arbitrary targets are deliberately not permitted." % target)
    return hit


# ── Probes ───────────────────────────────────────────────────────────────────

def ping_argv(ip, count=PING_COUNT):
    """argv for a bounded ping. `--` ends option parsing."""
    return ["ping", "-n", "-c", str(int(count)), "-w", str(PING_DEADLINE), "--", ip]


def trace_argv(ip, tool="mtr"):
    """argv for a bounded path trace.

    `mtr --report` is preferred and is what is installed here; `traceroute` is
    the fallback. Reporting which tool ran matters: their output differs, and a
    caller that assumed one format would silently mis-parse the other.
    """
    if tool == "mtr":
        return ["mtr", "--report", "--report-cycles", "1", "--no-dns",
                "-m", str(TRACE_MAX_HOPS), "--", ip]
    return ["traceroute", "-n", "-m", str(TRACE_MAX_HOPS), "-w", "2", "--", ip]


def _run(argv, timeout):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "<timed out after %ss>" % timeout
    except FileNotFoundError:
        return 127, "<command not found>"
    except Exception as exc:                                 # noqa: BLE001
        return 1, "<error: %s>" % type(exc).__name__


_PING_STATS = re.compile(
    r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss", re.S)
_PING_RTT = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)")


def parse_ping(output):
    """{sent, received, loss_pct, rtt_avg_ms} or None if unparseable.

    None, not zeros. A parse failure that returned 0-received would be reported as
    "the host is down", which is a confident wrong answer about someone's network.
    """
    m = _PING_STATS.search(output or "")
    if not m:
        return None
    sent, recv, loss = int(m.group(1)), int(m.group(2)), float(m.group(3))
    rtt = _PING_RTT.search(output or "")
    return {"sent": sent, "received": recv, "loss_pct": loss,
            "rtt_avg_ms": float(rtt.group(2)) if rtt else None}


def parse_trace(output, tool="mtr"):
    """[{hop, host, loss_pct, avg_ms}] — best effort, never raises."""
    hops = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("start:", "host", "traceroute")):
            continue
        if tool == "mtr":
            m = re.match(r"^\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%\s+\d+\s+([\d.]+)", line)
            if m:
                hops.append({"hop": int(m.group(1)), "host": m.group(2),
                             "loss_pct": float(m.group(3)),
                             "avg_ms": float(m.group(4))})
        else:
            m = re.match(r"^\s*(\d+)\s+(\S+)", line)
            if m:
                hops.append({"hop": int(m.group(1)), "host": m.group(2),
                             "loss_pct": None, "avg_ms": None})
    return hops


# ── Tiering ──────────────────────────────────────────────────────────────────

TIERS = ("beginner", "intermediate", "pro")


def _fmt_ms(ms):
    """Render a round-trip time without flattening sub-millisecond values to 0."""
    if ms is None:
        return "unknown"
    if ms < 1:
        return "under 1 ms"
    if ms < 10:
        return "%.1f ms" % ms
    return "%.0f ms" % ms


def tier_ping(label, ip, stats, raw, error=None):
    """Three readings of one ping."""
    if error or stats is None:
        b = ("Could not test %s. That is not the same as the device being off — "
             "the test itself did not complete. Next: try again, and check the "
             "device is still on your network." % label)
        return {"beginner": b,
                "intermediate": "%s (%s): probe did not complete (%s)"
                                % (label, ip, error or "unparseable output"),
                "pro": (raw or "").strip() or "(no output)"}
    loss, recv, sent = stats["loss_pct"], stats["received"], stats["sent"]
    rtt = stats["rtt_avg_ms"]
    if loss == 0:
        # Sub-millisecond RTT is normal on a LAN, and "%.0f" renders 0.29ms as
        # "0 ms" — which reads as a broken measurement rather than a fast one.
        b = ("%s is responding normally — all %d test messages came back%s."
             % (label, sent, (", averaging %s" % _fmt_ms(rtt)) if rtt else ""))
        nxt = ""
    elif loss >= 100:
        b = ("%s did not respond to any of the %d test messages. It may be "
             "switched off, asleep, or blocking this kind of test — not all "
             "devices answer." % (label, sent))
        nxt = "Next: if you expect it to be on, check it is powered and connected."
    else:
        b = ("%s responded to only %d of %d test messages (%.0f%% lost). "
             "Intermittent loss like this usually means a weak wireless signal "
             "or a congested link." % (label, recv, sent, loss))
        nxt = "Next: if it is on WiFi, signal strength is the first thing to check."
    if nxt:
        b += " " + nxt
    m = ("%s (%s): %d/%d received, %.0f%% loss%s"
         % (label, ip, recv, sent, loss, (", avg %.1f ms" % rtt) if rtt else ""))
    return {"beginner": b, "intermediate": m,
            "pro": (raw or "").strip() or "(no output)"}


def tier_trace(label, ip, hops, raw, error=None):
    """Three readings of one path trace."""
    if error or not hops:
        b = ("Could not map the network path to %s. The test did not complete, "
             "which is not the same as there being no path." % label)
        return {"beginner": b,
                "intermediate": "%s (%s): trace did not complete (%s)"
                                % (label, ip, error or "no hops parsed"),
                "pro": (raw or "").strip() or "(no output)"}
    n = len(hops)
    b = ("Traffic reaches %s through %d step%s inside your network. Each step is "
         "a piece of network equipment the data passes through."
         % (label, n, "" if n == 1 else "s"))
    lossy = [h for h in hops if (h.get("loss_pct") or 0) >= 50]
    if lossy:
        b += (" One or more steps are losing traffic, which is worth looking at "
              "— that is usually where a slow or unreliable connection starts.")
        b += " Next: the step showing loss is the one to investigate first."
    m = "%s (%s): %d hops%s" % (label, ip, n,
                                (", %d lossy" % len(lossy)) if lossy else "")
    return {"beginner": b, "intermediate": m,
            "pro": (raw or "").strip() or "(no output)"}


# ── Orchestration ────────────────────────────────────────────────────────────

def verdict_of(stats, ran):
    """One word for the card's colour. 'untested' is NOT 'unreachable'.

    A probe that could not RUN and a device that did not ANSWER are different
    findings. Collapsing them would let a missing binary render as every device
    on the network being down.
    """
    if not ran or stats is None:
        return "untested"
    if stats["received"] == 0:
        return "unreachable"
    if stats["loss_pct"] > 0:
        return "degraded"
    return "ok"


def available_trace_tool():
    """Which trace tool is installed, or None. Used by status()."""
    for tool in ("mtr", "traceroute"):
        if _run([tool, "--help"], 5)[0] != 127:
            return tool
    return None


def run_ping(raw_target, conn, runner=None):
    """Authorise, then ping. Raises before any packet if the target is not ours."""
    ip, source, label = authorise(raw_target, conn)
    runner = runner or _run
    rc, out = runner(ping_argv(ip), PING_DEADLINE + 4)
    problems = []
    if rc == 127:
        problems.append(("E-NETPROBE-001", "ping is not installed"))
    elif rc == 124:
        problems.append(("E-NETPROBE-002", "the ping probe timed out"))
    stats = parse_ping(out) if rc in (0, 1) else None
    err = None if stats else (out[:80] if rc not in (0, 1) else None)
    return {"kind": "ping", "target": ip, "source": source, "label": label,
            "stats": stats, "problems": problems,
            "verdict": verdict_of(stats, rc in (0, 1)),
            "explanation": tier_ping(label, ip, stats, out, err)}


def run_trace(raw_target, conn, runner=None, tool=None):
    """Authorise, then trace. Raises before any packet if the target is not ours."""
    ip, source, label = authorise(raw_target, conn)
    runner = runner or _run
    chosen = tool or "mtr"
    rc, out = runner(trace_argv(ip, chosen), TRACE_TIMEOUT)
    if rc == 127 and tool is None:
        # mtr absent — fall back, and SAY which tool produced the output.
        chosen = "traceroute"
        rc, out = runner(trace_argv(ip, chosen), TRACE_TIMEOUT)
    problems = []
    if rc == 127:
        problems.append(("E-NETPROBE-003", "neither mtr nor traceroute is installed"))
    elif rc == 124:
        problems.append(("E-NETPROBE-005", "the path trace timed out"))
    hops = parse_trace(out, chosen) if rc == 0 else []
    err = None if hops else (out[:80] if rc != 0 else None)
    return {"kind": "trace", "target": ip, "source": source, "label": label,
            "tool": chosen, "hops": hops, "problems": problems,
            "verdict": "ok" if hops else "untested",
            "explanation": tier_trace(label, ip, hops, out, err)}


# ── Canary — shared harness ──────────────────────────────────────────────────

def _load_harness():
    import importlib.util, os
    p = os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), "diagnostics", "canary.py")
    spec = importlib.util.spec_from_file_location("netprobe_canary_harness", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_H = _load_harness()

_PING_OK = ("4 packets transmitted, 4 received, 0% packet loss, time 3005ms\n"
            "rtt min/avg/max/mdev = 0.312/0.451/0.602/0.101 ms")
_PING_DEAD = "4 packets transmitted, 0 received, 100% packet loss, time 3070ms"


class _FakeConn:
    """An inventory stand-in. `rows` maps the query shape to results."""
    def __init__(self, lan=(), agents=(), raise_on_lan=False):
        self.lan, self.agents, self.raise_on_lan = lan, agents, raise_on_lan

    def execute(self, sql, params=()):
        if "FROM devices" in sql:
            if self.raise_on_lan:
                raise RuntimeError("db gone")
            return _Res(self.lan)
        return _Res(self.agents)


class _Res:
    def __init__(self, rows): self._rows = rows
    def fetchall(self): return list(self._rows)


_INV = _FakeConn(lan=[("192.0.2.10", "printer", "Office Printer")],
                 agents=[("192.0.2.50", "laptop-1")])


def _refused(target, conn=None):
    try:
        authorise(target, conn or _INV)
        return None
    except (ProbeRefused, InventoryUnavailable) as e:
        return str(e)


CASES = [
    # --- THE SECURITY PROPERTY: only known hosts ---------------------------
    _H.bad("an arbitrary internet host is refused",
           lambda: _refused("example.com")),
    _H.bad("an arbitrary IP is refused", lambda: _refused("8.8.8.8")),
    _H.bad("a LAN IP that is NOT in inventory is refused",
           lambda: _refused("192.0.2.99")),
    _H.bad("a leading-dash target is refused", lambda: _refused("-h")),
    _H.bad("a target that IS a flag is refused by normalise_target ITSELF",
           lambda: (normalise_target("-h") == "") or None),
    _H.bad("...including a long-form flag",
           lambda: (normalise_target("--interface=eth0") == "") or None),
    _H.good("CONTROL: a normal host is NOT refused by that guard",
            lambda: (normalise_target("printer") != "printer") or None),
    _H.bad("an empty target is refused", lambda: _refused("")),
    _H.bad("the refusal explains the policy, not just 'no'",
           lambda: ("deliberately not permitted" in (_refused("example.com") or "")) or None),
    # --- CONTROL: known hosts ARE permitted --------------------------------
    _H.good("a LAN inventory IP is permitted", lambda: _refused("192.0.2.10")),
    _H.good("a LAN device by hostname is permitted", lambda: _refused("printer")),
    _H.good("an approved agent IP is permitted", lambda: _refused("192.0.2.50")),
    _H.good("an agent by device name is permitted", lambda: _refused("laptop-1")),
    _H.bad("...and authorisation reports WHICH source allowed it",
           lambda: authorise("192.0.2.50", _INV)[1] == SOURCE_AGENT or None),
    # --- FAIL CLOSED --------------------------------------------------------
    _H.bad("an unreadable inventory REFUSES rather than allowing",
           lambda: _refused("192.0.2.10", _FakeConn(raise_on_lan=True))),
    _H.bad("...and says the inventory was unreadable, not that the host is unknown",
           lambda: ("unreadable" in (_refused("192.0.2.10",
                    _FakeConn(raise_on_lan=True)) or "")) or None),
    _H.bad("an EMPTY inventory permits nothing",
           lambda: _refused("192.0.2.10", _FakeConn())),
    # --- bounded commands ---------------------------------------------------
    _H.bad("ping is count-bounded", lambda: ("-c" in ping_argv("1.2.3.4")) or None),
    _H.bad("ping argv ends option parsing with --",
           lambda: (ping_argv("1.2.3.4").index("--") <
                    ping_argv("1.2.3.4").index("1.2.3.4")) or None),
    _H.bad("trace is hop-bounded", lambda: ("-m" in trace_argv("1.2.3.4")) or None),
    # --- parsing ------------------------------------------------------------
    _H.bad("a healthy ping parses", lambda: parse_ping(_PING_OK)),
    _H.bad("...with 0% loss", lambda: (parse_ping(_PING_OK)["loss_pct"] == 0.0) or None),
    _H.bad("a dead host parses as 100% loss",
           lambda: (parse_ping(_PING_DEAD)["loss_pct"] == 100.0) or None),
    _H.good("unparseable output yields None, NOT zero-received",
            lambda: parse_ping("total nonsense")),
    _H.good("empty output yields None", lambda: parse_ping("")),
    # --- tiering ------------------------------------------------------------
    _H.bad("all three tiers are produced",
           lambda: set(tier_ping("P", "1.2.3.4", parse_ping(_PING_OK), _PING_OK))
           == set(TIERS) or None),
    _H.bad("the three tiers differ",
           lambda: len(set(tier_ping("P", "1.2.3.4", parse_ping(_PING_OK),
                                     _PING_OK).values())) == 3 or None),
    _H.bad("a dead host gives the beginner a next step",
           lambda: "Next:" in tier_ping("P", "1.2.3.4", parse_ping(_PING_DEAD),
                                        _PING_DEAD)["beginner"] or None),
    _H.bad("sub-millisecond RTT is not flattened to '0 ms'",
           lambda: (_fmt_ms(0.29) == "under 1 ms") or None),
    _H.bad("a normal LAN RTT renders with precision",
           lambda: (_fmt_ms(3.4) == "3.4 ms") or None),
    _H.bad("a WAN-scale RTT rounds sensibly",
           lambda: (_fmt_ms(42.7) == "43 ms") or None),
    _H.good("an unknown RTT does not render as a number",
            lambda: (_fmt_ms(None) != "unknown") or None),
    _H.bad("a probe that could NOT RUN is 'untested', never 'unreachable'",
           lambda: (verdict_of(None, False) == "untested") or None),
    _H.bad("a host that did not answer IS 'unreachable'",
           lambda: (verdict_of({"received": 0, "loss_pct": 100.0}, True)
                    == "unreachable") or None),
    _H.bad("partial loss is 'degraded', not 'ok'",
           lambda: (verdict_of({"received": 2, "loss_pct": 50.0}, True)
                    == "degraded") or None),
    _H.good("CONTROL: a healthy host is not reported as degraded",
            lambda: (verdict_of({"received": 4, "loss_pct": 0.0}, True)
                     != "ok") or None),
    _H.good("a HEALTHY host gets no alarming next step",
            lambda: ("Next:" in tier_ping("P", "1.2.3.4", parse_ping(_PING_OK),
                                          _PING_OK)["beginner"]) or None),
    _H.bad("a failed probe is NOT reported as the device being off",
           lambda: ("not the same as the device being off"
                    in tier_ping("P", "1.2.3.4", None, "", error="boom")["beginner"]) or None),
]


def canary():
    return _H.run_cases(CASES)


def _assert_canary_at_import():
    ok, detail = canary()
    if not ok:
        raise AssertionError("probe_core canary failed at import: %s" % detail)


_assert_canary_at_import()
