"""Listening-port exposure collector (agent-side).

Answers "what on this device is listening, and how far is it reachable" -- item 2 of
the vulnerability/patch-management roadmap capability, shipped as its own v1 ahead of
the CVE work (operator decision 2026-09-03; see docs/roadmap for the split rationale).

⛔ V1 REPORTS EXPOSURE, IT DOES NOT JUDGE NECESSITY.
The roadmap wording is "flag unnecessary open ports". "Unnecessary" is a judgment that
needs a policy of what this device is FOR, and nothing in the product carries that
policy yet. Exposure -- loopback vs every interface -- is an objective property of the
socket, needs no policy, and is the half that is actually actionable ("your database is
listening on every interface" is true or false; "you don't need it" is an opinion).
The judgment layer is a later refinement that can be built ON this data. Emitting a
verdict now would mean inventing the policy silently.

⚠ PROCESS ATTRIBUTION IS PARTIAL AND THAT IS REPORTED, NEVER BLANKED.
Measured on a real host (psutil 7.1.0, non-root): 26 TCP listeners visible, only 9 with
a pid attributed. The kernel shows every listening socket but withholds the owning pid
for other users' sockets unless privileged. So a missing process name means "could not
attribute", NOT "no process" -- two different facts that a blank string would collapse
into one. Every event therefore carries an explicit `attribution` field, and the
server/UI must render "unattributed" rather than an empty owner. This is the standing
"a failed read must surface as an explicit failure state, never as a default value"
rule applied to a read that fails on MOST rows by design.

CADENCE: enumerate-current-and-diff, matching usb_events -- the server diffs the current
set against the known set. A new listener appearing is the event worth alerting on.

Best-effort: returns [] without psutil or on any enumeration error, never raises. A
collector that crashes the beat is worse than one that reports nothing, and "nothing"
is disambiguated upstream by the consent-omit contract (security.collect).
"""
import logging

log = logging.getLogger("nemesis.listening_ports")

#: Exposure classes. Objective properties of the bind address -- see module docstring.
EXPOSURE_LOOPBACK = "loopback"        # 127.0.0.0/8 or ::1 -- not reachable off-host
EXPOSURE_ALL      = "all-interfaces"  # 0.0.0.0 or :: -- reachable on every interface
EXPOSURE_SPECIFIC = "specific"        # bound to one real address
EXPOSURE_MULTICAST = "multicast"      # a group membership, NOT an exposed service
EXPOSURE_UNKNOWN  = "unknown"         # unparseable -- explicitly not a safe default

#: Attribution states for the owning process.
ATTR_OK     = "ok"           # pid resolved to a process name
ATTR_DENIED = "unattributed" # socket visible, owner withheld (privilege) or gone


def classify_exposure(ip: str) -> str:
    """Exposure class for a bind address.

    Uses ipaddress rather than string comparison so the whole 127.0.0.0/8 block and
    both unspecified forms (0.0.0.0, ::) classify correctly -- a `== "127.0.0.1"`
    test silently misclassifies a service bound to 127.0.1.1 as externally exposed.

    An unparseable address returns EXPOSURE_UNKNOWN and NOT a plausible default:
    guessing "loopback" would understate real exposure and guessing "all-interfaces"
    would manufacture an alert. Unknown is the honest answer and the caller can see it.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return EXPOSURE_UNKNOWN
    if addr.is_unspecified:
        return EXPOSURE_ALL
    if addr.is_loopback:
        return EXPOSURE_LOOPBACK
    if addr.is_multicast:
        # Measured on a real host: mDNS (224.0.0.251:5353), WS-Discovery
        # (239.255.255.250:3702) and ff02::c appear as "listening" UDP sockets, once
        # PER GROUP MEMBERSHIP -- four identical rows for one socket. They are group
        # JOINS, not a service bound to a reachable local address, so calling them
        # "specific" overstates exposure and invents alerts for ordinary desktop
        # service discovery. Classified, not dropped: the server decides what to
        # alert on, and silently discarding rows would hide real listeners.
        return EXPOSURE_MULTICAST
    return EXPOSURE_SPECIFIC


def structured_port(raw: dict) -> dict:
    """Normalise one listening socket into a structured event.

    Missing text fields become empty strings, never None -- the server builds dedup
    keys and alert text from these and a None poisons both (same contract as
    usb_devices.structured_device). `port` stays an int; a port is not text.
    """
    proc = (raw.get("process") or "").strip()
    return {
        "proto":       (raw.get("proto") or "").strip().lower(),
        "address":     (raw.get("address") or "").strip(),
        "port":        raw.get("port"),
        "exposure":    classify_exposure(raw.get("address") or ""),
        "pid":         raw.get("pid"),
        "process":     proc,
        "attribution": ATTR_OK if proc else ATTR_DENIED,
    }


def stable_key(ev: dict) -> str:
    """A dedup key stable across re-enumeration of the SAME listener.

    proto:address:port only. Deliberately EXCLUDES pid and process name: a service
    restart changes its pid and would otherwise re-alert as a brand-new listener every
    time, which is noise indistinguishable from a real new service. The socket -- not
    the process instance -- is the thing being tracked.
    """
    return "listen:%s:%s:%s" % (ev.get("proto") or "?",
                                ev.get("address") or "?",
                                ev.get("port") if ev.get("port") is not None else "?")


def list_listening_ports():
    """Currently-listening sockets as structured events. Best-effort, never raises."""
    try:
        import psutil
    except Exception as exc:                                   # noqa: BLE001
        log.debug("listening_ports: psutil unavailable: %s", exc)
        return []

    out = []
    try:
        for c in psutil.net_connections(kind="inet"):
            is_tcp = c.type == getattr(__import__("socket"), "SOCK_STREAM")
            # TCP is only "listening" in LISTEN state. UDP has no such state -- a bound
            # UDP socket IS its listening form, so it is included on bind alone. Testing
            # UDP for status == LISTEN would silently drop every UDP service (DNS, DHCP,
            # mDNS), which is the exact surface this collector exists to show.
            if is_tcp and c.status != psutil.CONN_LISTEN:
                continue
            if not c.laddr:
                continue
            name = ""
            if c.pid:
                try:
                    name = psutil.Process(c.pid).name()
                except Exception:                              # noqa: BLE001
                    name = ""   # -> ATTR_DENIED; owner withheld or process already gone
            out.append(structured_port({
                "proto":   "tcp" if is_tcp else "udp",
                "address": c.laddr.ip,
                "port":    c.laddr.port,
                "pid":     c.pid,
                "process": name,
            }))
    except Exception as exc:                                   # noqa: BLE001
        log.debug("listening_ports: enumeration error: %s", exc)
        return []
    return _dedupe(out)


def _dedupe(events):
    """One row per socket, preferring an entry whose owner could be attributed.

    Two measured causes of duplicates, with different meanings:
      * a multicast socket is listed once per group membership -- four identical rows,
        same pid, for one socket. Pure noise.
      * a port genuinely SHARED by two processes (SO_REUSEPORT; measured live on
        udp/5353, owned by svc-beta and by a second, unattributable process).

    ⚠ THE SHARED CASE COLLAPSES TO ONE ROW AND THAT LOSES THE SECOND OWNER.
    Deliberate for v1: the tracked thing is the SOCKET -- the exposure surface -- and
    the server dedups on that key regardless, so a second row would be discarded
    downstream anyway. Preferring the attributed entry means the surviving row names an
    owner where one is knowable instead of leaving it blank by accident of ordering.
    Reporting co-owners is a real refinement, but it needs a schema that can hold them;
    it is not something to fake by emitting rows the server will silently merge.
    """
    best = {}
    for ev in events:
        k = stable_key(ev)
        prev = best.get(k)
        if prev is None or (prev["attribution"] != ATTR_OK and ev["attribution"] == ATTR_OK):
            best[k] = ev
    return list(best.values())
