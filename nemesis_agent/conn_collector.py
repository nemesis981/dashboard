"""Track C step 4 — platform-independent collection core.

WHAT THIS IS AND IS NOT
-----------------------
This module holds everything about connection collection that is NOT
platform-specific: the DNS→name correlation cache, and the assembler that turns
raw connection facts into validated `conn_events` records.

`EtwSource` (bottom of this file) holds the Windows-specific plumbing and is now
IMPLEMENTED, built against measured provider behaviour rather than assumption —
see its docstring for the measurements and for why it classifies events by field
shape rather than by an event-id table nobody verified. Its event handlers take
plain dicts, so the classification, byte-accumulation and direction logic are all
testable on any platform with synthetic payloads; only the ETW session itself
requires Windows.

Consent (Requirement 0) is checked ONCE, at `Collector.start()`, and re-checked
per batch. Individual methods do not each re-implement it — that is exactly the
"one missed branch silently defeats it" shape the build plan warns about.
"""
import hashlib
import time
from collections import Counter

try:
    import consent
    import conn_events as ce
except ImportError:                      # pragma: no cover — package-relative import
    from . import consent                # type: ignore
    from . import conn_events as ce      # type: ignore


#: How long an observed DNS answer is allowed to attribute a destination.
#:
#: NOT the DNS record's own TTL, deliberately. A short TTL would throw away a
#: mapping that is still the best evidence we have; a long one would attribute a
#: reassigned address to a name that no longer serves it. This is a bounded
#: heuristic window over an inherently lossy mapping (one address serves many
#: names; one name resolves to many addresses), and it is documented as a
#: heuristic rather than presented as fact.
DNS_CACHE_TTL_SECONDS = 600

#: Hard cap on cached mappings. A host doing DNS-heavy work must not be able to
#: grow this without bound — the same "no silent unbounded growth" rule the
#: build plan applies to the event buffer.
DNS_CACHE_MAX = 4096


class DnsCache:
    """IP → most-recently-observed name, with expiry and a hard size cap.

    `available=False` means this platform cannot observe DNS at all (Linux
    today). That is reported as `unavailable` provenance, which is a DIFFERENT
    answer from "we watched and saw nothing" (`no_dns_observed`) — conflating
    them would make a platform limitation indistinguishable from a finding about
    the traffic.
    """

    def __init__(self, available=False, ttl=DNS_CACHE_TTL_SECONDS, max_entries=DNS_CACHE_MAX,
                 clock=time.monotonic):
        self.available = bool(available)
        self.ttl = ttl
        self.max_entries = max_entries
        self._clock = clock
        self._by_ip = {}        # ip -> (name, observed_at)
        self.evictions = 0      # reported, never silent

    def observe(self, name, addrs):
        """Record a DNS answer: one name, the addresses it resolved to."""
        if not self.available or not name or not addrs:
            return
        now = self._clock()
        for ip in addrs:
            if not ip:
                continue
            # Last writer wins. When several names share an address (a CDN), the
            # most recent observation is the best available guess and nothing
            # better is derivable from DNS alone. Documented as a guess.
            self._by_ip[ip] = (name, now)
        self._evict_if_needed(now)

    def _evict_if_needed(self, now):
        if len(self._by_ip) <= self.max_entries:
            return
        # Drop oldest first. Count it — an eviction means we may be about to
        # report `no_dns_observed` for a connection whose name we actually saw,
        # and that is a measurable degradation, not a detail to hide.
        for ip, _ in sorted(self._by_ip.items(), key=lambda kv: kv[1][1])[
                :len(self._by_ip) - self.max_entries]:
            del self._by_ip[ip]
            self.evictions += 1

    def lookup(self, ip):
        """(name, provenance). Never raises. Never invents a name."""
        if not self.available:
            return None, ce.NAME_SRC_UNAVAILABLE
        entry = self._by_ip.get(ip)
        if not entry:
            return None, ce.NAME_SRC_NONE
        name, seen_at = entry
        if (self._clock() - seen_at) > self.ttl:
            # Expired. Drop it rather than serve a stale attribution — a name
            # that no longer serves this address is a false claim, and a false
            # claim is worse than an absent one.
            del self._by_ip[ip]
            return None, ce.NAME_SRC_NONE
        return name, ce.NAME_SRC_DNS_EVENT

    def __len__(self):
        return len(self._by_ip)


class ConnectionAssembler:
    """Turns raw open/close facts into validated schema records.

    Holds the open-connection table so a `close` can carry the matching
    `ts_open_*`, which is what makes a close event self-contained (the schema
    stores both, so duration needs no server-side pairing).
    """

    #: Cap on simultaneously-tracked open connections. A host under a SYN flood,
    #: or one leaking sockets, must not be able to grow this without bound.
    MAX_OPEN = 8192

    def __init__(self, device_id, dns_cache=None, clock_wall=None, clock_mono=time.monotonic):
        self.device_id = device_id
        self.dns = dns_cache if dns_cache is not None else DnsCache(available=False)
        self._mono = clock_mono
        self._wall = clock_wall or (lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        self._open = {}         # conn_id -> (ts_open_wall, ts_open_mono)
        self.dropped_open_overflow = 0
        self.unmatched_closes = 0

    def on_open(self, conn_id, proto, laddr, lport, raddr, rport,
                pid=None, proc_name=None, proc_path=None,
                proc_signed=ce.SIGNED_UNKNOWN, consent_version=None):
        if len(self._open) >= self.MAX_OPEN:
            self.dropped_open_overflow += 1
            return None
        w, m = self._wall(), self._mono()
        self._open[conn_id] = (w, m)
        name, src = self.dns.lookup(raddr)
        return ce.new_event(
            ce.EVENT_OPEN, conn_id, self.device_id, consent_version, proto,
            laddr, lport, raddr, rport, w, m,
            pid=pid, proc_name=proc_name, proc_path=proc_path, proc_signed=proc_signed,
            resolved_name=name, resolved_name_source=src)

    def on_close(self, conn_id, proto, laddr, lport, raddr, rport,
                 pid=None, proc_name=None, proc_path=None,
                 proc_signed=ce.SIGNED_UNKNOWN, bytes_sent=None, bytes_recv=None,
                 consent_version=None, ts_close_wall=None, ts_close_mono=None):
        """`ts_close_*` may be supplied by the caller.

        A source that defers emission (EtwSource holds a closed connection open
        for a grace period, because ETW delivers data events AFTER the close that
        logically follows them) must report when the connection actually closed,
        not when it got around to emitting. Defaulting to "now" would silently
        inflate every duration by the grace window.
        """
        opened = self._open.pop(conn_id, None)
        if opened is None:
            # A close with no matching open — the collector started mid-connection,
            # or the open overflowed. Counted and NOT emitted: fabricating a
            # ts_open we never observed would put an invented measurement into the
            # store, which is worse than a missing record.
            self.unmatched_closes += 1
            return None
        w_open, m_open = opened
        name, src = self.dns.lookup(raddr)
        return ce.new_event(
            ce.EVENT_CLOSE, conn_id, self.device_id, consent_version, proto,
            laddr, lport, raddr, rport, w_open, m_open,
            ts_close_wall=ts_close_wall if ts_close_wall is not None else self._wall(),
            ts_close_mono=ts_close_mono if ts_close_mono is not None else self._mono(),
            pid=pid, proc_name=proc_name, proc_path=proc_path, proc_signed=proc_signed,
            bytes_sent=bytes_sent, bytes_recv=bytes_recv,
            resolved_name=name, resolved_name_source=src)

    def open_count(self):
        return len(self._open)


# --------------------------------------------------------------------------- #
# Flow identity — because ETW's `connid` is not one
# --------------------------------------------------------------------------- #
#
# MEASURED, 2026-08-07 (probe VM, 211 events): `connid` is the string `"0"` on
# EVERY Kernel-Network event — one distinct value across the whole capture. It is
# present on every event, and it means nothing.
#
# That is why `bytes_sent`/`bytes_recv` were always empty. Every connection
# collided on the single key `"0"`: an open registered the accumulator, the very
# next close popped it, and every subsequent data event was an orphan. The
# accumulator was working perfectly — it was being asked about a connection
# identity that did not exist.
#
# So identity is DERIVED here. The 5-tuple alone is ambiguous under port reuse
# (the original reason for preferring `connid`), so the open timestamp is folded
# into the emitted `conn_id`, which makes two successive connections on an
# identical 5-tuple distinguishable in the store.
#
# ⚠ THE INDEX AND THE ID ARE DELIBERATELY DIFFERENT THINGS. The in-memory table
# is keyed by the 5-tuple ALONE, because that is all a data event can compute — a
# data event carries no open timestamp. Uniqueness across reuse comes from the id
# stored *inside* the entry, and from the entry being replaced when a new open
# arrives for the same tuple. Trying to index by a key containing the open time
# would make every data event unable to find its own connection, which is the
# exact failure being fixed.

#: A flow with no close and no traffic for this long is abandoned. UDP has no
#: close at all, and TCP closes are missed whenever the collector starts
#: mid-connection or the process dies, so without this the table only grows.
FLOW_IDLE_TIMEOUT_SECONDS = 300

# --------------------------------------------------------------------------- #
# TCP event-id -> operation. MEASURED, not inferred.
# --------------------------------------------------------------------------- #
#
# Campaign run 2026-08-07 against a purpose-built LAN rig with EXACT known byte
# counts in each direction (the probe VM's internet is intermittent, and a run
# that transferred nothing proves nothing, so ground truth comes from the socket
# itself — not from whatever the network happened to do).
#
#   UPLOAD run   — really sent 65536, really recv 1024:
#       id=10 total 65536  = 1.000x sent      id=11 total 1024   = 1.000x recv
#   DOWNLOAD run — really sent 1,     really recv 65536:
#       id=10 total 1      = 1.000x sent      id=11 total 65536  = 1.000x recv
#       id=18 total 43800  = 0.668x recv  (a PARTIAL DUPLICATE of received data)
#
# Both directions, both runs, exact ratios. IPv6 ids are the documented +16
# offset, observed directly in earlier captures (27/29/34 on v6 connections).
#
# ⚠ THIS REPLACES CLASSIFICATION BY FIELD SHAPE, WHICH WAS ACTIVELY WRONG.
# `_is_close()` keys on `startime`/`endtime` — and the measurement above shows
# **`TcpIpSend` (id 10) carries `startime` and `endtime`**. So every send event
# was classified as a CLOSE. That single fault produced all of the observed
# symptoms: bytes_sent was never accumulated (sends were never seen as data), and
# the first send of a connection "closed" it, popping the accumulator so all
# later data orphaned. The earlier conclusion that "ETW delivers events out of
# order" was a MISDIAGNOSIS of exactly this — with correct classification the
# real disconnect (id 13) arrives last in every captured connection.
#
# The old docstring argued field shapes were safer because the id mapping "was
# never measured". It has now been measured; the shapes were the guess.
TCP_CONNECT_IDS    = frozenset({12, 28})   # TcpIpConnect      -> OPEN
TCP_DISCONNECT_IDS = frozenset({13, 29})   # TcpIpDisconnect   -> CLOSE
TCP_SEND_IDS       = frozenset({10, 26})   # TcpIpSend         -> bytes_sent
TCP_RECV_IDS       = frozenset({11, 27})   # TcpIpRecv         -> bytes_recv

#: `TcpIpTCPCopy` — measured to re-report data already counted by TcpIpRecv
#: (43800 of 65536 received bytes, i.e. a PARTIAL duplicate). Counting it inflates
#: recv by an amount that varies per connection, which is worse than a constant
#: error because it cannot be corrected for after the fact. EXCLUDED.
TCP_COPY_IDS       = frozenset({18, 34})

#: How long a CLOSED connection is held before its record is emitted.
#:
#: ⚠ RETAINED AS INSURANCE, BUT ITS ORIGINAL JUSTIFICATION WAS WRONG — say so
#: plainly rather than leaving a confident-sounding false claim in place.
#:
#: This was introduced on the conclusion that "ETW delivers a connection's close
#: BEFORE data events that preceded it", from an instrumented run showing 29
#: orphans and 0 bytes on a connection that really moved ~4KB. That evidence was
#: real; the explanation was not. Those "closes" were `TcpIpSend` events being
#: misclassified as closes (send carries `startime`/`endtime`). With the measured
#: id mapping in place, the true disconnect arrives LAST in every connection
#: captured, and no out-of-order delivery has been observed at all.
#:
#: It is kept because deferring the emission is cheap and a genuine reordering
#: would silently lose bytes — but it is defensive, NOT evidence-backed, and must
#: not be cited as a measured property of ETW.
CLOSE_GRACE_SECONDS = 2.0

#: Cap on simultaneously tracked flows. Mirrors ConnectionAssembler.MAX_OPEN.
MAX_FLOWS = 8192


def _endpoint(addr, port):
    return (str(addr or ""), _port(port))


def flow_key(proto, saddr, sport, daddr, dport):
    """Direction-agnostic connection identity: (proto, lower_ep, higher_ep).

    THE SORT IS LOAD-BEARING. A send and its matching receive arrive with saddr
    and daddr swapped, so an unsorted key would file the two directions of one
    connection as two different connections — and then neither would match the
    open, which is the orphaning bug in a new costume.
    """
    a, b = _endpoint(saddr, sport), _endpoint(daddr, dport)
    lo, hi = (a, b) if a <= b else (b, a)
    return (proto, lo, hi)


def flow_conn_id(fkey, opened_mono):
    """Stable synthetic `conn_id` for one connection instance.

    Includes the open timestamp so that two connections reusing the same 5-tuple
    get different ids. Hashed for compactness and a bounded length; the record
    already carries the addresses in their own fields, so the hash hides nothing
    that is not stored alongside it anyway.

    Deterministic: the open and the close of one connection MUST produce the same
    id, which is what lets the server pair them. The close does not recompute it —
    it reads back the id stored at open — but determinism keeps that an
    optimisation rather than a requirement.
    """
    proto, lo, hi = fkey
    raw = "%s|%s:%d|%s:%d|%.6f" % (proto, lo[0], lo[1], hi[0], hi[1], opened_mono)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def collection_permitted():
    """THE gate, re-exported so the collector has exactly one thing to call.

    Requirement 0 clause 4: one gate. This wrapper exists so a caller cannot be
    tempted to hand-roll a consent check, and so the consent version used to
    stamp records comes from the same read that authorised collection.
    """
    return consent.collection_allowed(consent.ITEM_CONNECTIONS), consent.consent_version()


# --------------------------------------------------------------------------- #
# Platform source — NOT IMPLEMENTED, and deliberately isolated
# --------------------------------------------------------------------------- #

class EtwSource:
    """Windows ETW collection, built against MEASURED provider behaviour.

    Measurements this is built on (probe VM, Windows 10.0.26200.8655, 2026-08-07 —
    raw data in `scoping-and-estimates/etw-probe-report-2026-08-07.json`):

      * `Microsoft-Windows-Kernel-Network` keyword table is exactly
        `IPV4=0x10`, `IPV6=0x20` (+ an Analytic keyword). **We enable 0x30 at
        level 4**, and that was verified to still deliver connect, close and data
        events — 11,580 in 25s. The probe's `0xFFFF...` + level 5 was discovery
        only; narrowing is what production ships.
      * **`connid` is present on every Kernel-Network event and is USELESS.**
        Measured 2026-08-07: it is the string `"0"` on all 211 events — one
        distinct value in the entire capture. An earlier revision of this
        docstring called it "a real per-connection identifier"; that was an
        INFERENCE FROM ITS PRESENCE, never a measurement of its content, and it
        was wrong. Presence is not meaning. Identity is therefore derived — see
        `flow_key()` / `flow_conn_id()` above — and the port-reuse ambiguity that
        made `connid` look preferable is handled by folding the open timestamp
        into the emitted id.
      * `size` appears on data events, never as a per-connection total, so bytes
        MUST be accumulated. Data events are **96% of volume** (ids 11 and 27
        alone were 11,111 of 11,580), so their handler is deliberately a dict
        increment and nothing more.
      * `Task Name` distinguishes only `KERNEL_NETWORK_TASK_TCPIP` from
        `..._UDPIP` — it does NOT identify connect/send/recv/close.

    CLASSIFICATION IS BY MEASURED EVENT ID (see the id tables above), with field
    shape kept only as a counted fallback for unmapped ids and for UDP.

    ⚠ THIS REVERSES AN EARLIER DECISION, AND THE EARLIER ONE WAS WRONG. This
    docstring used to argue that field shapes were safer because the id mapping
    "was never measured" and a hardcoded table "would be a guess". The mapping has
    now been measured against exact known byte counts in both directions — and the
    measurement showed the shapes were the guess: **`TcpIpSend` carries `startime`
    and `endtime`**, the very fields `_is_close()` tests for. Every send event was
    therefore classified as a connection close. That one fault caused all of it —
    `bytes_sent` was never accumulated because sends were never seen as data, and
    the first send of a connection "closed" it, popping the accumulator so every
    later data event orphaned.

    It also produced a convincing false conclusion: that ETW delivers events out
    of order. It does not, as far as anything here has observed — the "closes
    arriving before data" were sends being misread. `CLOSE_GRACE_SECONDS` was
    built on that misdiagnosis; it is retained as cheap insurance but is
    explicitly NOT evidence-backed (see its own note).

    The lesson worth keeping: "measured" applied to the FIELDS' existence, never
    to what they MEANT — the same error as reading `connid`'s presence as
    identity, made twice in one file.

    ONE PROVIDER PER SESSION, deliberately: the probe had to attribute events by
    guessing at id ranges because a single mixed session carries no provider name
    in the payload. Two sessions means provider identity comes from which callback
    fired, which is a fact rather than a deduction.

    PRIVILEGE. The probe proved a session starts as an Administrator
    (`admin=True`, `perf_log_users=False`). Whether a non-admin member of
    `Performance Log Users` also works is **UNTESTED**. This class therefore does
    NOT gate on a privilege check — gating on an untested assumption would refuse
    to run in a configuration that may be perfectly fine. It attempts the session
    and reports a precise failure instead.
    """

    KERNEL_NETWORK = "Microsoft-Windows-Kernel-Network"
    KERNEL_NETWORK_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
    DNS_CLIENT = "Microsoft-Windows-DNS-Client"
    DNS_CLIENT_GUID = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"

    KW_IPV4 = 0x10
    KW_IPV6 = 0x20
    LEVEL = 4                      # informational; verbose (5) was discovery-only

    #: DNS volume was measured at ~4 events/sec — two orders below the network
    #: provider — so it is not narrowed. Documented so the asymmetry reads as a
    #: measurement rather than an oversight.
    DNS_KEYWORDS = 0xFFFFFFFFFFFFFFFF

    def __init__(self, assembler, dns_cache, consent_version, emit,
                 clock_mono=time.monotonic, proc_map=None):
        self.asm = assembler
        self.dns = dns_cache
        self.consent_version = consent_version
        self.emit = emit
        #: pid -> process identity. OPTIONAL and defaulted to None so every
        #: existing caller and test keeps working unchanged; when absent, events
        #: carry a bare pid exactly as they did before (see _proc()).
        self.proc_map = proc_map
        self._jobs = []
        self._mono = clock_mono
        #: flow_key -> flow state. Replaces the old `connid`-keyed `_bytes` and
        #: `_local` dicts, which both collided on `"0"` for every connection.
        self._flows = {}
        self.stats = Counter()

    def _proc(self, pid):
        """(proc_name, proc_path) for a pid, or (None, None).

        ONE helper for both the open and close paths deliberately: two lookups
        written separately are two things that drift, and an event whose open and
        close disagree about which program owned it is worse than one that names
        neither.

        ⚠ `proc_signed` IS NOT FILLED and that is deliberate. Authenticode
        verification is a separate job with its own cost and failure modes;
        populating name and path while leaving `proc_signed` looking answered
        would be worse than leaving it plainly SIGNED_UNKNOWN.

        Never raises: attribution is an ENRICHMENT. A failure here must cost a
        name, never an event.
        """
        try:
            # getattr, not self.proc_map: this class is legitimately built via
            # __new__ with only the handler attributes set (the suite does exactly
            # that to exercise event logic without an ETW session). A bare
            # attribute access there raises AttributeError OUTSIDE any guard and
            # costs the whole event -- which is precisely what this docstring
            # promises cannot happen. It did, once, before this line.
            pmap = getattr(self, "proc_map", None)
            if pmap is None or pid is None:
                return (None, None)
            name, path, _src = pmap.lookup(pid)
            self.stats["proc_named" if name else "proc_unnamed"] += 1
            return (name, path)
        except Exception:                                    # noqa: BLE001
            self.stats["proc_lookup_errors"] += 1
            return (None, None)

    def _emit_closed(self, fkey, st):
        """Emit the deferred close record for one flow. Never raises."""
        saddr, sport, daddr, dport = st["close_ep"]
        # Bytes are reported ONLY when their direction is known. A connection
        # whose traffic could not be attributed reports None for both, not zero
        # and not a one-sided total — see the direction note in `_on_network`.
        if st["undirected"] and not (st["sent"] or st["recv"]):
            sent = recv = None
        else:
            sent, recv = st["sent"], st["recv"]
        _pname, _ppath = self._proc(st["close_pid"])
        rec = self.asm.on_close(
            st["conn_id"], st["proto"], saddr, sport, daddr, dport,
            pid=st["close_pid"], proc_name=_pname, proc_path=_ppath,
            bytes_sent=sent, bytes_recv=recv,
            consent_version=self.consent_version,
            ts_close_wall=st["close_wall"], ts_close_mono=st["close_mono"])
        if rec:
            self.emit(rec)

    def flush_closed(self, now=None, force=False):
        """Emit closed flows whose grace window has elapsed. Returns the count.

        Driven from the OPEN path and from `stop()` rather than from the data
        path, which is 96% of volume and must stay cheap. `force` flushes
        regardless of the window — used at shutdown so a connection that closed
        just before we stopped is still reported rather than silently dropped.
        """
        now = self._mono() if now is None else now
        ready = [k for k, st in self._flows.items()
                 if st.get("closing") is not None
                 and (force or now - st["closing"] >= CLOSE_GRACE_SECONDS)]
        for k in ready:
            st = self._flows.pop(k)
            try:
                self._emit_closed(k, st)
            except Exception:                                # noqa: BLE001
                self.stats["close_emit_errors"] += 1
        if ready:
            self.stats["close_emitted"] += len(ready)
        return len(ready)

    def _expire_flows(self, now):
        """Drop flows idle past the timeout. Returns how many were dropped.

        Called on OPEN and when the table is full — deliberately NOT on data
        events, which are 96% of volume and whose handler must stay a dict lookup
        plus an integer add. Opens are the rare event, so they are where the
        housekeeping belongs.
        """
        cutoff = now - FLOW_IDLE_TIMEOUT_SECONDS
        stale = [k for k, st in self._flows.items() if st["last_seen"] < cutoff]
        for k in stale:
            st = self._flows.pop(k)
            if st.get("closing") is not None:
                # It closed and then went quiet past the idle timeout without ever
                # being flushed (no further opens to drive the flush). It has a
                # real close time and real byte totals — emit it rather than
                # discarding a complete record on a housekeeping technicality.
                self.stats["close_flushed_by_expiry"] += 1
                try:
                    self._emit_closed(k, st)
                except Exception:                            # noqa: BLE001
                    self.stats["close_emit_errors"] += 1
        if stale:
            self.stats["flow_expired"] += len(stale)
        return len(stale)

    # -- classification, driven by measured field shape ---------------------
    @staticmethod
    def _is_open(p):
        return any(k in p for k in ("mss", "rcvwin", "sndwinscale"))

    @staticmethod
    def _is_close(p):
        return "endtime" in p or "startime" in p

    def classify(self, eid, p, proto):
        """-> 'open' | 'close' | 'send' | 'recv' | 'copy' | 'data'.

        Event id FIRST for TCP, because it is measured and the field shapes are
        provably ambiguous (TcpIpSend carries `startime`/`endtime`, which the
        shape test reads as a close). Shapes remain the fallback for anything
        unmeasured — UDP, and any id a future Windows build introduces — so an
        unknown id degrades to the old behaviour rather than being dropped, and
        is COUNTED so the degradation is visible instead of silent.
        """
        if proto == "tcp":
            if eid in TCP_CONNECT_IDS:    return "open"
            if eid in TCP_DISCONNECT_IDS: return "close"
            if eid in TCP_SEND_IDS:       return "send"
            if eid in TCP_RECV_IDS:       return "recv"
            if eid in TCP_COPY_IDS:       return "copy"
            self.stats["tcp_unmapped_event_id"] += 1
        if self._is_open(p):
            return "open"
        if self._is_close(p):
            return "close"
        return "data"

    def _on_network(self, event):
        try:
            eid, p = event[0], event[1]
            if not isinstance(p, dict):
                self.stats["network_malformed"] += 1
                return
            proto = ("udp" if str(p.get("Task Name") or "").endswith("UDPIP") else "tcp")
            saddr, sport = p.get("saddr"), p.get("sport")
            daddr, dport = p.get("daddr"), p.get("dport")
            if saddr is None or daddr is None:
                # Without both endpoints there is no identity to compute. Counted
                # explicitly rather than being keyed under a partial tuple, which
                # would silently merge unrelated connections.
                self.stats["no_endpoints"] += 1
                return
            fkey = flow_key(proto, saddr, sport, daddr, dport)
            kind = self.classify(eid, p, proto)

            if kind == "copy":
                # Measured duplicate of already-counted received data. Counted so
                # its volume stays visible, never added to a byte total.
                self.stats["tcp_copy_ignored"] += 1
                return

            if kind == "open":
                self.stats["open"] += 1
                if self.dns.lookup(daddr)[0] is None:
                    self.stats["open_unattributed"] += 1
                now = self._mono()
                self.flush_closed(now)
                self._expire_flows(now)
                prior = self._flows.get(fkey)
                if prior is not None:
                    # PORT REUSE while the previous connection is still inside its
                    # close grace window. Emit the old one now — otherwise this
                    # open would overwrite it and its bytes would vanish, which is
                    # the original bug wearing the grace window as a disguise.
                    self._flows.pop(fkey)
                    if prior.get("closing") is not None:
                        self.stats["close_flushed_by_reuse"] += 1
                        try:
                            self._emit_closed(fkey, prior)
                        except Exception:                    # noqa: BLE001
                            self.stats["close_emit_errors"] += 1
                    else:
                        # An open for a flow that never closed — the previous
                        # connection's close was missed entirely. Counted, and its
                        # partial byte counts are discarded rather than merged
                        # into the new connection's totals.
                        self.stats["flow_replaced_unclosed"] += 1
                if len(self._flows) >= MAX_FLOWS:
                    self.stats["flow_table_full"] += 1
                    return
                cid = flow_conn_id(fkey, now)
                # At OPEN, saddr is treated as the LOCAL endpoint — that is what
                # direction attribution keys off below. NOT independently verified
                # for inbound/accepted connections (the probe captured outbound
                # browsing traffic only), so an accepted connection may have its
                # send/recv reversed. Recorded as a known limit rather than
                # asserted as correct; fixing it needs a measurement we do not have.
                self._flows[fkey] = {"conn_id": cid, "proto": proto,
                                     "local": _endpoint(saddr, sport),
                                     "sent": 0, "recv": 0, "undirected": 0,
                                     "opened_mono": now, "last_seen": now,
                                     "closing": None}
                _opid = _pid(p.get("PID"))
                _pname, _ppath = self._proc(_opid)
                rec = self.asm.on_open(cid, proto, saddr, _port(sport), daddr,
                                       _port(dport), pid=_opid,
                                       proc_name=_pname, proc_path=_ppath,
                                       consent_version=self.consent_version)
                if rec:
                    self.emit(rec)
                return

            if kind == "close":
                self.stats["close"] += 1
                # Closes are rare relative to data, so driving the flush from here
                # as well as from OPEN is cheap — and it means a burst of closing
                # connections with no new opens still gets emitted promptly.
                self.flush_closed()
                st = self._flows.get(fkey)
                if st is None:
                    # Close for a connection we never saw open. The assembler
                    # counts it as an unmatched close and emits nothing; there is
                    # no id to report because there was no open to derive one from.
                    self.stats["close_unmatched_flow"] += 1
                    self.asm.unmatched_closes += 1
                    return
                if st.get("closing") is None:
                    # DO NOT emit yet, and DO NOT pop. Late data for this exact
                    # connection is still arriving (see CLOSE_GRACE_SECONDS). The
                    # close time is captured NOW so the deferred emission still
                    # reports when the connection really ended.
                    now = self._mono()
                    st["closing"] = now
                    st["close_wall"] = self.asm._wall()
                    st["close_mono"] = now
                    st["close_ep"] = (saddr, _port(sport), daddr, _port(dport))
                    st["close_pid"] = _pid(p.get("PID"))
                    st["last_seen"] = now
                else:
                    # A second close for one connection (retransmitted FIN/RST).
                    # The first close time is the real one; keep it.
                    self.stats["close_duplicate"] += 1
                return

            # Data event — the bulk of volume. Keep this cheap.
            #
            # `size` is NOT always an int: pywintrace decodes some fields as
            # strings. The original `if not isinstance(size, int): return` had no
            # counter, so every data event disappeared silently and bytes came out
            # 0/0 with nothing in the stats to say why. Coerce, and count the
            # genuinely unusable ones so a future decoding change is VISIBLE.
            size = _as_int(p.get("size"))
            if size is None:
                self.stats["data_unusable_size"] += 1
                return
            st = self._flows.get(fkey)
            if st is None:
                # Data for a connection whose open we never saw (started before we
                # did, or UDP — which has no open event at all, so UDP byte totals
                # are structurally unavailable on this path). Counted, not
                # accumulated: attributing it to a connection we cannot describe
                # would invent a record.
                self.stats["data_orphan"] += 1
                return
            # DIRECTION COMES FROM THE EVENT ID FOR TCP — measured, exact.
            #
            # It CANNOT come from the addresses: measured across every campaign
            # run, a TCP event's `saddr` is the connection's LOCAL endpoint
            # regardless of which way the bytes moved (`saddr==remote` never once
            # occurred). Those fields name the CONNECTION, not the packet. The
            # address test therefore answered "outbound" for everything and filed
            # a 4KB download as `sent=8536 recv=0` — inverted and doubled.
            #
            # UDP genuinely does swap saddr/daddr between request and reply
            # (measured on DNS), so the address test is kept there, where it works.
            if kind == "send":
                st["sent"] += size
            elif kind == "recv":
                st["recv"] += size
            elif proto == "udp":
                if _endpoint(saddr, sport) == st["local"]:
                    st["sent"] += size
                else:
                    st["recv"] += size
            else:
                # An unmapped TCP id reaching the data path. Its direction is
                # genuinely unknown, so it is accumulated apart and suppresses the
                # byte fields at close rather than being guessed into one of them.
                st["undirected"] += size
                self.stats["bytes_undirected"] += 1
            st["last_seen"] = self._mono()
            self.stats["data"] += 1
        except Exception:                                    # noqa: BLE001
            self.stats["network_errors"] += 1

    def _on_dns(self, event):
        try:
            _eid, p = event[0], event[1]
            if not isinstance(p, dict):
                return
            name = p.get("QueryName")
            results = p.get("QueryResults")
            if not name or not results:
                self.stats["dns_no_results"] += 1
                return
            addrs = _parse_query_results(results)
            if not addrs:
                self.stats["dns_no_addrs"] += 1
                return
            self.dns.observe(str(name).rstrip("."), addrs)
            self.stats["dns_observed"] += 1
        except Exception:                                    # noqa: BLE001
            self.stats["dns_errors"] += 1

    def _dispatch(self, event):
        """ONE session, both providers, routed by EventHeader.ProviderId.

        MEASURED before being relied on: `EventHeader` is a dict present on
        141/141 events with **zero** missing, and its `ProviderId` carries the
        exact provider GUIDs. So this is attribution by fact, unlike the original
        probe which had to guess from event-id ranges.

        An A/B under identical traffic showed one combined session costs nothing:
        Kernel-Network alone 127 events, Kernel-Network + DNS together 124. (An
        earlier 11,580-event reading was a background-traffic burst, NOT a healthy
        baseline — it briefly looked like the combined session was starving the
        network provider. It was not.)
        """
        try:
            p = event[1]
            if not isinstance(p, dict):
                self.stats["network_malformed"] += 1
                return
            pid_guid = str((p.get("EventHeader") or {}).get("ProviderId") or "").upper()
            if pid_guid == self.KERNEL_NETWORK_GUID.upper():
                self._on_network(event)
            elif pid_guid == self.DNS_CLIENT_GUID.upper():
                self._on_dns(event)
            else:
                # Neither provider we subscribed to. Counted rather than dropped:
                # a silent else is how an attribution bug hides.
                self.stats["unattributed_provider"] += 1
        except Exception:                                    # noqa: BLE001
            self.stats["dispatch_errors"] += 1

    def start(self):
        from etw import ETW, ProviderInfo                    # noqa: PLC0415
        from etw.GUID import GUID                            # noqa: PLC0415
        providers = [
            ProviderInfo(self.KERNEL_NETWORK, GUID(self.KERNEL_NETWORK_GUID),
                         self.LEVEL, self.KW_IPV4 | self.KW_IPV6),
            ProviderInfo(self.DNS_CLIENT, GUID(self.DNS_CLIENT_GUID),
                         self.LEVEL, self.DNS_KEYWORDS),
        ]
        job = ETW(providers=providers, event_callback=self._dispatch)
        job.start()
        self._jobs.append(job)
        return self

    def stop(self):
        # Flush FIRST, and force it: a connection that closed inside the grace
        # window at shutdown has a complete, correct record — dropping it would
        # lose real data for no reason.
        try:
            self.flush_closed(force=True)
        except Exception:                                    # noqa: BLE001
            self.stats["close_emit_errors"] += 1
        for j in self._jobs:
            try:
                j.stop()
            except Exception:                                # noqa: BLE001
                pass
        self._jobs = []


def _as_int(v):
    """int, or a string that is cleanly an int. None otherwise — never a guess."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        t = v.strip()
        if t.isdigit():
            return int(t)
    return None


def _port(v):
    n = _as_int(v)
    return n if n is not None and 0 <= n <= 65535 else 0


def _pid(v):
    n = _as_int(v)
    return n if n is not None and n >= 0 else None


def _parse_query_results(results):
    """Pull IP addresses out of a DNS-Client QueryResults blob.

    Deliberately TOLERANT rather than format-specific: the blob's exact layout was
    not measured (it contains real browsing data, so it is not something to dump
    and eyeball), and it can carry CNAMEs and type prefixes alongside addresses.
    So: split on the usual separators and keep only tokens that genuinely parse as
    an IP. A format change degrades to "no addresses found" — counted as
    `dns_no_addrs` — never to a wrong attribution.
    """
    import ipaddress
    out = []
    for tok in str(results).replace(",", ";").replace(" ", ";").split(";"):
        tok = tok.strip().strip("()[]").rstrip(".")
        if not tok:
            continue
        if tok.lower().startswith("::ffff:"):
            tok = tok[7:]
        try:
            ipaddress.ip_address(tok)
        except ValueError:
            continue
        out.append(tok)
    return out
