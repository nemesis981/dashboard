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
                 consent_version=None):
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
            ts_close_wall=self._wall(), ts_close_mono=self._mono(),
            pid=pid, proc_name=proc_name, proc_path=proc_path, proc_signed=proc_signed,
            bytes_sent=bytes_sent, bytes_recv=bytes_recv,
            resolved_name=name, resolved_name_source=src)

    def open_count(self):
        return len(self._open)


def collection_permitted():
    """THE gate, re-exported so the collector has exactly one thing to call.

    Requirement 0 clause 4: one gate. This wrapper exists so a caller cannot be
    tempted to hand-roll a consent check, and so the consent version used to
    stamp records comes from the same read that authorised collection.
    """
    return consent.collection_allowed(), consent.consent_version()


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
      * **Every Kernel-Network event carries `connid`** — a real per-connection
        identifier. We do NOT synthesise one from the 5-tuple, which would be
        ambiguous under port reuse.
      * `size` appears on data events, never as a per-connection total, so bytes
        MUST be accumulated. Data events are **96% of volume** (ids 11 and 27
        alone were 11,111 of 11,580), so their handler is deliberately a dict
        increment and nothing more.
      * `Task Name` distinguishes only `KERNEL_NETWORK_TASK_TCPIP` from
        `..._UDPIP` — it does NOT identify connect/send/recv/close.

    WHY CLASSIFY BY FIELD SHAPE RATHER THAN EVENT ID. The event-id → operation
    mapping was never measured; `Task Name` cannot supply it, and a hardcoded id
    table would be a guess that also risks differing across Windows builds. The
    field shapes ARE measured and are self-describing:
      * TCP handshake options (`mss`/`rcvwin`/`sndwinscale`) => connection OPEN
      * `startime`/`endtime`                                 => connection CLOSE
      * otherwise, has `size`                                => data, accumulate
    If a future build changes the shapes, this degrades to "no opens detected",
    which is visible in the counters below — not to silently mislabelled events.

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

    def __init__(self, assembler, dns_cache, consent_version, emit):
        self.asm = assembler
        self.dns = dns_cache
        self.consent_version = consent_version
        self.emit = emit
        self._jobs = []
        self._bytes = {}           # connid -> [sent, recv]
        self._local = {}           # connid -> (laddr, lport)
        self.stats = Counter()

    # -- classification, driven by measured field shape ---------------------
    @staticmethod
    def _is_open(p):
        return any(k in p for k in ("mss", "rcvwin", "sndwinscale"))

    @staticmethod
    def _is_close(p):
        return "endtime" in p or "startime" in p

    def _on_network(self, event):
        try:
            _eid, p = event[0], event[1]
            if not isinstance(p, dict):
                self.stats["network_malformed"] += 1
                return
            cid = p.get("connid")
            if cid is None:
                self.stats["no_connid"] += 1
                return
            # NORMALISE THE KEY. pywintrace decodes the same field as int on some
            # events and str on others (the same inconsistency that made `size`
            # vanish). Keying the accumulator on the raw value meant an open
            # recorded under 7 was never found by data arriving as "7" — every data
            # event became an orphan and bytes stayed 0. Measured: 117 orphans, 0
            # attributed, on a run with 4 healthy opens.
            cid = str(cid)
            proto = ("udp" if str(p.get("Task Name") or "").endswith("UDPIP") else "tcp")
            saddr, sport = p.get("saddr"), p.get("sport")
            daddr, dport = p.get("daddr"), p.get("dport")

            if self._is_open(p):
                self.stats["open"] += 1
                if self.dns.lookup(daddr)[0] is None:
                    self.stats["open_unattributed"] += 1
                self._local[cid] = (saddr, sport)
                self._bytes[cid] = [0, 0]
                rec = self.asm.on_open(str(cid), proto, saddr, _port(sport), daddr,
                                       _port(dport), pid=_pid(p.get("PID")),
                                       consent_version=self.consent_version)
                if rec:
                    self.emit(rec)
                return

            if self._is_close(p):
                self.stats["close"] += 1
                sent, recv = self._bytes.pop(cid, [None, None])
                self._local.pop(cid, None)
                rec = self.asm.on_close(str(cid), proto, saddr, _port(sport), daddr,
                                        _port(dport), pid=_pid(p.get("PID")),
                                        bytes_sent=sent, bytes_recv=recv,
                                        consent_version=self.consent_version)
                if rec:
                    self.emit(rec)
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
            acc = self._bytes.get(cid)
            if acc is None:
                # Data for a connection whose open we never saw (started before we
                # did). Counted, not accumulated — attributing it to a connection
                # we cannot describe would invent a record.
                self.stats["data_orphan"] += 1
                return
            # Direction from the addresses, NOT from the event id: if this event's
            # source matches the connection's local endpoint it is outbound. The id
            # -> send/recv mapping was never measured, so it is not relied on.
            local = self._local.get(cid)
            if local and saddr == local[0] and sport == local[1]:
                acc[0] += size
            else:
                acc[1] += size
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
