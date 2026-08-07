"""Track C step 4 — the platform-independent collection core.

Run: python3 nemesis_agent/test_conn_collector.py

Covers the DNS correlation cache, the open/close assembler, and `EtwSource`'s
event-handling logic — which is exercised with synthetic payloads shaped like the
ones actually measured on the probe VM. The ETW *session* still requires Windows
and is verified separately, live, against that VM.

Clocks are injected so expiry is tested deterministically rather than by
sleeping, which would make the suite slow and flaky in exchange for nothing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import conn_events as ce            # noqa: E402
import conn_collector as cc         # noqa: E402

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


# ------------------------------------------------------------------ DNS cache
print("DnsCache — provenance distinguishes 'cannot see' from 'saw nothing'")
clk = Clock()
unavailable = cc.DnsCache(available=False, clock=clk)
n, s = unavailable.lookup("198.51.100.20")
check("platform cannot observe DNS -> (None, unavailable)",
      n is None and s == ce.NAME_SRC_UNAVAILABLE)
unavailable.observe("example.test", ["198.51.100.20"])
n, s = unavailable.lookup("198.51.100.20")
check("  and observe() is inert when unavailable (no phantom names)",
      n is None and s == ce.NAME_SRC_UNAVAILABLE)

cache = cc.DnsCache(available=True, ttl=600, clock=clk)
n, s = cache.lookup("198.51.100.20")
check("watching but nothing seen -> (None, no_dns_observed)",
      n is None and s == ce.NAME_SRC_NONE)
cache.observe("example.test", ["198.51.100.20", "198.51.100.21"])
n, s = cache.lookup("198.51.100.20")
check("after observing -> (name, os_dns_event)",
      n == "example.test" and s == ce.NAME_SRC_DNS_EVENT)
check("  every address in the answer is mapped",
      cache.lookup("198.51.100.21")[0] == "example.test")
check("  an address NOT in the answer is still unattributed",
      cache.lookup("203.0.113.99")[0] is None)

print("expiry: a stale mapping is dropped, not served")
clk.advance(599)
check("just inside the TTL -> still attributed",
      cache.lookup("198.51.100.20")[0] == "example.test")
clk.advance(2)
n, s = cache.lookup("198.51.100.20")
check("past the TTL -> (None, no_dns_observed), NOT a stale name",
      n is None and s == ce.NAME_SRC_NONE)
check("  and the expired entry is evicted, not left to accumulate", len(cache) == 1)

print("last-writer-wins when several names share one address (the CDN case)")
c2 = cc.DnsCache(available=True, clock=Clock())
c2.observe("first.test", ["198.51.100.30"])
c2.observe("second.test", ["198.51.100.30"])
check("most recent observation wins", c2.lookup("198.51.100.30")[0] == "second.test")

print("the cache is bounded and reports its evictions")
c3 = cc.DnsCache(available=True, max_entries=10, clock=Clock())
for i in range(25):
    c3.observe("h%d.test" % i, ["198.51.100.%d" % i])
check("size is capped", len(c3) <= 10, "len=%d" % len(c3))
check("evictions are COUNTED, not silent", c3.evictions == 15, "evictions=%d" % c3.evictions)

# ------------------------------------------------------------------ assembler
print("ConnectionAssembler — open/close pairing")
clk2 = Clock()
wall = lambda: "2026-08-07T12:00:00-0500"                      # noqa: E731
dns = cc.DnsCache(available=True, clock=clk2)
dns.observe("example.test", ["198.51.100.20"])
asm = cc.ConnectionAssembler("dev-1", dns_cache=dns, clock_wall=wall, clock_mono=clk2)

op = asm.on_open("c-1", "tcp", "192.0.2.10", 51000, "198.51.100.20", 443,
                 pid=42, proc_name="curl", consent_version=1)
check("open event is schema-valid", ce.validate(op)[0], "; ".join(ce.validate(op)[1]))
check("  and carries the resolved name", op["resolved_name"] == "example.test")
check("  with os_dns_event provenance", op["resolved_name_source"] == ce.NAME_SRC_DNS_EVENT)
check("  connection is tracked as open", asm.open_count() == 1)

clk2.advance(9.5)
cl = asm.on_close("c-1", "tcp", "192.0.2.10", 51000, "198.51.100.20", 443,
                  pid=42, proc_name="curl", bytes_sent=120, bytes_recv=4096,
                  consent_version=1)
check("close event is schema-valid", ce.validate(cl)[0], "; ".join(ce.validate(cl)[1]))
d, src = ce.duration_seconds(cl)
check("  duration comes from the tracked open", abs(d - 9.5) < 1e-9 and src == "monotonic")
check("  bytes are carried through", cl["bytes_sent"] == 120 and cl["bytes_recv"] == 4096)
check("  and the connection is no longer tracked", asm.open_count() == 0)

print("a close with no matching open is counted, never fabricated")
res = asm.on_close("c-NEVER-OPENED", "tcp", "192.0.2.10", 5, "198.51.100.20", 443,
                   consent_version=1)
check("returns None rather than inventing a ts_open", res is None)
check("  and is counted", asm.unmatched_closes == 1)

print("unattributed destinations degrade honestly")
asm2 = cc.ConnectionAssembler("dev-1", dns_cache=cc.DnsCache(available=False),
                              clock_wall=wall, clock_mono=Clock())
op2 = asm2.on_open("c-2", "tcp", "192.0.2.10", 5, "203.0.113.50", 443, consent_version=1)
check("no DNS capability -> name None, provenance 'unavailable'",
      op2["resolved_name"] is None and op2["resolved_name_source"] == ce.NAME_SRC_UNAVAILABLE)
check("  and the record is still valid (absence is representable)", ce.validate(op2)[0])

print("the open table is bounded")
asm3 = cc.ConnectionAssembler("dev-1", clock_wall=wall, clock_mono=Clock())
asm3.MAX_OPEN = 5
made = [asm3.on_open("c-%d" % i, "tcp", "192.0.2.10", 5, "203.0.113.5", 443,
                     consent_version=1) for i in range(8)]
check("stops tracking past the cap", asm3.open_count() == 5)
check("  overflow returns None rather than a partial record",
      made[5] is None and made[6] is None)
check("  and overflow is COUNTED", asm3.dropped_open_overflow == 3,
      "n=%d" % asm3.dropped_open_overflow)

# ----------------------------------------------- EtwSource ships measured config
print("EtwSource carries the MEASURED provider configuration, not defaults")
check("keywords narrowed to IPV4|IPV6 = 0x30",
      (cc.EtwSource.KW_IPV4 | cc.EtwSource.KW_IPV6) == 0x30)
check("level is 4 (informational), not the probe's verbose 5", cc.EtwSource.LEVEL == 4)
check("DNS keywords left wide, deliberately (measured ~4 events/sec)",
      cc.EtwSource.DNS_KEYWORDS == 0xFFFFFFFFFFFFFFFF)
check("both provider GUIDs are pinned",
      cc.EtwSource.KERNEL_NETWORK_GUID.startswith("{7DD42A49")
      and cc.EtwSource.DNS_CLIENT_GUID.startswith("{1C95126E"))

# ------------------------------------------------------- EtwSource event logic
print("EtwSource classifies by MEASURED EVENT ID; field shape is only a fallback")
emitted = []
dns2 = cc.DnsCache(available=True, clock=Clock())
asm4 = cc.ConnectionAssembler("dev-1", dns_cache=dns2, clock_wall=wall, clock_mono=Clock())
flow_clock = Clock()
src = cc.EtwSource.__new__(cc.EtwSource)      # no ETW session; handlers only
src.asm, src.dns, src.consent_version = asm4, dns2, 1
src.emit = emitted.append
src._flows = {}
src._mono = flow_clock
src.stats = cc.Counter()

# ⚠ EVERY EVENT BELOW CARRIES `connid: "0"`. That is the MEASURED production
# value — one distinct value across all 211 probe events. The previous version of
# this suite used connid 7 and 999, i.e. it assumed the very thing that turned out
# to be false, which is exactly why it passed while production emitted bytes_* of
# None on every record and conn_id "0" on every record. A fixture that supplies
# the identity the code is supposed to derive cannot detect that it never derived
# one, so these fixtures now supply what ETW really sends.
OPEN = {"connid": "0", "Task Name": "KERNEL_NETWORK_TASK_TCPIP", "PID": 42,
        "saddr": "192.0.2.10", "sport": 51000, "daddr": "198.51.100.20", "rport": 0,
        "dport": 443, "size": 0, "mss": 1460, "rcvwin": 65535, "sndwinscale": 8}
src._on_network((28, OPEN))
check("handshake-option fields => OPEN", src.stats["open"] == 1 and len(emitted) == 1)
check("  emitted record is schema-valid", ce.validate(emitted[0])[0])
open_cid = emitted[0]["conn_id"]
check("  conn_id is DERIVED, not ETW's useless connid",
      open_cid not in ("0", 0, "", None), "conn_id=%r" % open_cid)
check("  and is a bounded, non-empty string", isinstance(open_cid, str)
      and 0 < len(open_cid) <= 64)

# ⚠ DIRECTION COMES FROM THE EVENT ID, MEASURED EXACTLY. Campaign 2026-08-07
# against a LAN rig with known byte counts: upload run gave id=10 total 65536 =
# 1.000x really-sent and id=11 total 1024 = 1.000x really-recv; download run gave
# id=11 total 65536 = 1.000x really-recv. Addresses cannot express TCP direction —
# `saddr` is the connection's LOCAL endpoint on EVERY event, never once the
# remote, so the old address test answered "outbound" for everything and filed a
# 4KB download as sent=8536 recv=0.
DATA_OUT = dict(OPEN); [DATA_OUT.pop(k) for k in ("mss", "rcvwin", "sndwinscale")]
DATA_OUT["size"] = 500
src._on_network((10, DATA_OUT))                    # id 10 = TcpIpSend
DATA_IN = dict(DATA_OUT)
DATA_IN["saddr"], DATA_IN["sport"] = "198.51.100.20", 443     # remote is the source
DATA_IN["daddr"], DATA_IN["dport"] = "192.0.2.10", 51000
DATA_IN["size"] = 1200
src._on_network((11, DATA_IN))                     # id 11 = TcpIpRecv
check("data events accumulate rather than emit", len(emitted) == 1 and src.stats["data"] == 2)
fk = cc.flow_key("tcp", "192.0.2.10", 51000, "198.51.100.20", 443)
check("  the flow table is keyed by 5-tuple, not by connid",
      list(src._flows) == [fk], "keys=%r" % list(src._flows))
check("  TcpIpSend (id 10) -> bytes_sent", src._flows[fk]["sent"] == 500,
      "sent=%r" % src._flows[fk]["sent"])
check("  TcpIpRecv (id 11) -> bytes_recv", src._flows[fk]["recv"] == 1200,
      "recv=%r" % src._flows[fk]["recv"])
check("  nothing landed in the undirected bucket",
      src._flows[fk]["undirected"] == 0)
# The send event's ADDRESSES say "local is the source" and the recv event's say
# the same — that is exactly why addresses cannot decide direction. Pin it: both
# events above carried a local-looking saddr, yet split correctly by id.
check("  REGRESSION: direction survived despite both events looking outbound",
      src._flows[fk]["sent"] == 500 and src._flows[fk]["recv"] == 1200)

print("TcpIpTCPCopy is a measured DUPLICATE and must never be counted")
# Measured: id 18 reported 43800 of 65536 already-counted received bytes — a
# partial duplicate, so including it inflates recv by a per-connection amount
# that cannot be corrected for afterwards.
COPY = dict(DATA_IN); COPY["size"] = 9999
src._on_network((18, COPY))
check("copy event ignored for byte totals", src._flows[fk]["recv"] == 1200)
check("  and counted so its volume stays visible",
      src.stats["tcp_copy_ignored"] == 1)

print("the flow key is direction-agnostic — a send and its reply are ONE flow")
# If it were not, the reply would file under a second key, match no open, and be
# counted as an orphan — the orphaning bug in a new costume.
check("send and reply produce the same key",
      cc.flow_key("tcp", "192.0.2.10", 51000, "198.51.100.20", 443)
      == cc.flow_key("tcp", "198.51.100.20", 443, "192.0.2.10", 51000))
check("  a different port is a different flow",
      cc.flow_key("tcp", "192.0.2.10", 51001, "198.51.100.20", 443) != fk)
check("  a different protocol is a different flow",
      cc.flow_key("udp", "192.0.2.10", 51000, "198.51.100.20", 443) != fk)
check("  ports compare as ints, not as decoded-type accidents",
      cc.flow_key("tcp", "192.0.2.10", "51000", "198.51.100.20", "443") == fk)

print("CLOSE is DEFERRED — ETW delivers data AFTER the close it follows")
# THE MEASURED FACT THIS ENCODES (probe VM, 2026-08-07): ETW events come from
# per-processor buffers and are NOT globally time-ordered, so a connection's close
# routinely arrives before data events that logically preceded it. Popping the
# accumulator on close therefore threw the bytes away every time — instrumented
# live: 29 data orphans and 0 bytes attributed on a connection that really moved
# ~4KB, with the orphans' flow key exactly matching the open that had just been
# popped. Emission is deferred by CLOSE_GRACE_SECONDS so late data still lands.
print("REGRESSION: a SEND is not a close, even though it carries startime/endtime")
# THE BUG THAT CAUSED EVERYTHING. TcpIpSend carries `startime` AND `endtime` —
# measured — so the old shape test classified every send as a connection close.
# The first send therefore "closed" the connection, popping the accumulator, and
# all later data orphaned. bytes_sent could never be non-zero.
SEND_LOOKS_LIKE_CLOSE = dict(DATA_OUT)
SEND_LOOKS_LIKE_CLOSE["startime"] = 1814599
SEND_LOOKS_LIKE_CLOSE["endtime"] = 1814600
SEND_LOOKS_LIKE_CLOSE["size"] = 300
check("the shape test alone WOULD call it a close (the trap)",
      cc.EtwSource._is_close(SEND_LOOKS_LIKE_CLOSE), True)
src._on_network((10, SEND_LOOKS_LIKE_CLOSE))
check("  but id 10 classifies it as a SEND", src.stats["close"] == 0,
      "close=%r" % src.stats["close"])
check("  its bytes went to sent", src._flows[fk]["sent"] == 800,
      "sent=%r" % src._flows[fk]["sent"])
check("  and the connection is still open", fk in src._flows)

CLOSE = dict(DATA_OUT); CLOSE["startime"] = 1; CLOSE["endtime"] = 2
src._on_network((13, CLOSE))                       # id 13 = TcpIpDisconnect
check("TcpIpDisconnect (id 13) => CLOSE recognised", src.stats["close"] == 1)
check("  but NOT emitted yet (grace window open)", len(emitted) == 1)
check("  and the flow is retained so late data can still land", fk in src._flows)

LATE = dict(DATA_IN); LATE["size"] = 700          # arriving after the close
src._on_network((11, LATE))
check("data arriving AFTER the close still accumulates",
      src._flows[fk]["recv"] == 1200 + 700, "recv=%r" % src._flows[fk]["recv"])

flow_clock.t += cc.CLOSE_GRACE_SECONDS + 0.1
n = src.flush_closed()
check("flush after the grace window emits the close", n == 1 and len(emitted) == 2)
close_rec = emitted[1]
check("  REAL byte totals, both directions, including the late data",
      close_rec["bytes_sent"] == 800 and close_rec["bytes_recv"] == 1900,
      "sent=%r recv=%r" % (close_rec["bytes_sent"], close_rec["bytes_recv"]))
check("  and is schema-valid", ce.validate(close_rec)[0])
check("  OPEN and CLOSE share one conn_id (server-side pairing works)",
      close_rec["conn_id"] == open_cid)
check("  flow freed once emitted", fk not in src._flows)

print("the deferred close reports the REAL close time, not the flush time")
# Defaulting ts_close to "now" at flush time would inflate every duration by the
# grace window — a silent, uniform measurement error.
asm_c = cc.ConnectionAssembler("dev-t", clock_wall=lambda: "WALL-NOW",
                               clock_mono=lambda: 999.0)
asm_c.on_open("c1", "tcp", "10.0.0.1", 1, "10.0.0.2", 2, consent_version=1)
rec_t = asm_c.on_close("c1", "tcp", "10.0.0.1", 1, "10.0.0.2", 2, consent_version=1,
                       ts_close_wall="WALL-AT-CLOSE", ts_close_mono=1002.5)
check("supplied close timestamps are used verbatim",
      rec_t["ts_close_wall"] == "WALL-AT-CLOSE" and rec_t["ts_close_mono"] == 1002.5)
asm_c.on_open("c2", "tcp", "10.0.0.1", 1, "10.0.0.2", 2, consent_version=1)
rec_d = asm_c.on_close("c2", "tcp", "10.0.0.1", 1, "10.0.0.2", 2, consent_version=1)
check("  CONTROL: a caller supplying none still gets the clock's 'now'",
      rec_d["ts_close_wall"] == "WALL-NOW" and rec_d["ts_close_mono"] == 999.0)

print("port reuse: the same 5-tuple twice gets two DIFFERENT conn_ids")
# This is the ambiguity that made ETW's connid look preferable in the first place.
flow_clock.t += 10
src._on_network((28, dict(OPEN)))
reuse_cid = emitted[2]["conn_id"]
check("second connection on the identical 5-tuple", len(emitted) == 3)
check("  gets a distinct conn_id (open timestamp folded in)",
      reuse_cid != open_cid, "first=%r second=%r" % (open_cid, reuse_cid))
src._on_network((13, dict(CLOSE)))
flow_clock.t += cc.CLOSE_GRACE_SECONDS + 0.1
src.flush_closed()
check("  and its close pairs with ITS open, not the earlier one",
      emitted[3]["conn_id"] == reuse_cid)

print("port reuse DURING the grace window flushes the old connection first")
# Otherwise the new open overwrites a closed-but-unflushed flow and its bytes
# vanish — the original bug wearing the grace window as a disguise.
flow_clock.t += 10
src._on_network((28, dict(OPEN)))
first_reuse = emitted[-1]["conn_id"]
src._on_network((10, dict(DATA_OUT)))            # 500 bytes out
src._on_network((13, dict(CLOSE)))               # closed, still inside grace
n_before = len(emitted)
src._on_network((28, dict(OPEN)))                # reuse, before the grace elapsed
check("the old connection was flushed by the reuse",
      src.stats["close_flushed_by_reuse"] == 1)
flushed = [r for r in emitted[n_before:] if r["event"] == "close"]
check("  its close was emitted rather than silently overwritten",
      len(flushed) == 1,
      "%r" % ([(r["event"], r.get("bytes_sent")) for r in emitted[n_before:]],))
check("  and it kept its OWN conn_id", flushed[0]["conn_id"] == first_reuse)
src._on_network((13, dict(CLOSE)))
src.flush_closed(force=True)

print("idle flows are expired rather than leaking forever")
src._on_network((28, dict(OPEN)))
check("a flow is tracked", len(src._flows) == 1)
flow_clock.t += cc.FLOW_IDLE_TIMEOUT_SECONDS + 1
OTHER = dict(OPEN); OTHER["sport"] = 51002
src._on_network((28, OTHER))          # an OPEN triggers the sweep
check("the idle flow was expired", src.stats["flow_expired"] == 1,
      "expired=%r" % src.stats["flow_expired"])
check("  and the fresh one survives", len(src._flows) == 1)

print("UDP direction DOES work — measured to genuinely swap saddr/daddr")
# The counterpart control. UDP request/reply really do carry opposite addresses
# (measured: DNS to :53 showed both orientations), so the address test is kept
# for UDP. Without this check the code would look like it had simply given up on
# direction everywhere, rather than declining it only where it is undecidable.
ufk = cc.flow_key("udp", "192.0.2.10", 53001, "192.0.2.53", 53)
src._flows[ufk] = {"conn_id": "u1", "proto": "udp",
                   "local": cc._endpoint("192.0.2.10", 53001),
                   "sent": 0, "recv": 0, "undirected": 0,
                   "opened_mono": flow_clock.t, "last_seen": flow_clock.t,
                   "closing": None}
UDP_OUT = {"connid": "0", "Task Name": "KERNEL_NETWORK_TASK_UDPIP",
           "saddr": "192.0.2.10", "sport": 53001,
           "daddr": "192.0.2.53", "dport": 53, "size": 30}
UDP_IN = dict(UDP_OUT)
UDP_IN["saddr"], UDP_IN["sport"] = "192.0.2.53", 53
UDP_IN["daddr"], UDP_IN["dport"] = "192.0.2.10", 53001
UDP_IN["size"] = 46
src._on_network((42, UDP_OUT))
src._on_network((43, UDP_IN))
check("UDP outbound summed to sent", src._flows[ufk]["sent"] == 30,
      "sent=%r" % src._flows[ufk]["sent"])
check("  UDP inbound summed to recv", src._flows[ufk]["recv"] == 46,
      "recv=%r" % src._flows[ufk]["recv"])
check("  and nothing went to the undirected bucket",
      src._flows[ufk]["undirected"] == 0)
del src._flows[ufk]

print("data for a connection we never saw open is counted, not attributed")
before = src.stats["data_orphan"]
ORPHAN = dict(DATA_OUT); ORPHAN["sport"] = 59999
src._on_network((11, ORPHAN))
check("orphan data counted", src.stats["data_orphan"] == before + 1)
check("  and no phantom flow created",
      cc.flow_key("tcp", "192.0.2.10", 59999, "198.51.100.20", 443) not in src._flows)

print("a close with no matching open emits nothing and is counted")
before_unmatched = src.stats["close_unmatched_flow"]
STRAY = dict(CLOSE); STRAY["sport"] = 58888
n_before = len(emitted)
src._on_network((13, STRAY))
check("unmatched close counted", src.stats["close_unmatched_flow"] == before_unmatched + 1)
check("  and NOT emitted (a fabricated ts_open would be an invented measurement)",
      len(emitted) == n_before)

print("malformed network events degrade to counters, never exceptions")
src._on_network((11, "not-a-dict"))
check("non-dict payload counted", src.stats["network_malformed"] == 1)
src._on_network((11, {"size": 5}))
check("missing endpoints counted", src.stats["no_endpoints"] == 1)

print("DNS QueryResults parsing is tolerant and never invents an address")
check("mixed blob -> only real IPs",
      cc._parse_query_results("type: 5 cname.example.test;::ffff:198.51.100.7;203.0.113.9;")
      == ["198.51.100.7", "203.0.113.9"])
check("no addresses in blob -> empty, not a guess",
      cc._parse_query_results("type: 5 alias.example.test;") == [])
check("garbage -> empty", cc._parse_query_results("!!!") == [])
check("None-ish -> empty", cc._parse_query_results("") == [])

src2 = cc.EtwSource.__new__(cc.EtwSource)
src2.dns, src2.stats = dns2, cc.Counter()
src2._on_dns((3008, {"QueryName": "example.test.",
                     "QueryResults": "::ffff:198.51.100.77;"}))
check("DNS event feeds the cache", dns2.lookup("198.51.100.77")[0] == "example.test")
check("  trailing dot stripped from the name", src2.stats["dns_observed"] == 1)
src2._on_dns((3016, {"QueryName": "noresults.test", "QueryResults": ""}))
check("event without results counted, not observed", src2.stats["dns_no_results"] == 1)
src2._on_dns((3008, {"QueryName": "cnameonly.test", "QueryResults": "type: 5 x.test;"}))
check("results with no parseable IP counted", src2.stats["dns_no_addrs"] == 1)

print()
print("%d/%d passed" % (passed, passed + failed))
sys.exit(1 if failed else 0)
