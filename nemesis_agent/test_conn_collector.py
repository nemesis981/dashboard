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
print("EtwSource classifies by measured field shape, not by an event-id guess")
emitted = []
dns2 = cc.DnsCache(available=True, clock=Clock())
asm4 = cc.ConnectionAssembler("dev-1", dns_cache=dns2, clock_wall=wall, clock_mono=Clock())
src = cc.EtwSource.__new__(cc.EtwSource)      # no ETW session; handlers only
src.asm, src.dns, src.consent_version = asm4, dns2, 1
src.emit = emitted.append
src._bytes, src._local = {}, {}
src.stats = cc.Counter()

OPEN = {"connid": 7, "Task Name": "KERNEL_NETWORK_TASK_TCPIP", "PID": 42,
        "saddr": "192.0.2.10", "sport": 51000, "daddr": "198.51.100.20", "rport": 0,
        "dport": 443, "size": 0, "mss": 1460, "rcvwin": 65535, "sndwinscale": 8}
src._on_network((28, OPEN))
check("handshake-option fields => OPEN", src.stats["open"] == 1 and len(emitted) == 1)
check("  emitted record is schema-valid", ce.validate(emitted[0])[0])
check("  conn_id comes from ETW's connid, not a synthesised 5-tuple",
      emitted[0]["conn_id"] == "7")

DATA_OUT = dict(OPEN); [DATA_OUT.pop(k) for k in ("mss", "rcvwin", "sndwinscale")]
DATA_OUT["size"] = 500
src._on_network((11, DATA_OUT))
DATA_IN = dict(DATA_OUT)
DATA_IN["saddr"], DATA_IN["sport"] = "198.51.100.20", 443     # remote is the source
DATA_IN["daddr"], DATA_IN["dport"] = "192.0.2.10", 51000
DATA_IN["size"] = 1200
src._on_network((11, DATA_IN))
check("data events accumulate rather than emit", len(emitted) == 1 and src.stats["data"] == 2)
check("  accumulator is keyed by STRING connid (pywintrace decodes it both ways)",
      "7" in src._bytes and 7 not in src._bytes)
check("  direction from ADDRESSES: outbound summed to sent",
      src._bytes["7"][0] == 500, "sent=%r" % src._bytes["7"][0])
check("  inbound summed to recv", src._bytes["7"][1] == 1200, "recv=%r" % src._bytes["7"][1])

CLOSE = dict(DATA_OUT); CLOSE["startime"] = 1; CLOSE["endtime"] = 2
src._on_network((26, CLOSE))
check("startime/endtime => CLOSE", src.stats["close"] == 1 and len(emitted) == 2)
close_rec = emitted[1]
check("  close carries the ACCUMULATED byte totals",
      close_rec["bytes_sent"] == 500 and close_rec["bytes_recv"] == 1200)
check("  and is schema-valid", ce.validate(close_rec)[0])
check("  accumulator freed on close", "7" not in src._bytes)

print("data for a connection we never saw open is counted, not attributed")
ORPHAN = dict(DATA_OUT); ORPHAN["connid"] = 999
src._on_network((11, ORPHAN))
check("orphan data counted", src.stats["data_orphan"] == 1)
check("  and no phantom accumulator created", "999" not in src._bytes)

print("malformed network events degrade to counters, never exceptions")
src._on_network((11, "not-a-dict"))
check("non-dict payload counted", src.stats["network_malformed"] == 1)
src._on_network((11, {"size": 5}))
check("missing connid counted", src.stats["no_connid"] == 1)

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
