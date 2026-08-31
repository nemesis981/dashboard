"""Track C — the agent's ownership of the connection collector.

Run: python3 nemesis_agent/test_conn_wiring.py

⚠ WHAT THIS CAN AND CANNOT PROVE, STATED UP FRONT.
ETW is Windows-only and this suite runs wherever the repo does. It therefore
proves the OWNERSHIP logic — when the collector starts, when it refuses to, what
the drain returns, and what happens when consent is withdrawn mid-session — using
injected fakes in place of the ETW source. It proves NOTHING about whether an ETW
session actually delivers events. That needs a Windows host, and claiming
otherwise from a green run here would be the "instrument that answered from the
wrong place" failure this repo keeps finding.

The three refusal paths are the load-bearing ones: a collector that starts when it
should not is a privacy failure, and one that silently does not start when it
should is indistinguishable from one that started and saw nothing.

ASSERTION COUNT IS FIXED and self-asserted.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config                       # noqa: E402
config.CONF_PATH = os.path.join(tempfile.mkdtemp(prefix="wiring-"), "agent.conf")
import consent                      # noqa: E402
import conn_buffer as cb            # noqa: E402
import conn_events as ce            # noqa: E402
import agent                        # noqa: E402

EXPECTED_CHECKS = 18
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name
          + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


def reset():
    agent._conn_source = None
    agent._conn_buffer = None
    try:
        os.remove(consent.state_path())
    except FileNotFoundError:
        pass


class FakeSource:
    """Stands in for EtwSource: same three methods the owner actually calls."""
    def __init__(self):
        self.stopped = False
        self.flushed = 0

    def flush_closed(self, now=None, force=False):
        self.flushed += 1
        return 0

    def stop(self):
        self.stopped = True


print("REFUSAL PATHS — the collector must not start when it should not")
reset()
agent._start_conn_collector({"conn_events_enabled": "false", "device_id": "d"})
check("flag OFF (the default) -> not started", agent._conn_source is None)

reset()
agent._start_conn_collector({"device_id": "d"})
check("flag ABSENT -> not started (defaults off, not on)",
      agent._conn_source is None)

reset()
_real_platform = agent._platform_name
agent._platform_name = "Linux"
agent._start_conn_collector({"conn_events_enabled": "true", "device_id": "d"})
check("flag ON but no event source for this platform -> not started",
      agent._conn_source is None)

reset()
agent._platform_name = "Windows"
consent.set_enabled(consent.ITEM_CONNECTIONS, False, device_id="d")
agent._start_conn_collector({"conn_events_enabled": "true", "device_id": "d"})
check("⭐ flag ON + Windows but consent OFF -> not started",
      agent._conn_source is None)
agent._platform_name = _real_platform

print("\nDRAIN when nothing is running")
reset()
check("drain with no collector returns {}", agent._drain_conn_events() == {})

print("\nDRAIN with an injected source + buffer")
reset()
buf = cb.ConnBuffer(cap=cb.MIN_CAP)
src = FakeSource()
agent._conn_source, agent._conn_buffer = src, buf
check("empty buffer -> {} (nothing to say)", agent._drain_conn_events() == {})
check("drain flushed closed flows first", src.flushed >= 1)

buf.put({"e": 1}); buf.put({"e": 2})
out = agent._drain_conn_events()
check("records ride the server's payload key",
      out.get(ce.PAYLOAD_KEY) == [{"e": 1}, {"e": 2}], str(out)[:60])
check("buffer is emptied by the drain", len(buf) == 0)
check("no drop key when nothing dropped", "connection_events_dropped" not in out)

print("\n⭐ DROPS are reported, and reported ONCE")
for i in range(cb.MIN_CAP + 5):
    buf.put({"e": i})
out = agent._drain_conn_events()
check("⭐ drop count is in the payload", out.get("connection_events_dropped") == 5,
      str(out.get("connection_events_dropped")))
buf.put({"e": "x"})
out2 = agent._drain_conn_events()
check("⭐ the same drop is not reported twice",
      "connection_events_dropped" not in out2)

print("\n⭐ CONSENT WITHDRAWN MID-SESSION")
reset()
buf = cb.ConnBuffer(cap=cb.MIN_CAP)
src = FakeSource()
agent._conn_source, agent._conn_buffer = src, buf
buf.put({"e": 1}); buf.put({"e": 2})
consent.set_enabled(consent.ITEM_CONNECTIONS, False, device_id="d")
out = agent._drain_conn_events()
check("⭐ withdrawal ships NOTHING, not the backlog", out == {}, str(out)[:60])
check("⭐ buffered events were discarded, not held", len(buf) == 0)
check("⭐ the source was stopped", src.stopped is True)
check("⭐ ownership was released", agent._conn_source is None
      and agent._conn_buffer is None)

print("\nSTOP is safe when never started")
reset()
agent._stop_conn_collector()
check("stop with no collector does not raise", True)

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
