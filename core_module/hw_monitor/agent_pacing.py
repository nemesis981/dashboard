"""Token-bucket pacing for the :5001 agent channel.

Staged 2026-07-29 (Window 3). NOT DEPLOYED.

Replaces the deferred `ufw limit 5001/tcp` hard cap. The difference is the whole
point:

  ufw limit  — counts CONNECTIONS in a window and BLOCKS the source once the
               count is exceeded. The threshold has to be picked in advance, and
               a legitimate fleet behind one NAT address shares that budget, so
               any value safe for a big fleet is useless against a flood and any
               value tight enough to matter locks out a big fleet. Fleet size
               varies per deployment, so no safe constant exists.

  this        — PACES delivery. Normal traffic passes with zero added latency.
               Traffic above the sustained rate is DELAYED (smoothed), not
               refused. Only traffic so far above the rate that smoothing it
               would exceed `max_delay` is shed with 429 + Retry-After. A fleet
               that sends steadily is never penalised; a flood is throttled.

── DEPENDS ON ThreadingHTTPServer ────────────────────────────────────────────
Pacing works by SLEEPING in the request handler. Under the single-threaded
`HTTPServer` this channel used before 2026-07-29, sleeping in a handler blocks
the whole listener — the limiter would itself become the denial of service it
exists to prevent. This module is only safe alongside the ThreadingHTTPServer
change staged in the same batch. **Ship both or neither.**

── TUNING (read before changing the defaults) ────────────────────────────────
The only input that matters is how many agents share one source address as far
as this server can see. Agents on the tailnet each have their own address; LAN
agents behind one NAT all look like a single source.

    required_rate  >=  (agents_behind_one_address / POLL_INTERVAL) * safety
    required_burst >=  agents_behind_one_address

POLL_INTERVAL is 300s (`nemesis_agent/agent.py:POLL_INTERVAL_DEFAULT`,
`hw_monitor.SAMPLE_INTERVAL`). So 100 agents behind one NAT generate ~0.33 req/s
sustained. The default rate of 5.0/s covers ~1500 such agents with a 3x margin.

`burst` exists for the thundering herd: after a power cut or a network flap,
every agent behind that address retries at once. burst must exceed that count or
the herd is paced (correct but slow) instead of absorbed (correct and instant).
Default 120 absorbs a 120-agent simultaneous wake-up with zero delay.

Raise `burst` first if a real fleet sees delays; raise `rate` only if the
SUSTAINED load is genuinely higher, which means the fleet is very large.

Every value is env-configurable — nothing here is hardcoded policy.
"""

import os
import threading
import time

__all__ = ["PacingLimiter", "from_env", "Decision"]


def _f(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


def _i(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


class Decision:
    """Outcome of a pacing check.

    allow  — serve the request (after sleeping `delay` seconds, which is 0.0 for
             traffic inside the sustained rate).
    delay  — seconds the caller must sleep before serving. Never > max_delay.
    retry_after — seconds to advertise in a 429 response; None unless shed.
    """

    __slots__ = ("allow", "delay", "retry_after")

    def __init__(self, allow, delay=0.0, retry_after=None):
        self.allow = allow
        self.delay = delay
        self.retry_after = retry_after

    def __repr__(self):
        return "Decision(allow=%r, delay=%.3f, retry_after=%r)" % (
            self.allow, self.delay, self.retry_after)


class _Bucket:
    __slots__ = ("tokens", "last")

    def __init__(self, tokens, last):
        self.tokens = tokens
        self.last = last


class PacingLimiter:
    """Per-source token bucket with bounded memory.

    Thread-safe: the :5001 listener is a ThreadingHTTPServer, so several handler
    threads call `check()` concurrently.
    """

    def __init__(self, rate=5.0, burst=120.0, max_delay=5.0, exempt=(),
                 max_buckets=4096, idle_ttl=900.0, clock=time.monotonic):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        if burst <= 0:
            raise ValueError("burst must be > 0")
        self.rate = float(rate)
        self.burst = float(burst)
        self.max_delay = float(max_delay)
        self.exempt = set(exempt or ())
        self.max_buckets = int(max_buckets)
        self.idle_ttl = float(idle_ttl)
        self._clock = clock
        self._buckets = {}
        self._lock = threading.Lock()
        #: Observability counters — read by the caller for logging/metrics.
        self.stats = {"allowed": 0, "paced": 0, "shed": 0, "exempt": 0,
                      "evicted": 0}

    # ── internals ────────────────────────────────────────────────────────────
    def _prune(self, now):
        """Bound memory. Called under the lock.

        Without this, a flood from many distinct (or spoofed) sources grows the
        bucket dict without limit — turning the limiter into a memory
        exhaustion vector, which is the opposite of its job.
        """
        stale = [k for k, b in self._buckets.items()
                 if now - b.last > self.idle_ttl]
        for k in stale:
            del self._buckets[k]
        self.stats["evicted"] += len(stale)

        # Hard ceiling regardless of TTL: evict least-recently-seen first.
        if len(self._buckets) > self.max_buckets:
            excess = len(self._buckets) - self.max_buckets
            oldest = sorted(self._buckets.items(), key=lambda kv: kv[1].last)
            for k, _ in oldest[:excess]:
                del self._buckets[k]
            self.stats["evicted"] += excess

    # ── public API ───────────────────────────────────────────────────────────
    def check(self, key):
        """Consume one token for `key`. Returns a Decision; does NOT sleep."""
        if key in self.exempt:
            self.stats["exempt"] += 1
            return Decision(True, 0.0)

        now = self._clock()
        with self._lock:
            if len(self._buckets) >= self.max_buckets:
                self._prune(now)

            b = self._buckets.get(key)
            if b is None:
                # A new source starts with a full bucket: the first request from
                # any agent must never be delayed.
                b = _Bucket(self.burst, now)
                self._buckets[key] = b
            else:
                elapsed = max(0.0, now - b.last)
                b.tokens = min(self.burst, b.tokens + elapsed * self.rate)
                b.last = now

            if b.tokens >= 1.0:
                b.tokens -= 1.0
                self.stats["allowed"] += 1
                return Decision(True, 0.0)

            # Not enough tokens: how long until one exists?
            deficit = 1.0 - b.tokens
            wait = deficit / self.rate

            if wait <= self.max_delay:
                # Pace it. Take the token now (going negative is what reserves
                # our slot), so concurrent callers queue behind us rather than
                # all being told the same wait.
                b.tokens -= 1.0
                self.stats["paced"] += 1
                return Decision(True, wait)

            self.stats["shed"] += 1
            return Decision(False, 0.0, retry_after=max(1, int(wait)))

    def snapshot(self):
        with self._lock:
            return dict(self.stats, tracked_sources=len(self._buckets))


def from_env(prefix="NEMESIS_5001"):
    """Build a limiter from environment variables, or None if disabled.

    NEMESIS_5001_PACING   1/0    master switch                  (default 1)
    NEMESIS_5001_RATE     float  sustained req/s per source     (default 5.0)
    NEMESIS_5001_BURST    float  instantaneous allowance        (default 120)
    NEMESIS_5001_MAX_DELAY float max seconds to pace before 429 (default 5.0)
    NEMESIS_5001_EXEMPT   csv    never-paced sources    (default 127.0.0.1,::1)
    NEMESIS_5001_MAX_BUCKETS int memory ceiling                 (default 4096)
    NEMESIS_5001_IDLE_TTL float  seconds before a source is forgotten (900)
    """
    if os.environ.get("%s_PACING" % prefix, "1").strip() not in ("1", "true", "yes"):
        return None
    exempt = os.environ.get("%s_EXEMPT" % prefix, "127.0.0.1,::1")
    return PacingLimiter(
        rate=_f("%s_RATE" % prefix, 5.0),
        burst=_f("%s_BURST" % prefix, 120.0),
        max_delay=_f("%s_MAX_DELAY" % prefix, 5.0),
        exempt=[a.strip() for a in exempt.split(",") if a.strip()],
        max_buckets=_i("%s_MAX_BUCKETS" % prefix, 4096),
        idle_ttl=_f("%s_IDLE_TTL" % prefix, 900.0),
    )
