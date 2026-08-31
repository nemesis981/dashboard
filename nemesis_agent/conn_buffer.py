"""Track C Piece 3 — the bounded buffer between ETW and the heartbeat.

WHY THIS EXISTS
    Connection events are bursty and the heartbeat is every 300s, so events must
    be held somewhere in between. That "somewhere" needs an explicit cap, or a
    host under a SYN flood (or one leaking sockets) grows the agent's memory
    without bound.

⚠ THE DROP COUNTER IS THE POINT, NOT A NICETY.
    The build plan names the failure this replaces: `conns[:50]` — a silent
    truncation that made a partial picture look like a complete one. A bounded
    buffer that drops quietly repeats exactly that mistake at a different layer.
    So every drop is counted, the count is REPORTED in the payload, and it is
    reset only when it has actually been sent.

⚠ NEITHER DROP DIRECTION IS SAFE UNDER AN ADVERSARIAL FLOOD, AND PRETENDING
  OTHERWISE WOULD BE THE REAL DEFECT.
    Dropping the OLDEST lets a flood evict prior evidence. Dropping the NEWEST
    lets an attacker flood first and then act unrecorded. There is no ordering
    that survives an attacker who can generate connections faster than we can
    ship them. This drops the oldest — standard ring behaviour, and it keeps the
    most recent window, which is what a live investigation needs — and treats the
    REPORTED COUNT as the actual mitigation: a server that sees a non-zero
    `dropped` knows this device's picture is incomplete and by how much. Silent
    completeness is the thing we cannot offer; visible incompleteness we can.

THREAD SAFETY IS REQUIRED, NOT DEFENSIVE.
    `put()` is called from the ETW dispatch thread and `drain()` from the
    heartbeat thread. They genuinely race. Every mutation is under one lock.
"""
import threading
from collections import deque

#: Default cap. ~2k events is minutes of ordinary traffic and bounded memory even
#: if every record is at its field-size limits. Overridable per deployment; the
#: constructor clamps rather than trusting a hostile or mistyped value.
DEFAULT_CAP = 2000
MIN_CAP = 16
MAX_CAP = 100000


class ConnBuffer:
    """Bounded FIFO of connection-event records, with counted drops."""

    def __init__(self, cap=DEFAULT_CAP):
        try:
            cap = int(cap)
        except (TypeError, ValueError):
            cap = DEFAULT_CAP
        # Clamp rather than accept. A cap of 0 would silently discard everything
        # while every surface still reported a healthy collector.
        self.cap = max(MIN_CAP, min(MAX_CAP, cap))
        self._q = deque()
        self._lock = threading.Lock()
        self._dropped = 0
        self._accepted = 0

    def put(self, rec):
        """Append one record, evicting the oldest if full. Returns True if kept.

        Returns False only when the record was NOT stored. Today that cannot
        happen (eviction always makes room), but the return is honest about the
        contract rather than always-True, so a future policy change cannot make
        every caller's success check silently meaningless.
        """
        if rec is None:
            return False
        with self._lock:
            if len(self._q) >= self.cap:
                self._q.popleft()
                self._dropped += 1
            self._q.append(rec)
            self._accepted += 1
            return True

    def drain(self, max_n=None):
        """Remove and return up to `max_n` records, oldest first.

        The caller OWNS what it receives: these records are gone from the buffer.
        A caller that fails to ship them has lost them, deliberately — re-queueing
        on failure is how a permanently-failing upload turns into an unbounded
        retry backlog, which is the problem this class exists to prevent.
        """
        with self._lock:
            if max_n is None or max_n >= len(self._q):
                out = list(self._q)
                self._q.clear()
            else:
                out = [self._q.popleft() for _ in range(max(0, int(max_n)))]
            return out

    def take_dropped(self):
        """Return the drop count and reset it. Call ONLY when it will be reported.

        Read-and-clear so a drop is reported exactly once. Reading without
        reporting loses it silently, which is the failure this counter exists to
        make impossible.
        """
        with self._lock:
            n, self._dropped = self._dropped, 0
            return n

    def discard(self):
        """Drop everything held, without counting it as an overflow drop.

        Used when consent is withdrawn mid-session: buffered-but-unsent events
        must not be shipped after the user has turned collection off. That is not
        an overflow and must not inflate the overflow counter — conflating the two
        would make a privacy action look like a capacity problem.
        """
        with self._lock:
            n = len(self._q)
            self._q.clear()
            return n

    def stats(self):
        with self._lock:
            return {"held": len(self._q), "cap": self.cap,
                    "dropped": self._dropped, "accepted": self._accepted}

    def __len__(self):
        with self._lock:
            return len(self._q)
