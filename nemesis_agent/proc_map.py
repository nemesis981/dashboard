"""pid -> process identity, so connection events can name the program that opened them.

WHY THIS EXISTS
    `track-c-metadata-tier-build-plan.md` Piece 1 calls `proc_name`/`proc_path`/
    `proc_signed` **"the asymmetric win -- no network sensor can produce this"**.
    It is the justification for collecting on the endpoint at all. The ETW
    collector shipped without it (2026-08-31, measured on real hardware: every
    event carried a pid, every name was null), and Piece 6 then retired the poll
    path that used to supply names via psutil. This closes that.

⚠ WHY NOT JUST CALL psutil WHEN A CONNECTION OPENS.
    That is the obvious fix and it is the wrong one. A beacon that connects for two
    seconds is very likely GONE before the lookup runs -- so the events that matter
    most are exactly the ones that would resolve to nothing. The map is populated
    ahead of the lookup and RETAINS ENTRIES AFTER EXIT, which is the whole point.

TWO SOURCES, DELIBERATELY
    * SEED (psutil, at collector start) -- covers every process that was already
      running, which is the majority of connections on any real machine. Verified,
      cross-platform, and works with no ETW involvement at all.
    * ETW process provider (see conn_collector) -- keeps it current as processes
      start and exit. UNVERIFIED against hardware; if it never delivers, the seeded
      map still answers for pre-existing processes and this degrades rather than
      breaks.

⚠ PID REUSE IS A REAL AND UNFIXABLE-BY-THIS-CLASS HAZARD, STATED PLAINLY.
    Windows reuses pids. If a pid is recycled and we never saw the start event, a
    lookup returns the PREVIOUS process's name -- a WRONG attribution, which is
    worse than no attribution, because it is confidently wrong. Three things bound
    it, none of them eliminate it:
      1. an ETW start event REPLACES the entry, which is the correct signal;
      2. entries carry their source, so a caller can tell a confirmed identity from
         an assumed one;
      3. every served lookup is counted by source, so drift is visible in the stats
         rather than invisible in the data.
    Do not describe this map as authoritative. It is a best-effort enrichment.

⚠ WHAT THIS DOES NOT DO: `proc_signed`.
    Authenticode verification is a separate job with its own failure modes and cost,
    and is NOT attempted here. Events keep `SIGNED_UNKNOWN`. Populating name/path
    while silently leaving `proc_signed` looking answered would be worse than
    leaving it plainly unknown.

THREAD SAFETY IS REQUIRED. Seeding runs on the caller's thread; ETW updates arrive
on the dispatch thread; lookups happen on both. Every mutation is under one lock.
"""
import threading
import time

#: Where an entry came from. Serving these distinctly is what lets a reader tell a
#: confirmed identity from an assumed one.
SRC_SEED = "seed"          # psutil snapshot at start -- assumed still valid
SRC_EVENT = "event"        # an observed process-start -- confirmed at that moment

DEFAULT_CAP = 4096
MIN_CAP = 64
MAX_CAP = 65536

#: How long an EXITED process stays resolvable. The short-lived-beacon case is the
#: entire reason this class exists, so this must comfortably exceed the window
#: between a process exiting and its connection's close record being emitted.
DEFAULT_RETAIN_EXITED_S = 300.0


class ProcessMap:
    def __init__(self, cap=DEFAULT_CAP, retain_exited_s=DEFAULT_RETAIN_EXITED_S,
                 clock=time.monotonic):
        try:
            cap = int(cap)
        except (TypeError, ValueError):
            cap = DEFAULT_CAP
        # Clamp rather than trust: a cap of 0 would discard every entry while every
        # surface still reported a working map.
        self.cap = max(MIN_CAP, min(MAX_CAP, cap))
        try:
            self.retain_exited_s = max(0.0, float(retain_exited_s))
        except (TypeError, ValueError):
            self.retain_exited_s = DEFAULT_RETAIN_EXITED_S
        self._clock = clock
        self._lock = threading.Lock()
        self._m = {}                      # pid -> dict
        self.stats = {}

    # ---------------------------------------------------------------- internals
    def _bump(self, key):
        self.stats[key] = self.stats.get(key, 0) + 1

    def _evict_if_needed(self):
        """Make room. EXITED entries go first, oldest-exit first, then oldest live.

        Exited-first is deliberate: a live process can still open new connections,
        so its identity has future value; an exited one only has value for records
        still in flight.
        """
        if len(self._m) <= self.cap:
            return
        exited = [(v["exited_at"], k) for k, v in self._m.items()
                  if v["exited_at"] is not None]
        exited.sort()
        while len(self._m) > self.cap and exited:
            self._m.pop(exited.pop(0)[1], None)
            self._bump("evicted_exited")
        if len(self._m) > self.cap:
            live = sorted((v["seen_at"], k) for k, v in self._m.items())
            while len(self._m) > self.cap and live:
                self._m.pop(live.pop(0)[1], None)
                self._bump("evicted_live")

    def _put(self, pid, name, path, source):
        now = self._clock()
        self._m[pid] = {"name": name or None, "path": path or None,
                        "source": source, "seen_at": now, "exited_at": None}
        self._evict_if_needed()

    # ------------------------------------------------------------------- public
    def seed(self, processes=None):
        """Populate from a snapshot. Returns how many entries were added.

        `processes` is an iterable of (pid, name, path) so this is testable without
        psutil and without a live process table. When omitted, psutil is used.

        A process that vanishes mid-iteration is SKIPPED, not counted as an error:
        the table is a moving target by nature and treating that as failure would
        make a healthy seed look broken.
        """
        rows = processes
        if rows is None:
            rows = self._psutil_rows()
        n = 0
        with self._lock:
            for pid, name, path in rows or ():
                try:
                    pid = int(pid)
                except (TypeError, ValueError):
                    self._bump("seed_bad_pid")
                    continue
                self._put(pid, name, path, SRC_SEED)
                n += 1
            self._bump("seeded") if n else None
            self.stats["seed_count"] = n
        return n

    def _psutil_rows(self):
        try:
            import psutil                                      # noqa: PLC0415
        except ImportError:
            with self._lock:
                self._bump("seed_psutil_unavailable")
            return []
        rows = []
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = p.info
                rows.append((info.get("pid"), info.get("name"), info.get("exe")))
            except Exception:                                  # noqa: BLE001
                # Gone, or not readable. Both are ordinary.
                continue
        return rows

    def note_start(self, pid, name, path=None):
        """Record an OBSERVED process start. This is the pid-reuse fix.

        Unconditionally replaces any existing entry: a start event for a pid we
        already hold means that pid has been recycled, and the old identity is now
        wrong. Keeping it would be the confidently-wrong case this class warns about.
        """
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            with self._lock:
                self._bump("start_bad_pid")
            return False
        with self._lock:
            if pid in self._m:
                self._bump("replaced_on_reuse")
            self._put(pid, name, path, SRC_EVENT)
            self._bump("noted_start")
        return True

    def note_exit(self, pid):
        """Mark a process exited. DOES NOT DELETE -- that is the entire point.

        Deleting here would reintroduce the race this class exists to close: the
        close record for a short-lived connection is emitted AFTER the process is
        gone, and would resolve to nothing.
        """
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False
        with self._lock:
            e = self._m.get(pid)
            if e is None:
                self._bump("exit_unknown_pid")
                return False
            if e["exited_at"] is None:
                e["exited_at"] = self._clock()
                self._bump("noted_exit")
            return True

    def lookup(self, pid):
        """(name, path, source) or (None, None, None).

        An exited entry is served only inside the retention window. Past it the
        answer is a miss rather than a stale guess -- the pid is very likely someone
        else's by then.
        """
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return (None, None, None)
        with self._lock:
            e = self._m.get(pid)
            if e is None:
                self._bump("miss")
                return (None, None, None)
            if e["exited_at"] is not None:
                age = self._clock() - e["exited_at"]
                if age > self.retain_exited_s:
                    self._bump("miss_exited_expired")
                    return (None, None, None)
                self._bump("served_post_exit")
            self._bump("served_" + e["source"])
            return (e["name"], e["path"], e["source"])

    def prune(self):
        """Drop exited entries past the retention window. Returns how many went."""
        now = self._clock()
        with self._lock:
            dead = [k for k, v in self._m.items()
                    if v["exited_at"] is not None
                    and now - v["exited_at"] > self.retain_exited_s]
            for k in dead:
                del self._m[k]
            if dead:
                self.stats["pruned"] = self.stats.get("pruned", 0) + len(dead)
            return len(dead)

    def __len__(self):
        with self._lock:
            return len(self._m)
