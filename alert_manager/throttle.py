"""Cooperative throttle: a generic executor-publishes / service-cooperates seam.

WHY COOPERATIVE, NOT IMPOSED
----------------------------
Nothing can reach across a process boundary and set another service's sleep
interval: the interval is a module-level constant inside a separate process, and
systemd offers no lever for it. So a throttle is not something done TO a service
-- it is something a service COOPERATES with. The executor (e.g. the memory
escalation ladder) publishes throttle INTENT for a component to durable shared
state; each throttle-aware service reads that intent at the top of its loop and
scales its own sleep. This module is both halves of that seam.

FITS ADR 0006, NOT A SIDE CHANNEL
---------------------------------
Intent and the cooperating-service registry are two tables owned by the
`throttle` namespace (see data_manager.NAMESPACES). Every write goes through the
Data Manager's atomic `upsert` -- access-checked, logged, actor-stamped. Readers
use read-any (ADR 0001); the intent table is not owned by the reader, and reads
are not access-controlled. Canonical DDL lives in database.init_throttle_tables().

TWO SAFETY PROPERTIES, BOTH DELIBERATE
--------------------------------------
1. AUTO-EXPIRY (fail-safe). Intent carries `until_ts`. A reader treats an expired
   intent as NORMAL. If the executor dies, throttle lifts ITSELF rather than
   leaving services stuck slow forever -- the same heartbeat discipline the
   tier2_gate state uses. The executor re-publishes each cycle to keep it live.
2. FAIL-OPEN on read error. A read failure returns NORMAL (full speed), never a
   stall. This is the deliberate OPPOSITE of the malware-scan mountinfo guard's
   fail-closed: throttle is an optimisation, not a safety gate, and a throttle
   layer that can hang or slow a service on a DB hiccup is worse than no throttle
   at all. The ALERT rung still fires regardless of whether THROTTLE was honoured.
"""
from __future__ import annotations

import logging
import os
import time

import data_manager

log = logging.getLogger("nemesis.throttle")

NAMESPACE = "throttle"
INTENT_TABLE = "throttle_intents"
REGISTRY_TABLE = "throttle_components"

#: A factor is a sleep MULTIPLIER: 1.0 = normal, >1 = slower. Never < 1 (throttle
#: only slows; it does not speed a service up past its own configured interval).
NORMAL = 1.0
#: Hard ceiling. A throttled service must still wake often enough to honour its
#: stop signal and to notice the throttle lifting; an unbounded factor could park
#: it for so long it looks hung. 8x a 300s interval is 40 min -- already generous.
MAX_FACTOR = 8.0


# --- pure core (self-testable; proves its own premise before a live read) -----
def _effective_factor(row, now):
    """Clamp a raw intent row to an effective sleep factor. PURE.

    row is a mapping/Row with `factor` and `until_ts`, or None. Returns NORMAL for
    a missing row, an expired row (now >= until_ts -> auto-lift), a malformed row,
    or a factor below NORMAL; otherwise the factor clamped to MAX_FACTOR.
    """
    if row is None:
        return NORMAL
    try:
        factor = float(row["factor"])
        until = float(row["until_ts"])
    except (TypeError, ValueError, KeyError, IndexError):
        return NORMAL                      # malformed -> fail-open, never guess
    if now >= until:
        return NORMAL                      # expired -> throttle auto-lifts
    if factor < NORMAL:
        return NORMAL
    return min(factor, MAX_FACTOR)


def _scaled_seconds(base_seconds, factor):
    """base * factor, floored at 1s and capped at base*MAX_FACTOR. PURE."""
    total = int(round(base_seconds * factor))
    return max(1, min(total, int(base_seconds * MAX_FACTOR)))


# --- read side (services) -----------------------------------------------------
def _read_intent_row(component, dm):
    """Read the current intent row for `component`, or None. Read-any (ADR 0001);
    connects as the throttle namespace, which owns the table. Any failure raises
    to the caller, which fails OPEN -- the raise is never swallowed into a row."""
    conn = dm.connect(NAMESPACE)
    try:
        cur = conn.execute(
            f"SELECT factor, until_ts FROM {INTENT_TABLE} WHERE component=?",
            (component,))
        return cur.fetchone()
    finally:
        try:
            conn.close()
        except Exception:                  # noqa: BLE001
            pass


def live_intent_components(dm, now=None):
    """Components with a currently-live (non-expired, > NORMAL) throttle intent.
    Used by the executor to know which intents to CLEAR when a component drops
    below throttle. Raises on DB error rather than returning a wrong empty set
    (which would make the executor stop clearing); the caller handles it."""
    now = time.time() if now is None else now
    conn = dm.connect(NAMESPACE)
    try:
        rows = conn.execute(
            f"SELECT component, factor, until_ts FROM {INTENT_TABLE}").fetchall()
    finally:
        try:
            conn.close()
        except Exception:                  # noqa: BLE001
            pass
    return {r["component"] for r in rows if _effective_factor(r, now) > NORMAL}


class ThrottleHandle:
    """Returned by register_throttle_aware(). A service keeps one and uses it in
    its loop in place of its previous sleep call."""

    def __init__(self, component, dm, *, now_fn=time.time):
        self.component = component
        self.dm = dm
        self._now = now_fn

    def current_factor(self):
        """Live effective factor for this component. Fail-open to NORMAL on ANY
        error -- a throttle read must never be able to slow or stall the service."""
        try:
            row = _read_intent_row(self.component, self.dm)
        except Exception as e:             # noqa: BLE001
            log.warning("throttle: intent read failed for %s (%s) -- running at "
                        "normal speed", self.component, e)
            return NORMAL
        return _effective_factor(row, self._now())

    def throttled_sleep(self, base_seconds, is_running=lambda: True,
                        sleep_fn=time.sleep):
        """Drop-in for a service's interruptible sleep. Sleeps base*factor (clamped)
        in 1s steps, stopping early when is_running() goes false -- so SIGTERM and a
        lifted throttle are both honoured within one second."""
        total = _scaled_seconds(base_seconds, self.current_factor())
        slept = 0
        while slept < total and is_running():
            sleep_fn(1)
            slept += 1


def register_throttle_aware(component, dm, *, pid=None, now=None):
    """A service declares itself throttle-aware once at startup and gets a handle.

    Records (component, last_registered_ts, pid) in the registry so the executor
    and dashboard can see which throttle-capable services are ACTUALLY running and
    listening -- closing the 'published a mitigation that does nothing because the
    process is down' gap, same honesty principle as mem_appliance.RUNG_AVAILABILITY.
    The registry write is BEST-EFFORT: throttle correctness depends only on the
    intent reads, so a failed registration is logged, not fatal.

    NOTE (appliance): a component that is UNTHROTTLED by design — no interval to
    slow, or slowing it would be harmful the same way restarting it would be
    (clamd, suricata, dashboard) — MUST NOT register here. That exclusion is a
    decision, not an oversight; the appliance surfaces it as the distinct status
    UNTHROTTLED (mem_appliance.throttle_status) rather than leaving the component
    silently absent, and mem_appliance.assert_throttle_registerable() is the guard
    a future appliance-service wiring calls to enforce it loudly.
    """
    now = time.time() if now is None else now
    pid = os.getpid() if pid is None else pid
    try:
        dm.upsert(NAMESPACE, REGISTRY_TABLE,
                  {"component": component, "last_registered_ts": now, "pid": pid},
                  conflict_cols=["component"])
    except Exception as e:                 # noqa: BLE001
        log.warning("throttle: could not record registration for %s (%s) -- "
                    "throttle still functions via intent reads", component, e)
    return ThrottleHandle(component, dm)


# --- publish side (executor) --------------------------------------------------
def publish_throttle(component, factor, hold_seconds, reason, dm, *,
                     source="mem-ladder", now=None):
    """Publish/refresh throttle intent for one component. Atomic + logged +
    actor-stamped via dm.upsert. Intent expires at now + hold_seconds; the
    executor must re-publish within that window to keep it live (fail-safe)."""
    now = time.time() if now is None else now
    dm.upsert(NAMESPACE, INTENT_TABLE,
              {"component": component, "factor": float(factor),
               "until_ts": now + hold_seconds, "reason": reason,
               "source": source, "updated_ts": now},
              conflict_cols=["component"])


def clear_throttle(component, dm, *, source="mem-ladder", now=None):
    """Lift throttle explicitly: publish a POSITIVE normal record (factor 1.0,
    already-expired until_ts) rather than deleting the row, so a reader can tell
    'explicitly returned to normal' from 'never throttled'."""
    now = time.time() if now is None else now
    dm.upsert(NAMESPACE, INTENT_TABLE,
              {"component": component, "factor": NORMAL, "until_ts": now,
               "reason": "cleared", "source": source, "updated_ts": now},
              conflict_cols=["component"])
