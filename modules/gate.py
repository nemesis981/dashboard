"""Module write gate — a disabled module cannot write, in ANY process.

WHY THIS IS NOT A CONVENTION
----------------------------
Before 2026-08-23, "disabled" was a dashboard-process display state. `stop()` was a
no-op in six of ten modules, Flask routes stayed registered and served writes after
unload, and module-level write functions kept being called by three SEPARATE processes
(watchdog, hw_monitor, nemesis_connectivity_notify) that never run `modules_loader`,
hold no `_loaded` state, and could not observe a disable even in principle.

A decorator that each new write function must remember to apply would not have fixed
that -- it just moves the failure from "forgot to check" to "forgot to decorate". So
this gate has two halves:

  * a MECHANISM (below) that refuses the call, sharing state through the DB so it works
    across process boundaries;
  * a CONFORMANCE TEST (`test_module_write_gate.py`) that statically finds every
    module-level function performing a write and fails if it is not gated. New ungated
    write functions are caught by the test, not by review.

The test is the "cannot forget" part, and it is honest about being a test rather than
a language guarantee. Python cannot make a function structurally unreachable; what it
can do is make the omission impossible to land unnoticed.

WHY THE DB IS THE SHARED STATE
------------------------------
It is the only thing all writers already share. An in-process registry cannot be seen
by watchdog or hw_monitor; a file flag would be a second source of truth beside
`modules_enabled`. The gate reads the same row `modules_loader.set_enabled()` writes,
so there is exactly one answer to "is this module enabled" no matter who asks.

WHY IT FAILS CLOSED
-------------------
If enablement cannot be read, the write is REFUSED (`EnablementUnknown`), not allowed.
That direction is nearly free here: the enablement row lives in the same database the
write itself targets, so a read failure almost certainly means the write would fail
too. Allowing the write instead would be the forbidden shape -- a failed read
presented as a legal answer ("assume enabled") -- and the cost of being wrong is a
module the operator switched off still writing.

CONTRACT: refusal RAISES. It never returns a legal-looking value.
`open_ticket()` returns an int and `0` already means "failed"; `_notify_ticket()`
distinguishes id / 0 (settings gate declined) / None (error). Folding "module
disabled" into any of those would make a deliberate refusal indistinguishable from a
failure or a config decision. An exception cannot be mistaken for a ticket id.
"""

import logging
import os
import sqlite3
import threading
import time

log = logging.getLogger("nemesis.modules.gate")

#: Enablement changes at human speed (someone clicks a toggle). A short TTL keeps the
#: cost off the write path without letting a disable linger: worst case a module keeps
#: writing for this long after being switched off.
_TTL_S = 5.0

_cache: dict = {}          # name -> (checked_at, enabled)
_lock = threading.Lock()


class ModuleDisabled(RuntimeError):
    """The module is switched off; the write was refused, not attempted."""


class EnablementUnknown(ModuleDisabled):
    """Enablement could not be determined, so the write was refused (fail closed).

    A SUBCLASS of ModuleDisabled deliberately: every caller that already handles a
    refusal handles this too, while a caller that wants to tell the two apart still
    can. The distinction matters for diagnosis -- "you turned it off" and "I could not
    find out" need different fixes -- but not for the decision, which is refuse.
    """


def _db_path():
    """Resolve the shared DB the same way every other cross-process caller does."""
    import modules
    return modules.get_shared_db_path()


def _read_enabled(name: str) -> bool:
    path = _db_path()
    if not path or not os.path.exists(path):
        log.error("write refused: cannot resolve the shared DB to check whether %r "
                  "is enabled", name)
        raise EnablementUnknown(
            "shared database path is unset or missing (%r); cannot confirm whether "
            "%r is enabled, so the write is refused" % (path, name))
    conn = sqlite3.connect(path, timeout=5.0)
    try:
        row = conn.execute(
            "SELECT enabled FROM modules_enabled WHERE module_name=?", (name,)
        ).fetchone()
    finally:
        conn.close()
    if row is not None:
        return bool(row[0])
    # No row yet: the module has never been toggled. Fall back to the manifest's
    # declared default, which is what modules_loader._is_enabled() does -- the two
    # must not disagree about an untoggled module or the gate would refuse writes
    # from a module the loader considers enabled.
    return _manifest_default(name)


def _manifest_default(name: str) -> bool:
    import json
    here = os.path.dirname(os.path.abspath(__file__))
    mpath = os.path.join(here, name, "manifest.json")
    try:
        with open(mpath, encoding="utf-8") as fh:
            return bool(json.load(fh).get("enabled_by_default", False))
    except Exception as exc:                                     # noqa: BLE001
        raise EnablementUnknown(
            "no modules_enabled row for %r and its manifest could not be read (%s); "
            "refusing the write rather than guessing" % (name, exc))


def is_enabled(name: str) -> bool:
    """Cached enablement check. Raises EnablementUnknown if it cannot be determined."""
    now = time.time()
    with _lock:
        hit = _cache.get(name)
        if hit and (now - hit[0]) < _TTL_S:
            return hit[1]
    value = _read_enabled(name)          # outside the lock: it touches the DB
    with _lock:
        _cache[name] = (now, value)
    return value


def invalidate(name: str = None) -> None:
    """Drop cached enablement. Called by modules_loader on every toggle so a disable
    takes effect immediately in THIS process rather than up to _TTL_S later."""
    with _lock:
        if name is None:
            _cache.clear()
        else:
            _cache.pop(name, None)


def require_enabled(name: str) -> None:
    """Raise unless `name` is enabled. The single decision point.

    LOGS BEFORE RAISING, deliberately. Several existing callers wrap these writes in
    a broad `except Exception` (watchdog, hw_monitor, the malware ticket path), so a
    refusal would otherwise vanish silently and the operator would see neither a
    ticket nor a reason. The log line is the trace that survives a caller swallowing
    the exception -- the same reasoning as recording E-TICKETS-001 rather than just
    returning 0.
    """
    if not is_enabled(name):
        log.warning("write refused: module %r is disabled", name)
        raise ModuleDisabled(
            "module %r is disabled; the write was refused. Enable it in Settings if "
            "this write should happen." % name)


def write_gated(module_name: str):
    """Decorator: refuse the call unless the module is enabled."""
    def _wrap(fn):
        def _gated(*a, **k):
            require_enabled(module_name)
            return fn(*a, **k)
        _gated.__name__ = fn.__name__
        _gated.__doc__ = fn.__doc__
        _gated.__wrapped__ = fn
        _gated.__nemesis_gated__ = module_name       # what the conformance test reads
        return _gated
    return _wrap


def gate_module_writes(module_name: str, namespace: dict, names) -> None:
    """Wrap every function in `names` found in `namespace`, in place.

    Called ONCE at the bottom of a module, so the gate applies at IMPORT time and
    therefore to every importer -- including the separate processes that bypass
    modules_loader entirely. That is the half a loader-side wrapper cannot reach.
    """
    missing = []
    for fname in names:
        fn = namespace.get(fname)
        if not callable(fn):
            missing.append(fname)
            continue
        if getattr(fn, "__nemesis_gated__", None):
            continue                                  # already gated; idempotent
        namespace[fname] = write_gated(module_name)(fn)
    if missing:
        # Loud, not silent: a name listed here that does not exist means the manifest
        # and the code have drifted, and the gate is protecting nothing under that
        # name. Exactly the "coverage that protects nothing" shape _AUTH_EXEMPT hit.
        raise RuntimeError(
            "gate_module_writes(%r): declared write function(s) not found in the "
            "module: %s" % (module_name, ", ".join(sorted(missing))))
