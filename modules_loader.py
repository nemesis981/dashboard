"""
Nemesis Module Loader
=====================
Discovers, loads, and manages lifecycle of dashboard modules.

Usage in dashboard.py:
    import modules_loader
    modules_loader.init(app, DB_PATH, MODULES_DIR)

Public API:
    init(app, db_path, modules_dir)  — call once at startup
    get_module_cards()               — returns [(name, html), ...]
    get_all_manifests()              — returns {name: manifest_dict, ...}
    is_enabled(name)                 — bool
    set_enabled(name, enabled)       — update DB + load/unload immediately
    module_status(name)              — {"state": ..., "detail": ...}
"""

import os
import ast
import json
import importlib.util
import sqlite3
import logging

import modules  # the modules package: NemesisModule + shared DB accessor

log = logging.getLogger(__name__)

_modules_dir: str | None = None
_db_path: str | None = None
_app = None
_manifests: dict = {}   # name -> manifest dict (always populated after init)
_loaded: dict = {}      # name -> Module instance (only enabled modules)


class ModuleEnforcementError(RuntimeError):
    """A module violates the ADR 0006 Data Manager contract by reaching the DB
    directly (raw sqlite3 / bare get_db) instead of through the Data Manager.
    Raised by the loader BEFORE any module code runs — no routing, no load."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init(app, db_path: str, modules_dir: str) -> None:
    """Initialise the loader.  Call exactly once, before serving requests."""
    global _modules_dir, _db_path, _app
    _app = app
    _db_path = db_path
    _modules_dir = modules_dir
    # Publish the single shared DB path so modules can reach it via the accessor
    # (self.get_db() / self.db_path) — before any module is constructed/started.
    modules.set_shared_db_path(db_path)
    _init_db()
    _discover()
    _load_all_enabled()
    log.info("modules_loader: discovered %d module(s), loaded %d",
             len(_manifests), len(_loaded))


def get_all_manifests() -> dict:
    """Return a copy of all discovered manifests (enabled or not)."""
    return dict(_manifests)


def is_enabled(name: str) -> bool:
    return _is_enabled(name)


def set_enabled(name: str, enabled: bool, actor: str = None) -> None:
    """Toggle a module.  Updates DB and starts/stops the module immediately.

    `actor` is the attribution seam: threaded to _set_enabled_in_db so the
    toggling identity is recorded on the modules_enabled row.
    """
    if name not in _manifests:
        raise ValueError(f"Unknown module: {name!r}")
    if not enabled and _manifests[name].get("required"):
        raise ValueError(f"Module {name!r} is required and cannot be disabled")
    _set_enabled_in_db(name, enabled, actor)
    # Drop the write gate's cached answer so a toggle takes effect in THIS process
    # immediately rather than up to its TTL later. Other processes pick it up on
    # their own next TTL expiry -- that lag is the documented cost of sharing the
    # state through the database, which is the only thing they all see.
    try:
        from modules import gate as _gate
        _gate.invalidate(name)
    except Exception:                                            # noqa: BLE001
        log.exception("modules_loader: could not invalidate write-gate cache for %s", name)
    if enabled:
        _load_module(name)
    else:
        _unload_module(name)


def get_module_cards() -> list:
    """Return [(name, html_string), ...] for all loaded modules with cards."""
    cards = []
    for name, instance in list(_loaded.items()):
        try:
            html = instance.get_dashboard_card()
            if html:
                cards.append((name, html))
        except Exception:
            log.exception("Module %s get_dashboard_card() failed", name)
    return cards


def module_status(name: str) -> dict:
    instance = _loaded.get(name)
    if not instance:
        return {"state": "stopped", "detail": "not loaded"}
    try:
        return instance.status()
    except Exception as e:
        return {"state": "error", "detail": str(e)}


#: A required detector must be enabled AND healthy. These states count as healthy;
#: anything else on a REQUIRED module is SUPPRESSED coverage. Same vocabulary as the
#: settings-row honesty fix (R2) so the two never disagree about what "healthy" means.
_HEALTHY_DETECTOR_STATES = frozenset({"active", "running", "ok", "healthy", "enabled"})


def required_detector_coverage() -> list:
    """Findings for any REQUIRED module whose coverage is suppressed. Empty == all covered.

    R6 (2026-08-22): a required detector that is enabled-but-erroring, or somehow not
    enabled, is a loss of protection coverage — and it is alertable ON ITS OWN, without
    waiting on attestation deployment. This reuses the required flag (R1) and the real
    status() (R2): required + not-healthy = suppression. Fail-closed: a status that cannot
    be read counts as suppressed (a detector we cannot confirm is running is not confirmed
    coverage), never silently passed.

    Each finding: {module, reason, state, detail}. Read-only; records nothing itself so it
    is safe to call from any watcher — the caller decides how loudly to alert.
    """
    findings = []
    for name, man in _manifests.items():
        if not man.get("required"):
            continue
        if not is_enabled(name):
            # The loader refuses set_enabled(False) for required modules, so this should be
            # unreachable — which is exactly why it is worth catching if it ever happens.
            findings.append({"module": name, "reason": "required detector is DISABLED",
                             "state": "disabled", "detail": ""})
            continue
        st = module_status(name) or {}
        state = str(st.get("state", "")).lower()
        if state not in _HEALTHY_DETECTOR_STATES:
            findings.append({
                "module": name,
                "reason": "required detector enabled but not healthy (coverage suppressed)",
                "state": state or "unknown",
                "detail": str(st.get("detail", ""))[:160]})
    return findings


def get_loaded_modules() -> dict:
    return dict(_loaded)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _init_db() -> None:
    conn = sqlite3.connect(_db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS modules_enabled (
            module_name TEXT PRIMARY KEY,
            enabled     INTEGER NOT NULL DEFAULT 0,
            actor       TEXT
        )
    """)
    # Idempotent migration: actor attribution seam (readiness Tier B). Records who
    # toggled a module; NULL today, threaded so a future identity can flow through.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(modules_enabled)").fetchall()}
    if "actor" not in existing:
        conn.execute("ALTER TABLE modules_enabled ADD COLUMN actor TEXT")
    conn.commit()
    conn.close()


def _discover() -> None:
    global _manifests
    _manifests = {}
    if not _modules_dir or not os.path.isdir(_modules_dir):
        return
    for entry in sorted(os.scandir(_modules_dir), key=lambda e: e.name):
        if not entry.is_dir() or entry.name.startswith("_"):
            continue
        manifest_path = os.path.join(entry.path, "manifest.json")
        if not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            name = manifest.get("name", entry.name)
            manifest["_dir"] = entry.path
            _manifests[name] = manifest
            log.debug("modules_loader: discovered %s", name)
        except Exception:
            log.exception("modules_loader: failed to read %s", manifest_path)


def _load_all_enabled() -> None:
    # Required modules load first so their Python APIs are importable when
    # optional modules execute their top-level imports (e.g. anomaly_detection
    # imports modules.ai_engine at module level).
    ordered = sorted(_manifests, key=lambda n: (0 if _manifests[n].get("required") else 1, n))
    for name in ordered:
        if _is_enabled(name):
            try:
                _load_module(name)
            except ModuleEnforcementError as e:
                # Loud + specific, no traceback noise — the message names the module,
                # the failed check, and the line. The module simply does not load.
                log.error("modules_loader: REFUSED to load module — %s", e)
            except Exception:
                log.exception("modules_loader: failed to load %s", name)


def _is_enabled(name: str) -> bool:
    conn = sqlite3.connect(_db_path)
    row = conn.execute(
        "SELECT enabled FROM modules_enabled WHERE module_name=?", (name,)
    ).fetchone()
    conn.close()
    if row is not None:
        return bool(row[0])
    return bool(_manifests.get(name, {}).get("enabled_by_default", False))


def _set_enabled_in_db(name: str, enabled: bool, actor: str = None) -> None:
    # actor: attribution seam (readiness Tier B). NULL today; threaded so a future
    # authenticated caller can record who enabled/disabled the module.
    conn = sqlite3.connect(_db_path)
    conn.execute(
        "INSERT OR REPLACE INTO modules_enabled (module_name, enabled, actor) VALUES (?, ?, ?)",
        (name, int(enabled), actor),
    )
    conn.commit()
    conn.close()


def _check_data_manager_contract(name: str, module_file: str) -> None:
    """ADR 0006 Step 3 — enforce the Data Manager contract statically, BEFORE the
    module's code is executed. A module that reaches the DB directly is refused
    load. Rejects, naming the specific violation + line:
      * ANY `import sqlite3` / `from sqlite3 import ...` (incl. aliases), and
      * ANY bare `get_db` — a call (`get_db()`, `self.get_db()`, `modules.get_db()`)
        or `from modules import get_db`.
    `get_data_manager()` / `data_manager.connect()` are the sanctioned path and are
    NOT flagged. Core services (watchdog, hw_monitor, …) do not pass through this
    loader and keep their higher-trust direct path.
    """
    try:
        with open(module_file) as f:
            tree = ast.parse(f.read(), module_file)
    except SyntaxError as e:
        raise ModuleEnforcementError(
            f"module {name!r} rejected — module.py failed to parse ({e})") from e

    hint = ("ADR 0006: route DB access through the Data Manager via "
            "get_data_manager() / data_manager.connect()")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "sqlite3" or a.name.startswith("sqlite3."):
                    raise ModuleEnforcementError(
                        f"module {name!r} rejected — raw sqlite3 import at "
                        f"module.py:{node.lineno} ({hint})")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "sqlite3":
                raise ModuleEnforcementError(
                    f"module {name!r} rejected — raw sqlite3 import at "
                    f"module.py:{node.lineno} ({hint})")
            if node.module == "modules" and any(a.name == "get_db" for a in node.names):
                raise ModuleEnforcementError(
                    f"module {name!r} rejected — imports the bare get_db accessor at "
                    f"module.py:{node.lineno} ({hint})")
        elif isinstance(node, ast.Call):
            fn = node.func
            if (isinstance(fn, ast.Name) and fn.id == "get_db") or \
               (isinstance(fn, ast.Attribute) and fn.attr == "get_db"):
                raise ModuleEnforcementError(
                    f"module {name!r} rejected — bare get_db() call at "
                    f"module.py:{node.lineno} ({hint})")


def _load_module(name: str) -> None:
    if name in _loaded:
        return  # already running

    manifest = _manifests.get(name)
    if not manifest:
        raise ValueError(f"No manifest for module {name!r}")

    module_file = os.path.join(manifest["_dir"], "module.py")
    if not os.path.isfile(module_file):
        raise FileNotFoundError(f"No module.py in {manifest['_dir']}")

    # ADR 0006 Step 3: enforce the Data Manager contract before running ANY module
    # code. A module that reaches the DB directly is refused load (raises).
    _check_data_manager_contract(name, module_file)

    # Dynamic import — each module gets its own namespace
    spec = importlib.util.spec_from_file_location(f"nemesis_module_{name}", module_file)
    py_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(py_module)
    # Register under the package path so `from modules.<name> import ...` in
    # other modules and dashboard.py resolves to THIS instance (same _incident
    # dicts, same in-flight sets, etc.) instead of a fresh duplicate.
    import sys as _sys
    _sys.modules[f"modules.{name}.module"] = py_module

    instance = py_module.Module(manifest)
    instance.start()

    # Register any Flask routes the module declares
    routes = instance.get_routes()
    if routes and _app:
        # ── Load-time RBAC registration check (2026-08-26) ────────────────────
        #
        # A route absent from roles.ROUTE_MINIMUMS resolves to admin-only via the
        # gate's fail-closed path -- SAFE, but the access level is a DEFAULT
        # rather than a decision, and nothing forced anyone to make one. The
        # runtime drift signal (E-RBAC-002) is supposed to say so; it recorded
        # NOTHING AT ALL until the `connect("core")` bug was fixed the same day,
        # and a ledger of zero rows read exactly like "no drift ever occurred".
        #
        # WHY THE ROUTE IS SKIPPED RATHER THAN THE MODULE REFUSED. `modules_loader`
        # hard-refuses an ADR-0006 violation, and this deliberately does NOT match
        # that: an ADR-0006 violation means a module BYPASSES access control, while
        # an unregistered route is merely OVER-restricted. Killing an entire
        # module -- its background work, its card, its other routes -- over a
        # registry omission whose security posture is already safe would trade a
        # safe route for a dead module. Skipping just the offending route fails
        # closed at the exact granularity of the mistake.
        #
        # AND THE POINT IS THAT THE SIGNAL IS THE BEHAVIOUR, NOT THE LOG LINE. A
        # warning can go unread for months -- that is precisely how the broken
        # recorder survived. A route that visibly 404s cannot.
        #
        # Imported HERE, not at module top level: this file imports only stdlib +
        # `modules`, and is imported by a dozen test files and two modules that do
        # not necessarily have alert_manager/ on their path. Inside `if _app` we
        # are in the dashboard process, where roles is importable by construction.
        try:
            import roles as _roles_reg                          # noqa: PLC0415
        except ImportError:  # pragma: no cover
            try:
                from alert_manager import roles as _roles_reg   # noqa: PLC0415
            except ImportError:
                _roles_reg = None
                log.warning("modules_loader: roles registry unavailable — "
                            "registering %s routes WITHOUT the RBAC check", name)

        for rule, view_func, options in routes:
            endpoint = f"module_{name}_{view_func.__name__}"

            if _roles_reg is not None and endpoint not in _roles_reg.ROUTE_MINIMUMS:
                log.error(
                    "modules_loader: REFUSING to register %s (%s) — endpoint %r "
                    "is not in roles.ROUTE_MINIMUMS, so its required role was "
                    "never decided. The route will 404 until it is registered. "
                    "Fix: add \"%s\": (<get_role>, <post_role>) to ROUTE_MINIMUMS "
                    "in alert_manager/roles.py.",
                    rule, name, endpoint, endpoint)
                continue

            try:
                _app.add_url_rule(rule, endpoint,
                                  _guard_view(name, view_func), **options)
            except AssertionError:
                # Route already registered (e.g. module reloaded in dev)
                log.debug("Route %s already registered, skipping", rule)

    _loaded[name] = instance
    log.info("modules_loader: loaded module %s", name)


def _guard_view(name: str, view_func):
    """Wrap a module view so it stops serving when the module is disabled.

    WHY A WRAPPER AND NOT DEREGISTRATION: Flask builds `url_map` at registration and
    exposes no supported way to remove a rule. Before this, `_unload_module` popped the
    instance from `_loaded` and the route kept serving 200s from the still-bound
    instance -- a disabled module answering writes. Reproduced directly before the fix.

    503, not 404: the route exists and is expected to work again the moment the module
    is re-enabled. 404 would say "no such endpoint", which is false and would send an
    operator looking for a routing bug instead of a switched-off module.

    ⚠ TWO CASES, AND THEY BEHAVE DIFFERENTLY. Confirmed on a live appliance 2026-08-23:

      * TOGGLED OFF in a running process -> the route is registered, this guard runs,
        the caller gets 503.
      * ALREADY OFF AT STARTUP -> `_load_all_enabled()` never loads the module, so
        `_load_module` never runs and the route is NEVER REGISTERED. Flask answers 404.

    Quiescence holds in both cases -- no handler runs, nothing is written -- so this is
    a DIAGNOSTIC inconsistency, not a safety one. But it is exactly the misleading
    signal the paragraph above argues against, so it is written down rather than left
    for someone to rediscover: after a restart, a disabled module's routes 404.

    Making it uniformly 503 means registering routes for modules that are not running,
    which requires separating "construct the instance to read its routes" from "start
    it" -- a real change to the module contract, deliberately not folded in here.
    Tracked as a follow-up.
    """
    def _guarded(*a, **k):
        if name not in _loaded:
            from flask import jsonify
            return jsonify({
                "ok": False,
                "error": f"module {name!r} is disabled",
                "module": name,
            }), 503
        return view_func(*a, **k)
    _guarded.__name__ = view_func.__name__
    _guarded.__doc__ = view_func.__doc__
    _guarded.__wrapped__ = view_func
    return _guarded


def _unload_module(name: str) -> None:
    instance = _loaded.pop(name, None)
    if instance:
        try:
            instance.stop()
        except Exception:
            log.exception("modules_loader: error stopping module %s", name)
        log.info("modules_loader: unloaded module %s", name)
