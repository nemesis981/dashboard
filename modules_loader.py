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


def set_enabled(name: str, enabled: bool) -> None:
    """Toggle a module.  Updates DB and starts/stops the module immediately."""
    if name not in _manifests:
        raise ValueError(f"Unknown module: {name!r}")
    if not enabled and _manifests[name].get("required"):
        raise ValueError(f"Module {name!r} is required and cannot be disabled")
    _set_enabled_in_db(name, enabled)
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
            enabled     INTEGER NOT NULL DEFAULT 0
        )
    """)
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


def _set_enabled_in_db(name: str, enabled: bool) -> None:
    conn = sqlite3.connect(_db_path)
    conn.execute(
        "INSERT OR REPLACE INTO modules_enabled (module_name, enabled) VALUES (?, ?)",
        (name, int(enabled)),
    )
    conn.commit()
    conn.close()


def _load_module(name: str) -> None:
    if name in _loaded:
        return  # already running

    manifest = _manifests.get(name)
    if not manifest:
        raise ValueError(f"No manifest for module {name!r}")

    module_file = os.path.join(manifest["_dir"], "module.py")
    if not os.path.isfile(module_file):
        raise FileNotFoundError(f"No module.py in {manifest['_dir']}")

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
        for rule, view_func, options in routes:
            endpoint = f"module_{name}_{view_func.__name__}"
            try:
                _app.add_url_rule(rule, endpoint, view_func, **options)
            except AssertionError:
                # Route already registered (e.g. module reloaded in dev)
                log.debug("Route %s already registered, skipping", rule)

    _loaded[name] = instance
    log.info("modules_loader: loaded module %s", name)


def _unload_module(name: str) -> None:
    instance = _loaded.pop(name, None)
    if instance:
        try:
            instance.stop()
        except Exception:
            log.exception("modules_loader: error stopping module %s", name)
        log.info("modules_loader: unloaded module %s", name)
