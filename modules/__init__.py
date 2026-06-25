"""
Nemesis Module System — base class for all pluggable dashboard modules.

Every module is a subdirectory of modules/ containing:
  - manifest.json   (metadata, see README.md)
  - module.py       (defines a class named Module that subclasses NemesisModule)

The loader imports module.py dynamically and calls Module(manifest) to
instantiate. Do NOT import this file directly from module.py — the loader
handles the relationship.
"""

import sqlite3


# ---------------------------------------------------------------------------
# Shared database accessor  (ADR 0001, Stage 1)
# ---------------------------------------------------------------------------
# modules_loader.init() calls set_shared_db_path() once with the single shared
# alerts.db path. Modules reach the DB through this accessor (self.get_db() /
# self.db_path) instead of computing their own __file__-relative path. Stage 1
# only INTRODUCES the accessor — no data is moved and no existing module is
# forced to change; modules adopt it during Stage 2/3.
_shared_db_path: str | None = None


def set_shared_db_path(path: str) -> None:
    """Register the single shared DB path. Called once by the loader at init."""
    global _shared_db_path
    _shared_db_path = path


def get_shared_db_path() -> str:
    """Return the shared DB path, or raise if the loader hasn't set it yet."""
    if _shared_db_path is None:
        raise RuntimeError(
            "shared DB path not set — modules_loader.init() must run first"
        )
    return _shared_db_path


def get_db(**kwargs) -> sqlite3.Connection:
    """Open a connection to the shared DB. kwargs pass through to sqlite3.connect.

    Applies a 5s busy_timeout explicitly (not relying on Python's default) so the
    connection waits rather than erroring under the concurrent-writer load the
    shared DB sees in WAL mode (ADR 0001 Stage-2 prerequisite).
    """
    kwargs.setdefault("timeout", 5.0)
    conn = sqlite3.connect(get_shared_db_path(), **kwargs)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


class NemesisModule:
    """Base class all modules must subclass.

    Subclass, override the five methods below, and name your class `Module`.
    The loader will find it by that name.
    """

    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.name: str = manifest.get("name", "unknown")

    # --- Shared database access (ADR 0001) ---------------------------------

    @property
    def db_path(self) -> str:
        """Path to the single shared alerts.db (set by the loader at init)."""
        return get_shared_db_path()

    def get_db(self, **kwargs) -> sqlite3.Connection:
        """Open a connection to the shared DB (kwargs -> sqlite3.connect)."""
        return get_db(**kwargs)

    # --- Lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Called when the module is enabled.

        Do whatever is needed to activate the feature: start a background
        thread, call an external API, write config, etc.  Must be idempotent
        (safe to call when already running).
        """
        raise NotImplementedError(f"{self.name}.start() not implemented")

    def stop(self) -> None:
        """Called when the module is disabled.

        Cleanly reverse whatever start() did.  Must be idempotent.
        """
        raise NotImplementedError(f"{self.name}.stop() not implemented")

    def status(self) -> dict:
        """Return current runtime state.

        Return a dict with at minimum:
          {"state": "running" | "stopped" | "error", "detail": "<short string>"}
        """
        raise NotImplementedError(f"{self.name}.status() not implemented")

    # --- Dashboard integration ---------------------------------------------

    def get_dashboard_card(self) -> str | None:
        """Return an HTML string for this module's dashboard card, or None.

        The string should be a single <div class="card"> element (or
        <div class="card full-width"> for a wide card) using the existing
        dashboard CSS classes.  It is injected directly into the main grid —
        no surrounding wrapper is added by the loader.

        Return None if the module has no dashboard presence.
        """
        return None

    def get_routes(self) -> list | None:
        """Return Flask routes this module wants to register, or None.

        Each element must be a 3-tuple:
          (url_rule: str, view_func: callable, options: dict)

        Example:
          [("/module/dhcp/leases", self.leases_view, {"methods": ["GET"]})]

        The loader calls app.add_url_rule(*entry) for each.  Endpoint names
        are auto-generated as  module_<name>_<func_name>  to avoid collisions.
        """
        return None
