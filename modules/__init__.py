"""
Nemesis Module System — base class for all pluggable dashboard modules.

Every module is a subdirectory of modules/ containing:
  - manifest.json   (metadata, see README.md)
  - module.py       (defines a class named Module that subclasses NemesisModule)

The loader imports module.py dynamically and calls Module(manifest) to
instantiate. Do NOT import this file directly from module.py — the loader
handles the relationship.
"""


class NemesisModule:
    """Base class all modules must subclass.

    Subclass, override the five methods below, and name your class `Module`.
    The loader will find it by that name.
    """

    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.name: str = manifest.get("name", "unknown")

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
