"""
DHCP Server Module — activates Pi-hole's built-in DHCP server.

Pi-hole v6 manages DHCP through its FTL config API:
  GET  /api/config          -> returns full config tree incl. dhcp.*
  PATCH /api/config         -> update any config keys
  GET  /api/dhcp/leases     -> list of active DHCP leases

Default DHCP range is read from modules/dhcp/config.json if present,
otherwise falls back to sensible 192.168.4.x defaults.
"""

import os
import json
import logging
import requests

from modules import NemesisModule

log = logging.getLogger(__name__)

_DEFAULT_CONFIG = {
    "dhcp_start":     "192.168.4.100",
    "dhcp_end":       "192.168.4.200",
    "dhcp_router":    "192.168.4.1",
    "dhcp_leasetime": 24,
    "dhcp_domain":    "lan",
}


class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)
        self._pihole_ip = os.environ.get("PIHOLE_IP", "192.168.4.69:8080")
        self._pihole_pw = os.environ.get("PIHOLE_PASSWORD", "")
        self._session_sid: str | None = None
        self._cfg = self._load_local_config()

    # -----------------------------------------------------------------------
    # NemesisModule interface
    # -----------------------------------------------------------------------

    def start(self) -> None:
        self._set_dhcp_active(True)

    def stop(self) -> None:
        self._set_dhcp_active(False)

    def status(self) -> dict:
        try:
            cfg = self._get_pihole_dhcp_config()
            if cfg is None:
                return {"state": "error", "detail": "cannot reach Pi-hole"}
            active = cfg.get("active", False)
            if active:
                leases = self._get_leases()
                n = len(leases)
                return {
                    "state": "running",
                    "detail": f"{n} lease{'s' if n != 1 else ''} active",
                    "leases": leases,
                    "lease_count": n,
                }
            return {"state": "stopped", "detail": "DHCP not active in Pi-hole"}
        except Exception as e:
            log.exception("dhcp.status() failed")
            return {"state": "error", "detail": str(e)}

    def get_dashboard_card(self) -> str:
        s = self.status()
        state = s.get("state", "stopped")
        detail = s.get("detail", "")
        lease_count = s.get("lease_count", 0)

        if state == "running":
            dot = "🟢"
            state_color = "#00ff88"
            state_label = "Active"
        elif state == "error":
            dot = "🔴"
            state_color = "#ff4444"
            state_label = "Error"
        else:
            dot = "⚫"
            state_color = "#888"
            state_label = "Inactive"

        lease_html = ""
        if state == "running":
            lease_html = (
                f'<p style="margin:6px 0 0 0;font-size:0.85em;color:#aaa">'
                f'Leases active: <strong style="color:#00d4ff">{lease_count}</strong></p>'
                f'<p style="margin:4px 0 0 0;font-size:0.8em">'
                f'<a href="http://{self._pihole_ip}/admin/dhcp.leaselist" '
                f'target="_blank" rel="noopener" style="color:#00d4ff">'
                f'View lease table ↗</a></p>'
            )

        return (
            '<div class="card">'
            '<h2>📡 DHCP Server</h2>'
            f'<p style="margin:4px 0">{dot} <span style="color:{state_color}">{state_label}</span></p>'
            f'<p style="color:#888;font-size:0.82em;margin:4px 0">{detail}</p>'
            f'{lease_html}'
            "</div>"
        )

    def get_routes(self):
        return None

    # -----------------------------------------------------------------------
    # Pi-hole API helpers
    # -----------------------------------------------------------------------

    def _get_token(self) -> str | None:
        try:
            if self._session_sid:
                r = requests.get(
                    f"http://{self._pihole_ip}/api/auth",
                    headers={"sid": self._session_sid},
                    timeout=4,
                )
                if r.json().get("session", {}).get("valid"):
                    return self._session_sid
            r = requests.post(
                f"http://{self._pihole_ip}/api/auth",
                json={"password": self._pihole_pw},
                timeout=4,
            )
            sid = r.json().get("session", {}).get("sid")
            self._session_sid = sid
            return sid
        except Exception:
            log.exception("dhcp: Pi-hole auth failed")
            return None

    def _get_pihole_dhcp_config(self) -> dict | None:
        token = self._get_token()
        if not token:
            return None
        try:
            r = requests.get(
                f"http://{self._pihole_ip}/api/config",
                headers={"sid": token},
                timeout=5,
            )
            r.raise_for_status()
            return r.json().get("config", {}).get("dhcp", {})
        except Exception:
            log.exception("dhcp: failed to fetch Pi-hole config")
            return None

    def _set_dhcp_active(self, active: bool) -> None:
        token = self._get_token()
        if not token:
            raise RuntimeError("Cannot authenticate with Pi-hole")

        payload: dict = {"config": {"dhcp": {"active": active}}}

        if active:
            # Apply range/router defaults only when enabling, in case Pi-hole
            # has never had DHCP configured.
            current = self._get_pihole_dhcp_config() or {}
            payload["config"]["dhcp"].update({
                "start":     current.get("start")     or self._cfg["dhcp_start"],
                "end":       current.get("end")       or self._cfg["dhcp_end"],
                "router":    current.get("router")    or self._cfg["dhcp_router"],
                "leasetime": current.get("leasetime") or self._cfg["dhcp_leasetime"],
                "domain":    current.get("domain")    or self._cfg["dhcp_domain"],
            })

        r = requests.patch(
            f"http://{self._pihole_ip}/api/config",
            headers={"sid": token},
            json=payload,
            timeout=5,
        )
        r.raise_for_status()
        log.info("dhcp: set active=%s, Pi-hole responded %s", active, r.status_code)

    def _get_leases(self) -> list:
        token = self._get_token()
        if not token:
            return []
        try:
            r = requests.get(
                f"http://{self._pihole_ip}/api/dhcp/leases",
                headers={"sid": token},
                timeout=5,
            )
            r.raise_for_status()
            return r.json().get("leases", [])
        except Exception:
            log.exception("dhcp: failed to fetch DHCP leases")
            return []

    # -----------------------------------------------------------------------
    # Local config
    # -----------------------------------------------------------------------

    def _load_local_config(self) -> dict:
        cfg_path = os.path.join(self.manifest["_dir"], "config.json")
        try:
            with open(cfg_path) as f:
                overrides = json.load(f)
            merged = dict(_DEFAULT_CONFIG)
            merged.update(overrides)
            return merged
        except FileNotFoundError:
            return dict(_DEFAULT_CONFIG)
        except Exception:
            log.exception("dhcp: failed to load config.json, using defaults")
            return dict(_DEFAULT_CONFIG)
