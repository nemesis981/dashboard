"""Nemesis Firewall diagnostics package.

Each module in this package is independently runnable:
    python3 -m diagnostics.service_status

The CHECKS list defines display order on the diagnostics page.
"""

from . import (
    config_check,
    service_status,
    disk_space,
    hardware,
    ufw_rules,
    suricata_health,
    pihole_health,
    network_devices,
    alert_summary,
    anomaly_state,
    vpn_status,
    log_tails,
    schema_drift,
    clock_and_timestamp_sanity,
    agent_enrollment_integrity,
    dependency_preflight,
    config_drift,
    audit_write_liveness,
)
from .redact import redact, redact_result

CHECKS = [
    config_check,
    service_status,
    disk_space,
    hardware,
    ufw_rules,
    suricata_health,
    pihole_health,
    network_devices,
    alert_summary,
    anomaly_state,
    vpn_status,
    log_tails,
    schema_drift,
    clock_and_timestamp_sanity,
    agent_enrollment_integrity,
    dependency_preflight,
    config_drift,
    audit_write_liveness,
]

_CHECK_MAP = {m.META["id"]: m for m in CHECKS}


def run_check(check_id: str) -> dict:
    """Run a single check by ID and return its redacted result."""
    mod = _CHECK_MAP.get(check_id)
    if mod is None:
        return {
            "id": check_id,
            "name": check_id,
            "icon": "❓",
            "status": "error",
            "summary": f"Unknown check: {check_id}",
            "output": "",
        }
    try:
        result = mod.run()
    except Exception as e:
        result = {
            "id": check_id,
            "name": mod.META.get("name", check_id),
            "icon": mod.META.get("icon", "❓"),
            "status": "error",
            "summary": f"Check failed: {e}",
            "output": str(e),
        }
    return redact_result(result)
