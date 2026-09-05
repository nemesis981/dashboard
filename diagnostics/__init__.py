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
from .redact import redact, redact_result, SCOPE_DISPLAY, SCOPE_EXPORT

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
    """Run a single check by ID and return its DISPLAY-scoped result.

    ⛔ DISPLAY SCOPE, DELIBERATELY. The only production callers are
    dashboard.py's /api/diagnostics/run and /run-all, which render straight into
    the appliance owner's own browser. Secrets are still stripped; the owner's
    own IPs, MACs and device names are NOT, because they are the answer the
    person is looking at.

    This is not an oversight and must not be "tightened" back to EXPORT. From
    485b303 until 2026-09-05 this line applied the full export scrubber to the
    screen. That was harmless while redact() was secrets-only, then 109191d
    widened redact() for the Submit-to-Support path — touching redact.py alone —
    and the display path silently inherited it. Network Devices then rendered
    every one of 70 devices as [REDACTED]/[REDACTED]/[REDACTED], and the built-in
    AI assistant, whose prompt is generated from these same checks, was sending
    people to a page that could no longer answer them.

    ⛔ IF YOU ADD A CALLER THAT SENDS THIS RESULT OFF THE BOX, re-redact it at
    SCOPE_EXPORT. api_diag_submit() already does exactly that on the text the
    browser posts back, which is why display scope here is safe.
    """
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
    return redact_result(result, scope=SCOPE_DISPLAY)
