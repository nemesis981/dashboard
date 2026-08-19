#!/usr/bin/env python3
"""Nemesis Connectivity Diagnostics Watcher — standalone always-on service.

Wraps the diagnostics module's connectivity probe (watcher.run_once) in a
self-gating systemd service. Each loop: two-gate (diagnostics module enabled in
modules_enabled AND watcher_enabled setting) then run_once, then sleep
watcher_interval_seconds (read fresh each loop — the scheduler-aware seam). All
probe logic lives in the module; this file is just the process host.

Per the diagnostics classification (Transient + Dashboard-independent) this MUST
run OUTSIDE Flask so it survives a dashboard/DB failure — the failure modes that
need diagnostics most are exactly when in-Flask tools are down. Runs as root,
uniform with the other Nemesis services.

Rule 8: raw probe detail (addresses) goes to the flat log under watcher_log_dir
(OUTSIDE the repo); only sanitized verdicts reach the DB. This service logs its
own lifecycle to BOTH stdout (journald, Type=simple) AND a flat service log in
the same diagnostics log dir.
"""

import logging
import os
import signal
import sys
import time

_HERE   = os.path.dirname(os.path.abspath(__file__))
import nemesis_paths
DB_PATH = nemesis_paths.db_path(os.path.join(_HERE, "alerts.db"))
DEFAULT_INTERVAL_SECONDS = 60
#: Throttle handle, set in main() once diagnostics-watcher registers throttle-aware.
_throttle = None
# systemd sets $LOGS_DIRECTORY from the unit's LogsDirectory=, and creates it
# owned by the service user. Preferring it avoids a hardcoded path drifting
# from what the unit actually provisions — under ProtectSystem=strict the
# rest of /var/log is read-only, so a mismatch is an unrecoverable OSError.
DEFAULT_LOG_DIR = os.environ.get("LOGS_DIRECTORY") or "/var/log/nemesis/diagnostics"
SERVICE_LOG_BASENAME = "diagnostics_watcher.log"

# Start with stdout logging so startup/errors are journald-visible immediately
# (Type=simple captures stdout). A flat-file handler is added in main() once we
# can read watcher_log_dir from settings.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("nemesis.diagnostics.service")

# ── Cross-process DB hazard: register the shared DB path BEFORE any module import
#    that reaches the DB. modules.get_shared_db_path() raises until this is set,
#    and this service never runs modules_loader.init(). MUST be first.
sys.path.insert(0, os.path.dirname(_HERE))   # repo root
import modules                                # noqa: E402
modules.set_shared_db_path(DB_PATH)
from modules.diagnostics import module as diag           # noqa: E402  (after set_shared_db_path)
from modules.diagnostics import watcher as diag_watcher  # noqa: E402
# Core-side episode notifier, shared with vpn_dns_guard. Resolves via the unit's
# PYTHONPATH (/opt/nemesis/alert_manager), same as `nemesis_paths` above.
import nemesis_connectivity_notify as conn_notify         # noqa: E402

_running = True


def _add_flat_log_handler() -> None:
    """Add a FileHandler in the diagnostics flat-log dir so lifecycle messages
    land in the flat log too (readable over SSH when Flask/DB are down). The dir
    is root-owned under /var/log; create it if absent — the non-root dashboard
    process must NOT assume write access, so this root service is its creator.
    """
    log_dir = diag._get_setting("watcher_log_dir", DEFAULT_LOG_DIR) or DEFAULT_LOG_DIR
    try:
        os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(os.path.join(log_dir, SERVICE_LOG_BASENAME))
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
        logging.getLogger().addHandler(fh)
    except Exception:
        log.exception("diagnostics-service: flat service log setup failed in %s", log_dir)


def _interval_seconds() -> int:
    """Cadence read fresh from settings each loop (scheduler-aware seam)."""
    try:
        return max(5, int(diag._get_setting("watcher_interval_seconds",
                                            str(DEFAULT_INTERVAL_SECONDS))))
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_SECONDS


def _gates_open() -> bool:
    """Two-gate self-gating (mirrors the canary): the diagnostics module must be
    enabled in modules_enabled AND watcher_enabled must be on. Either off -> the
    service no-ops this cycle (logs a skip) — no systemctl toggling from the UI.
    The toggle flips a flag; the service decides whether to act on it.
    """
    return (diag._module_enabled("diagnostics")
            and diag._get_setting("watcher_enabled", "0") == "1")


def _on_signal(signum, _frame) -> None:
    global _running
    log.info("diagnostics-service: received signal %d — shutting down", signum)
    _running = False


def _notify(result: dict) -> None:
    """Hand this cycle's verdict to the shared episode notifier.

    WHY THIS LIVES IN THE SERVICE HOST AND NOT IN THE MODULE. The diagnostics
    module is observe-only by deliberate design (ADR 0005) and, under ADR 0001,
    may write only its own `diagnostics_*` tables — while episode state is
    core-owned (`connectivity_episodes`) and shared with `vpn_dns_guard`. So the
    probe stays in the module and the *reporting* happens here, core-side, which
    is the same split `watchdog.py` already uses for hardware alerts.

    Raising an alert is reporting, not remediation, so this does not weaken the
    observe-only boundary — nothing here changes system state.

    NEVER raises: a broken notifier must not stop the probe loop that feeds it.
    `observe()` already guarantees that internally; this is the second belt,
    because a probe that dies because reporting failed would recreate the exact
    silence this whole change exists to remove.
    """
    verdict = result.get("verdict")
    if not verdict:
        # An absent verdict is NOT "everything is fine" — it means the probe did
        # not produce a reading. Treating it as OK would be an instrument that
        # can only report success, which is the failure shape this codebase keeps
        # finding. Skip the cycle and say so.
        log.warning("diagnostics-service: probe returned no verdict — "
                    "episode state NOT updated this cycle")
        return
    try:
        conn_notify.observe(
            source="diagnostics",
            ok=(verdict == "ALL_OK"),
            verdict=None if verdict == "ALL_OK" else verdict,
            # Controlled vocabulary only — this reaches the DB and email (Rule 8).
            # `note` is already a fixed-string field in the probe library.
            detail=result.get("note"),
        )
    except Exception:
        log.exception("diagnostics-service: connectivity notify failed")


def _probe_sleep(seconds):
    """The probe loop's wait, cooperatively throttled. The interval is already read
    fresh each loop (the scheduler-aware seam); this lets the memory ladder lengthen
    it further under RAM pressure. Falls back to the plain interruptible sleep when
    unregistered."""
    if _throttle is not None:
        _throttle.throttled_sleep(seconds, is_running=lambda: _running)
    else:
        slept = 0
        while _running and slept < seconds:
            time.sleep(1)
            slept += 1


def main() -> None:
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    # Idempotent schema init — can't assume the dashboard process ran first.
    try:
        diag._init_db()
    except Exception:
        log.exception("diagnostics-service: _init_db failed at startup")

    # Cooperative throttle seam (ADR 0006). Best-effort; throttle.py fails OPEN.
    global _throttle
    try:
        import throttle                                  # noqa: PLC0415
        import data_manager                              # noqa: PLC0415
        import database as _db_throttle                  # noqa: PLC0415
        _db_throttle.init_throttle_tables()
        _throttle = throttle.register_throttle_aware(
            "diagnostics-watcher", data_manager.DataManager(DB_PATH))
        log.info("throttle: diagnostics-watcher registered as throttle-aware")
    except Exception as exc:                             # noqa: BLE001
        _throttle = None
        log.error("throttle: could not register diagnostics-watcher (%s) -- probe "
                  "runs at normal cadence, un-throttleable, until resolved", exc)

    _add_flat_log_handler()
    # journald-visible (stdout) AND flat log (the FileHandler just added).
    log.info("diagnostics watcher started — interval=%ds, gates_open=%s",
             _interval_seconds(), _gates_open())

    while _running:
        try:
            if _gates_open():
                result = diag_watcher.run_once(actor="diagnostics-service")
                log.info("diagnostics-service: verdict=%s vpn=%s lat=%sms",
                         result.get("verdict"), result.get("vpn_connected"),
                         result.get("latency_ms"))
                _notify(result)
            else:
                log.info("diagnostics-service: self-gated off — skipping probe")
        except Exception:
            log.exception("diagnostics-service: probe cycle error")

        # Sleep in 1s increments so SIGTERM/SIGINT shut us down promptly.
        _probe_sleep(_interval_seconds())

    log.info("diagnostics watcher stopped cleanly")


if __name__ == "__main__":
    # Assert the privilege boundary against the kernel before doing any work.
    # Inert until the migrated unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    import nemesis_privsep
    nemesis_privsep.attest_from_env("diagnostics-watcher")
    main()
