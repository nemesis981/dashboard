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
DB_PATH = os.path.join(_HERE, "alerts.db")
DEFAULT_INTERVAL_SECONDS = 60
DEFAULT_LOG_DIR = "/var/log/nemesis/diagnostics"
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


def main() -> None:
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    # Idempotent schema init — can't assume the dashboard process ran first.
    try:
        diag._init_db()
    except Exception:
        log.exception("diagnostics-service: _init_db failed at startup")

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
            else:
                log.info("diagnostics-service: self-gated off — skipping probe")
        except Exception:
            log.exception("diagnostics-service: probe cycle error")

        # Sleep in 1s increments so SIGTERM/SIGINT shut us down promptly.
        interval = _interval_seconds()
        slept = 0
        while _running and slept < interval:
            time.sleep(1)
            slept += 1

    log.info("diagnostics watcher stopped cleanly")


if __name__ == "__main__":
    main()
