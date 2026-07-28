#!/usr/bin/env python3
"""TEMPLATE for a core_module process. Copy this directory, then see README.md.

Everything here exists because an earlier daemon got it wrong at least once.
Read the comments before deleting anything — several of these are load-bearing.
"""

import json
import logging
import os
import signal
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))          # /opt/nemesis
sys.path.insert(0, os.path.join(_ROOT, "alert_manager"))

import nemesis_paths                                      # noqa: E402
import nemesis_privsep                                    # noqa: E402
import data_manager as dm                                 # noqa: E402

# ── identity ─────────────────────────────────────────────────────────────────
# MUST match manifest.json's "name". It is the process's identity everywhere:
# the DM namespace key, the Settings toggle, the AI's name for it in
# troubleshooting advice, and (later) the owner field on structured error codes.
# One name, four consumers — do not let them drift.
with open(os.path.join(_HERE, "manifest.json")) as _f:
    MANIFEST = json.load(_f)
NAME = MANIFEST["name"]

log = logging.getLogger("nemesis.%s" % NAME)

_running = True


def _handle_sigterm(_signum, _frame):
    """Cooperative shutdown. systemd sends SIGTERM on stop/restart; without this
    the process is SIGKILLed after the timeout, which can leave a half-written
    transaction and makes every restart look like a crash in the journal."""
    global _running
    _running = False
    log.info("%s: SIGTERM received, finishing current cycle", NAME)


_DM = None


def _data_manager():
    """One DataManager per process, built lazily.

    A core process is standalone: it does NOT run the dashboard's module loader,
    so `modules.get_data_manager()` is never populated here. Each process builds
    its own against the canonical DB path.
    """
    global _DM
    if _DM is None:
        _DM = dm.DataManager(nemesis_paths.db_path())
    return _DM


def db():
    """Guarded connection scoped to THIS process's namespace.

    Access control is a byproduct of using this helper — that is the point. Do
    not open sqlite3 directly; a raw connection bypasses both the write-own
    check and the operation log, and there is no way to tell from the outside
    that it happened.
    """
    return _data_manager().connect(NAME)


def cycle():
    """One unit of work. Replace this.

    Keep it SHORT and idempotent. A long cycle delays shutdown (see _running)
    and widens the window where a restart loses work.
    """
    raise NotImplementedError("replace cycle() with this process's actual work")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stdout,          # journald captures stdout; do NOT log to a
    )                               # file in the code tree — /opt is read-only
                                    # under ProtectSystem=strict.
    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)

    # Attestation reads KERNEL truth (/proc/self/status), not unit config.
    # `systemctl show` reports what was CONFIGURED; several hardening directives
    # silently imply others, so configured and effective routinely disagree.
    # Inert unless the unit sets NEMESIS_EXPECT_USER.
    nemesis_privsep.attest(NAME)

    log.info("%s: starting (db=%s)", NAME, nemesis_paths.db_path())

    interval = int(os.environ.get("NEMESIS_%s_INTERVAL" % NAME.upper(), MANIFEST.get("interval_seconds", 60)))

    while _running:
        started = time.time()
        try:
            cycle()
        except Exception:
            # A crash-loop is worse than a skipped cycle: systemd's
            # StartLimitBurst will eventually refuse to restart at all, and the
            # process is then silently gone. Log loudly and keep the loop alive.
            log.exception("%s: cycle failed", NAME)
        # Sleep in short slices so SIGTERM is honoured promptly rather than
        # after a full interval.
        while _running and (time.time() - started) < interval:
            time.sleep(0.5)

    log.info("%s: stopped cleanly", NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main())
