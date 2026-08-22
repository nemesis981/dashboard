"""
integrity_watch — server-side cross-checks that do not depend on agent honesty.

WHY THIS EXISTS
---------------
`scan_tasks` carries the server's own warning, in its schema comment: results are
ATTESTED CLAIMS, not ground truth. `status='completed'` means the agent SAID it
completed. There is no agent self-integrity check anywhere in the tree, so an
attacker who replaces agent code gets an agent that reports success with no
findings, indefinitely, and every other signal keeps looking healthy.

Every check in this module runs SERVER-SIDE against data the agent must produce.
That is the point: an attacker who owns the agent cannot switch these off. Agent
self-attestation (Tier 1/2) raises the cost of tampering but is a self-report and
can be neutered along with everything else; these cannot.

OBSERVE-ONLY, DELIBERATELY (decision A2)
----------------------------------------
This module records and surfaces. It does NOT quarantine, block, or refuse task
dispatch. Legitimate partial upgrades will produce false positives, and acting on
an uncalibrated signal is how a fleet outage happens. The same discipline ADR 0019
used: observe until the false-positive rate is measured, then decide about
enforcement. Escalation is a separate, later decision.

THE MEASUREMENT TRAP THIS MODULE IS BUILT AROUND
------------------------------------------------
"Zero findings" is the NORMAL, healthy state for most devices. A naive
"no findings = suspicious" rule flags the entire fleet and is worse than nothing.
Worse, the obvious framing -- compare a device against the fleet -- silently fails
at home scale, where there may be one device and no distribution to compare
against.

So every verdict here is one of three states, never two:

    ok           - measured, and nothing anomalous
    flag         - measured, and anomalous
    undetermined - NOT MEASURABLE (too few scans, or too small a fleet)

`undetermined` must never be rendered or read as `ok`. A check that cannot run is
not a check that passed, and collapsing those two is precisely the failure this
codebase keeps finding in its own verification code.
"""

import datetime
import html
import logging
import os
import sys
import threading

from modules import NemesisModule, get_data_manager

# Bounded evaluation cadence. Bare import off alert_manager/, the idiom every
# service here uses — the dashboard unit's PYTHONPATH does not include the repo
# root, so `from alert_manager import bounded` would work only by accident of
# where dashboard.py lives.
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "alert_manager"))
import bounded as _bounded                                        # noqa: E402

log = logging.getLogger(__name__)

MODULE = "integrity_watch"

#: How soon after start the first evaluation runs. Deliberately short: the whole
#: reason this module was found dormant is that nothing ever invoked it, and a
#: loop whose first output is 24 hours away is indistinguishable from one that
#: does not work — for a full day, every restart.
FIRST_RUN_DELAY_SECONDS = 60

#: Core settings key for the evaluation cadence. Stored in the CORE settings
#: table rather than a new `integrity_settings` one: ADR 0001 is read-any /
#: write-own, and this module only ever READS it. Adding a whole table (plus its
#: canonical DDL and migration) for a single integer that has no UI yet would be
#: more schema than the value justifies.
_EVAL_INTERVAL_KEY = "integrity_eval_interval_hours"


def _get_eval_interval_hours():
    """The configured cadence, or the spec default when it cannot be read.

    Returns the RAW stored value — `_bounded.resolve` does the bounding, so there
    is exactly one place that decides what an out-of-range value means. Returning
    an already-defaulted value here would hide a bad setting from resolve()'s
    warning, which is the only thing that would tell an operator their write was
    overruled.
    """
    try:
        import database as _db                                    # noqa: PLC0415
        raw = _db.get_setting(_EVAL_INTERVAL_KEY, None)
    except Exception:                                             # noqa: BLE001
        log.debug("integrity_watch: could not read %s; using default",
                  _EVAL_INTERVAL_KEY, exc_info=True)
        return _bounded.INTEGRITY_EVAL_INTERVAL_HOURS.default
    if raw is None:
        return _bounded.INTEGRITY_EVAL_INTERVAL_HOURS.default
    return raw

# Below this many completed scans, a per-device find-rate is noise, not a signal.
MIN_SCANS_FOR_SIGNAL = 10

# Below this many devices there is no fleet distribution to compare against, so
# the fleet-relative check reports `undetermined` rather than a false clean bill.
# Home installs sit below this by design -- that is expected, not a failure.
FLEET_MIN_DEVICES = 5

# Recent-vs-prior split for the self-history check.
WINDOW_DAYS = 30


def _conn():
    return get_data_manager().connect(MODULE)


def _init_db() -> None:
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS integrity_observations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at     TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            signal          TEXT NOT NULL,
            verdict         TEXT NOT NULL,
            scans_window    INTEGER,
            findings_window INTEGER,
            scans_prior     INTEGER,
            findings_prior  INTEGER,
            fleet_devices   INTEGER,
            detail          TEXT,
            -- Multi-user-ready seam (CLAUDE.md): somewhere to record WHO, even
            -- though nothing sets an actor yet. Retrofitting this later means
            -- touching every write.
            actor           TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_integrity_obs_device
            ON integrity_observations(device_id, observed_at);
    """)
    conn.commit()


_init_db()


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _cutoff(days: int) -> str:
    return (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=days)).isoformat()


def _gather() -> dict:
    """Per-device scan counts and finding counts, split recent vs prior.

    Reads across `scan_tasks` (core) and `malware_findings` (malware_detection).
    ADR 0001 read-any/write-own: reading both is in-contract; this module writes
    only its own `integrity_*` tables.
    """
    cut = _cutoff(WINDOW_DAYS)
    conn = _conn()
    devices: dict[str, dict] = {}

    def _row(dev):
        return devices.setdefault(dev, {"scans_window": 0, "scans_prior": 0,
                                        "findings_window": 0, "findings_prior": 0})

    # Denominator: what each device CLAIMS to have completed.
    for dev, recent, n in conn.execute(
            "SELECT device_id, (COALESCE(reported_at, '') >= ?), COUNT(*) "
            "FROM scan_tasks WHERE status = 'completed' "
            "GROUP BY device_id, (COALESCE(reported_at, '') >= ?)",
            (cut, cut)):
        _row(dev)["scans_window" if recent else "scans_prior"] = n

    # Numerator: what it actually produced.
    for dev, recent, n in conn.execute(
            "SELECT device_id, (COALESCE(detected_at, '') >= ?), COUNT(*) "
            "FROM malware_findings "
            "GROUP BY device_id, (COALESCE(detected_at, '') >= ?)",
            (cut, cut)):
        _row(dev)["findings_window" if recent else "findings_prior"] = n

    return devices


def evaluate(persist: bool = True) -> list[dict]:
    """Run both cross-checks. Returns one observation per device per signal.

    Never raises on an empty fleet -- it returns an empty list, and callers must
    treat that as "nothing to measure", not as "everything is fine".
    """
    devices = _gather()
    fleet_n = len(devices)
    now = _utcnow()
    out: list[dict] = []

    # Fleet find-rate, computed only over devices with enough scans to count.
    eligible = {d: v for d, v in devices.items()
                if (v["scans_window"] + v["scans_prior"]) >= MIN_SCANS_FOR_SIGNAL}
    fleet_finders = sum(1 for v in eligible.values()
                        if (v["findings_window"] + v["findings_prior"]) > 0)

    for dev, v in devices.items():
        scans = v["scans_window"] + v["scans_prior"]
        finds = v["findings_window"] + v["findings_prior"]

        # ── Signal 1: self-history regression ────────────────────────────────
        # Works at ANY fleet size, including a single device -- it compares the
        # device against its own past, not against peers. This is the shape that
        # catches an agent that WAS honest and was later replaced.
        if v["scans_window"] < MIN_SCANS_FOR_SIGNAL:
            verdict, detail = "undetermined", (
                "only %d completed scans in the last %d days (need %d) -- not measurable"
                % (v["scans_window"], WINDOW_DAYS, MIN_SCANS_FOR_SIGNAL))
        elif v["findings_prior"] > 0 and v["findings_window"] == 0:
            verdict, detail = "flag", (
                "produced %d findings historically but 0 in the last %d days "
                "across %d completed scans" % (v["findings_prior"], WINDOW_DAYS,
                                               v["scans_window"]))
        else:
            verdict, detail = "ok", (
                "%d findings across %d recent completed scans"
                % (v["findings_window"], v["scans_window"]))
        out.append(_observation(now, dev, "finding_regression", verdict, v,
                                fleet_n, detail))

        # ── Signal 2: fleet-relative outlier ─────────────────────────────────
        # Meaningful ONLY above a fleet-size threshold. Below it this reports
        # `undetermined` -- explicitly NOT `ok`. Most home installs live here,
        # and that is expected rather than a fault.
        if fleet_n < FLEET_MIN_DEVICES:
            verdict, detail = "undetermined", (
                "fleet of %d device(s) is below the %d needed for a distribution "
                "-- no peer comparison possible" % (fleet_n, FLEET_MIN_DEVICES))
        elif scans < MIN_SCANS_FOR_SIGNAL:
            verdict, detail = "undetermined", (
                "only %d completed scans total (need %d) -- not measurable" %
                (scans, MIN_SCANS_FOR_SIGNAL))
        elif finds == 0 and fleet_finders > 0:
            verdict, detail = "flag", (
                "0 findings across %d completed scans while %d of %d comparable "
                "devices found something" % (scans, fleet_finders, len(eligible)))
        else:
            verdict, detail = "ok", (
                "%d findings across %d completed scans" % (finds, scans))
        out.append(_observation(now, dev, "fleet_outlier", verdict, v,
                                fleet_n, detail))

    if persist and out:
        _persist(out)
    return out


def _observation(now, dev, signal, verdict, v, fleet_n, detail) -> dict:
    return {"observed_at": now, "device_id": dev, "signal": signal,
            "verdict": verdict, "scans_window": v["scans_window"],
            "findings_window": v["findings_window"],
            "scans_prior": v["scans_prior"], "findings_prior": v["findings_prior"],
            "fleet_devices": fleet_n, "detail": detail}


def _persist(rows: list[dict]) -> None:
    conn = _conn()
    conn.executemany(
        "INSERT INTO integrity_observations "
        "(observed_at, device_id, signal, verdict, scans_window, findings_window, "
        " scans_prior, findings_prior, fleet_devices, detail) "
        "VALUES (:observed_at, :device_id, :signal, :verdict, :scans_window, "
        ":findings_window, :scans_prior, :findings_prior, :fleet_devices, :detail)",
        rows)
    conn.commit()


def latest() -> list[dict]:
    """Most recent observation per (device, signal), for display."""
    conn = _conn()
    rows = conn.execute(
        "SELECT device_id, signal, verdict, detail, observed_at "
        "FROM integrity_observations o WHERE observed_at = ("
        "  SELECT MAX(observed_at) FROM integrity_observations "
        "  WHERE device_id = o.device_id AND signal = o.signal) "
        "ORDER BY device_id, signal").fetchall()
    return [{"device_id": r[0], "signal": r[1], "verdict": r[2],
             "detail": r[3], "observed_at": r[4]} for r in rows]


class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)

    #: Set once in start(); the loop exits promptly when it is set.
    _stop = None
    _thread = None

    def _interval_seconds(self) -> float:
        """Evaluation cadence, bounded at both ends by `bounded.py`.

        Read fresh each cycle (the scheduler-aware seam used by the canary and the
        connectivity watcher) so a change takes effect without a restart.
        """
        return _bounded.resolve(
            _get_eval_interval_hours(),
            _bounded.INTEGRITY_EVAL_INTERVAL_HOURS) * 3600.0

    def _loop(self) -> None:
        """Periodically run the cross-checks.

        WHY THIS EXISTS AT ALL. Until 2026-08-22 `evaluate()` had NO production
        caller anywhere in the repo — the module had been enabled for 18 days and
        `integrity_observations` held zero rows. Every other piece of it worked;
        nothing ever invoked it. A detector that is enabled, reports "running",
        renders a card, and never measures anything is worse than one that is
        honestly off, because the card reads as coverage.

        Never raises out of the thread: a failed evaluation must not take the
        module down, and it must not silently stop the loop either — the next
        cycle still runs.
        """
        # First run soon after start, then on the bounded interval.
        if self._stop.wait(FIRST_RUN_DELAY_SECONDS):
            return
        while not self._stop.is_set():
            try:
                obs = evaluate(persist=True)
                flags = sum(1 for o in obs if o["verdict"] == "flag")
                undet = sum(1 for o in obs if o["verdict"] == "undetermined")
                if not obs:
                    # An empty fleet is "nothing to measure", NOT "all clear".
                    # Logged distinctly so a box with no agents does not read the
                    # same as a box whose agents are all healthy.
                    log.info("integrity_watch: no devices to evaluate "
                             "(nothing measured, not a clean bill)")
                else:
                    log.info("integrity_watch: evaluated %d observations "
                             "(%d flagged, %d not measurable)",
                             len(obs), flags, undet)
            except Exception:                            # noqa: BLE001
                log.exception("integrity_watch: evaluation cycle failed")
            if self._stop.wait(self._interval_seconds()):
                return

    def start(self) -> None:
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop, name="integrity-watch-eval", daemon=True)
        self._thread.start()
        log.info("integrity_watch: enabled (observe-only), evaluating every %.1fh",
                 self._interval_seconds() / 3600.0)

    def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            # Bounded join: the loop wakes on the event, so this returns quickly.
            # Not waiting at all would let a restart run two loops concurrently.
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                log.warning("integrity_watch: evaluation thread did not stop "
                            "within 5s; it is a daemon and will not block exit")
        self._thread = None
        log.info("integrity_watch: disabled")

    def status(self) -> dict:
        try:
            obs = latest()
        except Exception as e:                       # noqa: BLE001
            log.warning("integrity_watch status failed: %s", e)
            return {"running": False, "detail": "unavailable: %s" % e}
        flags = sum(1 for o in obs if o["verdict"] == "flag")
        undet = sum(1 for o in obs if o["verdict"] == "undetermined")
        return {"running": True,
                "detail": "%d flagged, %d undetermined, %d total observations"
                          % (flags, undet, len(obs))}

    def get_dashboard_card(self) -> str:
        try:
            obs = latest()
        except Exception as e:                       # noqa: BLE001
            return ("<div class='card'><h3>Agent Integrity Watch</h3>"
                    "<p>Unavailable: %s</p></div>" % html.escape(str(e), quote=True))

        if not obs:
            return ("<div class='card'><h3>Agent Integrity Watch</h3>"
                    "<p>No observations recorded yet.</p></div>")

        flags = [o for o in obs if o["verdict"] == "flag"]
        undet = [o for o in obs if o["verdict"] == "undetermined"]

        # `undetermined` is shown SEPARATELY from `ok` on purpose. Folding them
        # together would render an unmeasurable check as a passing one, which is
        # the exact confusion this module is built to avoid.
        #
        # device_id is agent-supplied (heartbeat payload, no format validation at
        # enrollment) and reaches this render path unmodified through
        # integrity_observations -- escaped here to match the existing convention
        # at dashboard.py:3522/3579/3619/3637, the same data rendered elsewhere.
        # signal and detail are server-generated, not attacker-reachable today,
        # but escaped too rather than trusting that invariant to hold forever.
        rows = "".join(
            "<li><strong>%s</strong> &mdash; %s: %s</li>"
            % (html.escape(o["device_id"], quote=True),
               html.escape(o["signal"], quote=True),
               html.escape(o["detail"], quote=True))
            for o in flags[:5])

        return (
            "<div class='card'><h3>Agent Integrity Watch</h3>"
            "<p>%d flagged &middot; %d not measurable &middot; %d checks</p>"
            "%s"
            "<p style='font-size:0.85em;opacity:0.75'>Observe-only. Not measurable "
            "means the check could not run, not that it passed.</p></div>"
            % (len(flags), len(undet), len(obs),
               ("<ul>%s</ul>" % rows) if rows else "")
        )

    def get_routes(self):
        # No routes in this increment. A read-only view is worth adding, but any
        # new dashboard route triggers the standing route-level security audit
        # and an explicit _AUTH_EXEMPT check, so it lands as its own change.
        return None
