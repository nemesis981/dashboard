"""Email security gateway — module scaffold. ADR 0028, build spec Stage 2.1.

WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT YET
    The module contract and lifecycle only. It registers the feature, reports
    honest status, and owns nothing else yet. The IMAP client (2.2), MIME parser
    (2.3), fast check (2.4) and storage (2.6) land as separate steps, each with
    its own tests, per the build spec's staged sequence.

    `enabled_by_default` is FALSE and `confirmation_required` is TRUE in the
    manifest, deliberately: this module reads a user's actual mailbox. Every
    other security module in this codebase observes the appliance or the
    network; this one holds a credential to a personal account and reads
    correspondence. That is a different category of thing to switch on, and it
    should never start because a default said so.

WHY IT REPORTS "not configured" RATHER THAN "stopped"
    A module with no mailbox configured and a module whose mailbox connection
    has died both have zero active connections. Those are different facts, and
    collapsing them would be this project's standing failure shape -- a state
    that "means something" standing in for a real measurement. `status()`
    distinguishes them explicitly and refuses to imply coverage it does not
    have.

DATA ACCESS
    Through `get_data_manager()` only (ADR 0006). `modules_loader.py` statically
    refuses to load a module that imports raw `sqlite3` or the bare `get_db`
    accessor, before any of its code runs -- so this is enforced, not merely
    conventional.

SCOPE BOUNDARY THAT MUST SURVIVE INTO LATER STAGES
    Nothing in this module fetches a URL. Link detonation (a later stage) is a
    separate, explicitly network-enabled engine running in a sandbox -- the
    measurement tooling that produced this feature's evidence base was
    network-free by design, and the corpora contain live malicious URLs. The
    boundary between "parse and score locally" and "deliberately visit in a
    sandbox" is the whole safety model; do not blur it by adding a convenience
    fetch here.
"""

from __future__ import annotations

import threading

from modules import NemesisModule, get_data_manager

#: Module name, used for Data Manager access control and table ownership.
#: Tables this module owns carry the `email_` prefix (ADR 0001).
MODULE_NAME = "email_security"


def _dm():
    """Data Manager handle scoped to this module (ADR 0006)."""
    return get_data_manager().connect(MODULE_NAME)


class Module(NemesisModule):
    """Email security gateway.

    Lifecycle only at this stage. `start()` does NOT open a mailbox connection
    yet -- 2.2 adds that -- and says so in `status()` rather than reporting a
    running state it has not earned.
    """

    def __init__(self, manifest: dict):
        super().__init__(manifest)
        self._lock = threading.Lock()
        self._running = False
        #: Set by 2.2 once the IMAP IDLE client exists. Kept as an explicit
        #: attribute now so `status()` has a real thing to report on rather
        #: than a hardcoded string that would later become a lie.
        self._client = None
        self._last_error: str | None = None

    # --- Lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Idempotent. Marks the module active; does not yet connect a mailbox.

        Deliberately does NOT raise when no account is configured. A user can
        legitimately enable the module before adding a mailbox, and refusing to
        start would make enabling it feel broken. `status()` carries the
        distinction instead.

        CREATES THIS MODULE'S TABLES FIRST, and deliberately BEFORE `_running`
        is set. The canonical DDL lives in `database.init_email_security_tables()`
        (ADR 0001, one CREATE per table in one place); this is the call site that
        makes it actually run. A DDL that exists in the repo but is never invoked
        is indistinguishable from no DDL at all on a fresh install -- the
        `devices`-table failure, which `init_tier2_gate_tables` was added to avoid
        and which dashboard.py's own init comments warn about verbatim. Caught in
        review by Window 2 before commit, 2026-08-25.

        A DDL failure is NOT swallowed: the module cannot function without its
        tables, so the exception propagates and the module stays STOPPED rather
        than reporting a running state it has not earned. Ordering matters --
        setting `_running` first would leave a module that claims to be running
        with no tables underneath it, which is the same false-assurance shape
        `status()` exists to prevent. Idempotent, so repeated starts are safe.

        The import is LOCAL, not top-of-file (same shape as integrity_watch's
        `import database as _db`), because `database` resolves only when
        `alert_manager/` is on the caller's path. A top-level import would make
        merely LOADING this module fail wherever that is not true -- turning a
        dependency needed only when starting into one needed to exist at all.
        Unlike integrity_watch's use, the exception is deliberately NOT caught
        and defaulted: that read wanted an optional setting, this one creates the
        tables the module cannot run without.
        """
        with self._lock:
            if self._running:
                return
            try:  # resolves under either caller PYTHONPATH shape
                import database as _db                       # noqa: PLC0415
            except ImportError:  # pragma: no cover
                from alert_manager import database as _db    # noqa: PLC0415
            _db.init_email_security_tables()
            self._running = True
            self._last_error = None

    def stop(self) -> None:
        """Idempotent. Reverses start()."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            if self._client is not None:
                try:
                    self._client.close()
                except Exception as exc:                        # noqa: BLE001
                    # Recorded, not swallowed silently: a client that failed to
                    # close is a fact worth surfacing in status(), and a stop()
                    # that raised would prevent the module being disabled.
                    self._last_error = "close failed: %s" % type(exc).__name__
                finally:
                    self._client = None

    # --- Status ------------------------------------------------------------

    def status(self) -> dict:
        """Current runtime state, with 'configured' and 'connected' separated.

        FOUR distinct states, not two. "stopped", "no mailbox configured",
        "configured but not connected", and "running" are different facts about
        whether mail is actually being examined, and a parent-level UI that
        collapsed them would show a reassuring green state for a module
        examining nothing.
        """
        with self._lock:
            running = self._running
            client = self._client
            err = self._last_error

        if not running:
            return {"state": "stopped", "detail": "module disabled"}

        try:
            accounts = self._configured_account_count()
        except Exception as exc:                                # noqa: BLE001
            # An unreadable account table is an explicit error state, never a
            # zero that would read as "no mailboxes configured".
            return {"state": "error",
                    "detail": "cannot read account config: %s"
                              % type(exc).__name__}

        if accounts == 0:
            return {"state": "running",
                    "detail": "enabled, no mailbox configured yet — "
                              "no mail is being examined"}
        if client is None:
            return {"state": "error" if err else "running",
                    "detail": err or ("%d mailbox(es) configured, not connected "
                                      "(IMAP client not built yet — build spec "
                                      "stage 2.2)" % accounts)}
        return {"state": "running",
                "detail": "%d mailbox(es) connected" % accounts}

    def _configured_account_count(self) -> int:
        """How many mailboxes are configured. Raises rather than defaulting.

        Returns 0 ONLY when the table exists and is genuinely empty. A missing
        table (before stage 2.6 creates it) is an expected condition and is
        reported as zero; any other failure propagates to `status()`, which
        renders it as an explicit error rather than as "no mailboxes".
        """
        conn = _dm()
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='email_accounts'")
            if cur.fetchone() is None:
                return 0          # table not created yet — stage 2.6
            row = conn.execute(
                "SELECT COUNT(*) FROM email_accounts WHERE enabled=1").fetchone()
            return int(row[0]) if row else 0
        finally:
            try:
                conn.close()
            except Exception:                                   # noqa: BLE001
                pass

    # --- Dashboard ---------------------------------------------------------

    def get_dashboard_card(self) -> str | None:
        """Dashboard card. Returns None until there is something honest to show.

        Deliberately None at this stage rather than a placeholder card: a card
        implying the feature is watching mail, before any mail is being read,
        is precisely the false-assurance shape this feature's own measurement
        work exists to avoid.
        """
        return None

    def get_routes(self) -> list | None:
        """No routes yet. Enrollment and verdict UI are later stages."""
        return None
