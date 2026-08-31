"""One watcher thread per enabled mailbox. ADR 0028, build spec stage 2.8.

WHAT THIS IS
    The piece that makes mail actually get scanned. Everything else existed and
    composed correctly; nothing ran it. `ImapIdleClient` had zero production
    instantiations before this file.

⚠ THE TRAP THIS FILE EXISTS TO AVOID, STATED FIRST BECAUSE IT IS THE WHOLE POINT
    `ImapIdleClient.run()` lets `ImapAuthError` PROPAGATE and END the loop, on
    purpose: retrying a credential that cannot work burns attempts against the
    provider's rate limits and turns a config error into an account-recovery
    problem.

    That is correct, and it creates a silent-failure shape one layer up. A thread
    that has exited is not connected, not retrying, and not visibly broken. If
    the supervisor merely let the thread die, a single wrong password would stop
    scanning that mailbox FOREVER while the dashboard card kept reporting the
    mailbox as configured and the module as running.

    So every terminal outcome is CAUGHT AND RECORDED as a per-account state, and
    `states()` exposes it for `status()` to render. A dead watcher is a fact the
    UI must be able to state, not an absence it has to infer.

ONE THREAD PER MAILBOX, NEVER A SHARED CONNECTION
    imap_idle documents that an IMAP connection is not safe to share across
    threads -- interleaved responses corrupt each other. One client, one mailbox,
    one thread, and no lock pretending otherwise.

THE CALLBACK MUST NEVER RAISE INTO THE CLIENT
    An exception from the scan would escape through the client's fetch loop and
    kill the watcher for every subsequent message. One malformed message must not
    stop the mailbox. `_scan_one` therefore catches everything and records the
    failure as a verdict row problem instead.

PRIVACY. Nothing here logs subjects, bodies, senders, or any message content.
    Log lines carry UIDs, counts and account ids only -- the same contract
    imap_idle keeps.
"""
from __future__ import annotations

import json
import logging
import threading

log = logging.getLogger("nemesis.email_security.supervisor")

#: Per-account watcher states. Distinct values because the fixes differ, and a
#: UI that collapsed them would tell the operator to do the wrong thing.
STARTING = "starting"          # thread launched, no connection yet
CONNECTED = "connected"        # authenticated and watching
AUTH_FAILED = "auth_failed"    # PERMANENT: credential rejected. Human fix.
CONFIG_ERROR = "config_error"  # PERMANENT: TLS/transport/credential-store fault
CRASHED = "crashed"            # unexpected: a bug, not a configuration problem
STOPPED = "stopped"            # asked to stop, exited cleanly

#: The states meaning "this mailbox is not being scanned and will not recover on
#: its own". Grouped so callers test intent rather than enumerating strings.
TERMINAL_STATES = (AUTH_FAILED, CONFIG_ERROR, CRASHED)


class _Watcher:
    """One mailbox: its thread, its client, and its last known state."""

    def __init__(self, account: dict):
        self.account = dict(account)
        self.state = STARTING
        self.detail = ""
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.client = None
        self.messages_scanned = 0

    @property
    def address(self):
        return self.account.get("address") or "<unknown>"

    def snapshot(self) -> dict:
        """State for status(). Deliberately carries no credential material."""
        return {
            "account_id": self.account.get("id"),
            "address": self.address,
            "provider": self.account.get("provider"),
            "mailbox": self.account.get("mailbox"),
            "state": self.state,
            "detail": self.detail,
            "messages_scanned": self.messages_scanned,
            "alive": bool(self.thread and self.thread.is_alive()),
        }


class MailboxSupervisor:
    """Runs a watcher per enabled mailbox. Not itself a thread.

    Constructed by `Module.start()` and shut down by `Module.stop()`. Safe to
    start and stop repeatedly.
    """

    def __init__(self, *, client_factory=None, account_loader=None):
        # Both injectable so the suite can drive the supervisor without a live
        # mailbox or a real database. Production passes neither.
        self._client_factory = client_factory or _build_client
        self._account_loader = account_loader or _load_enabled_accounts
        self._lock = threading.Lock()
        self._watchers: dict = {}
        self._started = False

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> int:
        """Launch a watcher per enabled mailbox. Returns how many started.

        Idempotent. An account whose credential cannot be resolved still gets a
        watcher RECORD in CONFIG_ERROR rather than being skipped: a mailbox that
        is enabled but unscannable must be visible, and silently omitting it
        would make the account list and the watcher list disagree with no
        indication which is right.
        """
        with self._lock:
            if self._started:
                return len(self._watchers)
            self._started = True

        try:
            accounts = self._account_loader()
        except Exception as exc:                                # noqa: BLE001
            # An unreadable account table is an explicit failure, never "no
            # mailboxes" -- the same rule Module._configured_account_count keeps.
            log.exception("email_security: cannot load accounts")
            with self._lock:
                self._started = False
            raise

        # Same decide-and-insert-under-one-hold discipline as refresh(), and for
        # the same reason. Not reachable through the toggle route today --
        # modules_loader only publishes the instance AFTER start() returns, and
        # _guard_view 503s until then, so nothing can call refresh() while this
        # runs. That is an accident of the loader's ordering, not a property of
        # this class, so the defence lives here rather than depending on it.
        to_start = []
        with self._lock:
            for acct in accounts:
                acct_id = acct.get("id")
                if acct_id in self._watchers:
                    continue
                w = _Watcher(acct)
                w.thread = threading.Thread(
                    target=self._watch, args=(w,),
                    name="email-watch-%s" % (acct_id,), daemon=True)
                self._watchers[acct_id] = w
                to_start.append(w)
        for w in to_start:
            w.thread.start()
        started = len(to_start)
        log.info("email_security: supervisor started %d watcher(s)", started)
        return started

    def refresh(self) -> dict:
        """Reconcile running watchers against the CURRENT enabled set.

        ⚠ WITHOUT THIS, TOGGLING `enabled` IS A LIE UNTIL THE NEXT RESTART.
        `start()` reads the enabled accounts once. An admin who switches scanning
        ON would get a row saying `enabled=1`, an API reply saying success, and
        NO WATCHER -- and because `status()` reports the SUPERVISOR's states, the
        mailbox would not even appear as a problem. It would simply be absent:
        enabled, unwatched, and invisible. That is precisely the silent
        non-coverage this module's status() exists to refuse, arriving through
        the one door that looks like it turns scanning on.

        Returns {"started": n, "stopped": n} -- counts, so a caller can report
        what actually happened rather than assuming it worked.

        A watcher in a TERMINAL state for an account that is still enabled is
        left alone: nothing about it has changed, and silently respawning it
        would hide a permanent fault behind a restart loop. Toggling the account
        off and on is the deliberate "try again", and that path works because the
        off pass removes the watcher entirely.
        """
        with self._lock:
            if not self._started:
                # Module stopped. Reconciling would resurrect watchers the
                # lifecycle deliberately tore down.
                return {"started": 0, "stopped": 0}

        # The DB read happens OUTSIDE the lock -- it is I/O, and holding a lock
        # across it would serialise every status() call behind a query.
        accounts = self._account_loader()
        want = {a.get("id"): a for a in accounts}

        # ⛔ DECIDE AND INSERT UNDER ONE LOCK HOLD. THIS IS NOT STYLE.
        #
        # This was previously read-then-decide-then-insert with the lock dropped
        # in between, and the insert was an unconditional `=`. Two concurrent
        # refreshes -- an admin double-clicking the toggle is enough, Flask being
        # threaded -- both computed the same `to_start`, both spawned a watcher,
        # and the second OVERWROTE the first in the dict. The first watcher was
        # then live and unreachable: `stop()` and the stop pass below both
        # iterate `self._watchers`, which no longer contained it, so its
        # stop_event was never set and its client never closed.
        #
        # REPRODUCED 2026-08-31 before fixing: 2 threads started, 1 tracked, and
        # 1 STILL READING after stop() returned. For a route whose entire purpose
        # is that consent to read someone's mail can be withdrawn, a withdrawal
        # that reports success while a watcher keeps reading is the worst
        # available outcome -- worse than never having built the toggle.
        #
        # `_started` is RE-CHECKED here, and that closes a second hole: the
        # check at the top of this method was a TOCTOU. The lock was dropped for
        # the DB read above, during which stop() could run to completion --
        # setting _started False, signalling every watcher and clearing the dict
        # -- after which this method would compute `have` as empty and start a
        # watcher for EVERY enabled mailbox on a module that had just been
        # disabled. status() would report "stopped" while scanning continued.
        # stop() sets _started under this same lock, so re-checking it here makes
        # that ordering impossible rather than merely unlikely.
        stopped, to_start = [], []
        with self._lock:
            if not self._started:
                return {"started": 0, "stopped": 0}
            for acct_id in [i for i in self._watchers if i not in want]:
                stopped.append(self._watchers.pop(acct_id))
            for acct_id, acct in want.items():
                # SKIP, never overwrite. A watcher already tracked for this id is
                # the one running; replacing it strands a live thread.
                if acct_id in self._watchers:
                    continue
                w = _Watcher(acct)
                # The Thread object is built and attached BEFORE the watcher
                # becomes visible, so a concurrent states() can never observe a
                # tracked watcher with thread=None and report "alive": False for
                # something that is about to be alive.
                w.thread = threading.Thread(
                    target=self._watch, args=(w,),
                    name="email-watch-%s" % (acct_id,), daemon=True)
                self._watchers[acct_id] = w
                to_start.append(w)

        # Threads are STARTED outside the lock: _watch() runs indefinitely and
        # starting under the lock would hold it for the life of the watcher.
        for w in stopped:
            w.stop_event.set()
            if w.client is not None:
                try:
                    w.client.close()      # unblocks a socket read promptly
                except Exception:         # noqa: BLE001
                    pass
        for w in to_start:
            w.thread.start()
        started = len(to_start)

        # Joined AFTER the new ones are launched so a slow shutdown does not
        # delay scanning starting on a mailbox someone just switched on.
        for w in stopped:
            if w.thread is not None:
                w.thread.join(timeout=5.0)

        if started or stopped:
            log.info("email_security: supervisor refreshed (+%d, -%d)",
                     started, len(stopped))
        return {"started": started, "stopped": len(stopped)}

    def stop(self, timeout: float = 10.0) -> None:
        """Signal every watcher to stop and wait briefly. Idempotent.

        Threads are daemons, so a watcher blocked in a socket read cannot hold
        shutdown open indefinitely. The join is best-effort and its failure is
        recorded rather than raised -- a stop() that raised would prevent the
        module being disabled, which is the one thing stop() must always allow.
        """
        with self._lock:
            watchers = list(self._watchers.values())
            self._started = False

        for w in watchers:
            w.stop_event.set()
            if w.client is not None:
                try:
                    w.client.close()          # unblocks a socket read promptly
                except Exception:             # noqa: BLE001
                    pass
        for w in watchers:
            if w.thread is not None:
                w.thread.join(timeout=timeout)
                if w.thread.is_alive():
                    log.warning("email_security: watcher for account %s did not "
                                "stop within %.0fs", w.account.get("id"), timeout)
        with self._lock:
            self._watchers.clear()

    # --- state -------------------------------------------------------------

    def states(self) -> list:
        """Snapshot of every watcher. The input to an honest status()."""
        with self._lock:
            return [w.snapshot() for w in self._watchers.values()]

    def problem_accounts(self) -> list:
        """Watchers in a terminal state -- enabled mailboxes NOT being scanned.

        This is the accessor that keeps a dead watcher from being invisible.
        """
        return [s for s in self.states() if s["state"] in TERMINAL_STATES]

    # --- the watcher thread ------------------------------------------------

    def _watch(self, w: _Watcher) -> None:
        """One mailbox, until stopped or permanently broken.

        EVERY exit path sets a state. A thread that ended without one would be
        exactly the invisible failure this module exists to prevent.
        """
        from . import imap_idle                                  # noqa: PLC0415
        try:
            client = self._client_factory(w.account, self._make_callback(w))
        except Exception as exc:                                 # noqa: BLE001
            # Credential missing/unreadable, unknown provider, refused TLS
            # config -- all permanent and all a human's to fix.
            w.state = CONFIG_ERROR
            w.detail = _safe_detail(exc)
            log.error("email_security: watcher for account %s cannot start: %s",
                      w.account.get("id"), w.detail)
            return

        w.client = client
        try:
            w.state = CONNECTED
            client.run(w.stop_event)
            # run() returns only when stop was set.
            w.state = STOPPED
            w.detail = ""
        except imap_idle.ImapAuthError as exc:
            # ⚠ THE CASE THIS FILE EXISTS FOR. Permanent by design in the client;
            # made VISIBLE here. Without this the mailbox silently stops being
            # scanned while everything above still reports healthy.
            w.state = AUTH_FAILED
            w.detail = _safe_detail(exc)
            log.error("email_security: authentication failed for account %s -- "
                      "this mailbox is NO LONGER BEING SCANNED until the "
                      "credential is replaced: %s",
                      w.account.get("id"), w.detail)
        except imap_idle.ImapConfigError as exc:
            w.state = CONFIG_ERROR
            w.detail = _safe_detail(exc)
            log.error("email_security: transport misconfigured for account %s -- "
                      "not retried, mailbox NOT being scanned: %s",
                      w.account.get("id"), w.detail)
        except Exception as exc:                                 # noqa: BLE001
            # A bug, not a configuration problem. Distinguished so nobody is
            # sent to check a password over what is actually a defect here.
            w.state = CRASHED
            w.detail = _safe_detail(exc)
            log.exception("email_security: watcher for account %s crashed",
                          w.account.get("id"))
        finally:
            try:
                client.close()
            except Exception:                                    # noqa: BLE001
                pass

    # --- the scan callback -------------------------------------------------

    def _make_callback(self, w: _Watcher):
        """Build the on_message callback bound to this account."""
        def _on_message(uid, raw):
            self._scan_one(w, uid, raw)
        return _on_message

    def _scan_one(self, w: _Watcher, uid, raw) -> None:
        """parse -> check -> persist, for ONE message.

        ⚠ NEVER RAISES. An exception here would escape through the client's
        fetch loop and kill the watcher, so one malformed or hostile message
        would stop the mailbox for every message behind it -- a denial of
        service delivered by email, which is precisely the shape mime_parse
        already refuses to have. Failures become a recorded problem instead.
        """
        from . import fast_check, mime_parse, sender_id, writes  # noqa: PLC0415
        from . import providers                                  # noqa: PLC0415

        account_id = w.account.get("id")
        uidvalidity = getattr(w.client, "uidvalidity", None)
        if uidvalidity is None:
            # A UID without its UIDVALIDITY cannot be keyed correctly: the
            # verdict table's uniqueness spans both, and inventing a 0 would
            # collapse this message onto another mailbox generation's row.
            # Refusing to write is the honest outcome.
            log.warning("email_security: no UIDVALIDITY for account %s; "
                        "skipping verdict for uid %s", account_id, uid)
            return

        try:
            parsed = mime_parse.parse(raw)
        except Exception as exc:                                 # noqa: BLE001
            # mime_parse documents that it never raises; this is belt and braces
            # so a regression there cannot take the watcher down with it.
            log.error("email_security: parse failed for account %s uid %s: %s",
                      account_id, uid, type(exc).__name__)
            return

        try:
            # Same resolution point as _build_client. This used to call
            # providers.get() directly, which raises for a custom provider --
            # and the handler below swallowed it, so a self-hosted mailbox
            # scanned NOTHING while reporting a healthy connected watcher.
            #
            # The anchor is NULL-on-row -> provider value -> unmatchable
            # sentinel. "We have not confirmed this provider's identity" and
            # "this is a custom domain" both end at a value no real header can
            # equal, so fast_check finds a mismatch and refuses to read the
            # verdicts. Never a falsy value, which would make it trust ANY
            # Authentication-Results header, including a forged one.
            from . import settings_resolve                        # noqa: PLC0415
            authserv = settings_resolve.for_account(w.account)["authserv_id"]
            result = fast_check.check(parsed, expect_authserv_id=authserv)
        except Exception as exc:                                 # noqa: BLE001
            log.error("email_security: check failed for account %s uid %s: %s",
                      account_id, uid, type(exc).__name__)
            return

        headers = getattr(parsed, "headers", {}) or {}
        auth = result.auth
        try:
            writes.record_verdict(
                account_id, uidvalidity, int(uid),
                # ⚠ verdict STAYS None. fast_check returns signals and auth
                # facts and deliberately NO verdict -- combining them is a
                # separate decision with its own measurement requirement (D9).
                # Writing "clean" here to fill the column would manufacture a
                # judgement nothing made, and it would be served with full
                # confidence to a UI that cannot tell it was invented.
                verdict=None, confidence=None, reason=None,
                signals_json=json.dumps(result.to_dict(), sort_keys=True,
                                        default=str),
                message_id_hdr=_first(headers.get("message_id")),
                received_at=_first(headers.get("date")),
                auth_spf=(auth.spf if auth else None),
                auth_dkim=(auth.dkim if auth else None),
                auth_dmarc=(auth.dmarc if auth else None),
                dmarc_policy=(auth.dmarc_policy if auth else None),
                auth_problems=(",".join(auth.problems) if auth and auth.problems
                               else None),
                # None is a legitimate value meaning UNKNOWN (no salt, or no
                # parseable From). sender_id refuses to fall back to an
                # unsalted digest, which would be reversible against a contact
                # list -- so NULL here must never be read as "a new sender".
                sender_hash=sender_id.sender_token(_first(headers.get("from"))),
            )
        except Exception as exc:                                 # noqa: BLE001
            log.error("email_security: could not record verdict for account %s "
                      "uid %s: %s", account_id, uid, type(exc).__name__)
            return

        w.messages_scanned += 1
        # COUNT AND UID ONLY. Never a subject, sender, or body.
        log.info("email_security: scanned uid %s for account %s", uid, account_id)


# ── helpers ─────────────────────────────────────────────────────────────────

def _first(value):
    """Headers arrive as a list or a scalar depending on the header. Take one."""
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else None
    return str(value) if value else None


def _safe_detail(exc) -> str:
    """A short, non-secret description of a failure.

    Truncated and type-prefixed. An exception message from the IMAP layer can
    echo server output, so this is kept short and is never rendered anywhere a
    credential could be reconstructed from it.
    """
    return ("%s: %s" % (type(exc).__name__, exc))[:300]


def _load_enabled_accounts() -> list:
    """Every mailbox with scanning switched ON.

    `enabled=0` is the default at enrollment on purpose -- adding a mailbox and
    beginning to read it are two different consents -- so this deliberately does
    NOT pick up freshly enrolled accounts until someone turns them on.
    """
    from modules import get_data_manager                         # noqa: PLC0415
    conn = get_data_manager().connect("email_security")
    try:
        cur = conn.execute(
            "SELECT id, address, provider, imap_host, imap_port, mailbox, "
            "       credential_ref, tls_mode, authserv_id "
            "  FROM email_accounts WHERE enabled=1")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def _build_client(account: dict, on_message):
    """Construct a configured client for one account.

    Raises on a missing credential or unknown provider rather than returning a
    client that cannot work -- the caller records that as CONFIG_ERROR, which is
    a visible state. A client built with an empty password would instead fail as
    an authentication error and send someone to check a password that was never
    stored.
    """
    from . import credential_store, imap_idle                    # noqa: PLC0415
    from . import settings_resolve                                # noqa: PLC0415

    # ONE resolution point, shared with the scan callback. Previously this and
    # the callback each did providers.get(row["provider"]) independently, which
    # raises for a custom/self-hosted mailbox -- here it surfaced as
    # CONFIG_ERROR, there it was swallowed and the message silently not scanned.
    cfg = settings_resolve.for_account(account)
    secret = credential_store.get_secret(account["credential_ref"])

    return imap_idle.ImapIdleClient(
        account["address"], secret,
        # Transport comes from the ROW (what enrollment actually recorded, so a
        # later providers.py edit cannot redirect or downgrade an existing
        # mailbox); allow_self_signed comes from the provider TABLE only,
        # because it is a privilege and not a setting. See for_account().
        host=cfg["imap_host"],
        port=cfg["imap_port"],
        mailbox=account.get("mailbox") or "INBOX",
        on_message=on_message,
        tls_mode=cfg["tls_mode"],
        allow_self_signed=cfg["allow_self_signed"],
        provider=cfg["provider"],
        strip_inner_whitespace=prov.get("strip_inner_whitespace", True),
    )
