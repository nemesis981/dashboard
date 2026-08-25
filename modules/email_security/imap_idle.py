"""Gmail IMAP IDLE client. ADR 0028 D2/D3, build spec Stage 2.2.

SCOPE: GMAIL ONLY, AND DELIBERATELY NOT GENERALISED
    The build spec is explicit that this must not become a provider-agnostic
    IMAP client. Outlook.com personal accounts are deferred precisely because
    they need XOAUTH2 and a registered Microsoft OAuth app -- the
    registration/review cost ADR 0028 D1 chose IMAP to avoid. A generic client
    is how that cost sneaks back in through the back door: someone adds a
    `provider=` argument, then an OAuth branch, and the deferral has silently
    been reversed by refactoring rather than by decision.

    Gmail app passwords are a TRANSITIONAL mechanism with no announced removal
    date. This client is a real but shrinking escape hatch, not a foundation.

CREDENTIALS ARE PARAMETERS, NEVER READ FROM CONFIG HERE
    The client takes host/user/password as constructor arguments and reads no
    file, environment variable, or database. That keeps it unit-testable
    without a live mailbox, and keeps credential sourcing a caller's concern --
    verification harnesses pass test credentials; production will pass values
    from the `email_accounts` table (Stage 2.6). Nothing about this module
    needs to know which.

PUSH-DRIVEN, AND A MISSING IDLE IS A LOUD FAILURE -- NEVER A POLLING FALLBACK
    `imaplib.IMAP4.idle()` is new in Python 3.14. On an older interpreter it
    does not exist, and the tempting fallback is to poll instead.

    That fallback is refused deliberately. Polling would LOOK like it works --
    messages would still arrive, tests would pass, the dashboard would show a
    connected mailbox -- while silently not being push-driven, which is the
    entire point of this stage. It is the project's standing "default that
    means something" failure: a degraded mode indistinguishable from the real
    one from the outside. A missing `idle()` raises at CONSTRUCTION time, not
    at first use, so the failure surfaces where it can be understood.

AUTH FAILURE IS PERMANENT; NETWORK FAILURE IS TRANSIENT. THEY ARE NOT THE SAME
    A wrong app password will never succeed on retry, and retrying it in a loop
    risks Google rate-limiting or locking the account -- turning a
    configuration error into an account-recovery problem. `ImapAuthError` is
    therefore raised and NOT retried; only `ImapTransientError` is.

PRIVACY
    This reads a real person's mail. Nothing here logs, prints, or stores
    subjects, bodies, senders, or any message content. Raw bytes are handed to
    the caller's callback and released; what the caller does with them is the
    caller's contract to keep. Log lines carry counts and UIDs only.

NOTHING HERE EVER FETCHES A URL. Link detonation is a separate, deliberately
network-enabled sandboxed engine. The boundary between "parse locally" and
"visit in a sandbox" is the safety model; a convenience fetch here would erase
it silently.
"""

from __future__ import annotations

import imaplib
import logging
import re
import socket
import ssl
import threading

log = logging.getLogger("email_security.imap")

#: RFC 2177 requires the client to re-issue IDLE at least every 29 minutes;
#: servers may drop a longer-lived idle. 25 minutes leaves margin for a slow
#: round trip without sitting near the limit.
DEFAULT_IDLE_SECONDS = 25 * 60

#: Gmail's IMAP endpoint. Hardcoded default rather than a parameter default of
#: "" -- an empty host would fail in a way that reads like a network problem.
GMAIL_IMAP_HOST = "imap.gmail.com"
GMAIL_IMAP_PORT = 993

#: An untagged EXISTS response is how the server announces new mail during
#: IDLE. Matched strictly: a loose match that also accepted EXPUNGE or FETCH
#: would make the client "detect" mail that did not arrive.
_EXISTS_RE = re.compile(rb"^\*?\s*(\d+)\s+EXISTS\s*$", re.I)


class ImapError(RuntimeError):
    """Base for this module. Callers can catch one type."""


class ImapAuthError(ImapError):
    """Credential or account-configuration failure. PERMANENT -- do not retry.

    Covers a wrong app password, 2FA disabled (which invalidates app
    passwords), and IMAP switched off in Gmail settings. All three surface
    as an IMAP login failure and all three are fixed by a human, not by
    another attempt.
    """


class ImapTransientError(ImapError):
    """Network, TLS, or server-side failure. Retryable with backoff."""


class ImapUnsupported(ImapError):
    """The interpreter cannot support push IDLE. Raised at construction."""


def _idle_supported() -> bool:
    """True when the stdlib provides native IDLE (Python 3.14+)."""
    return hasattr(imaplib.IMAP4, "idle")


class ImapIdleClient:
    """One Gmail mailbox, watched by IMAP IDLE.

    Not thread-safe by design: one client, one mailbox, one thread. Sharing an
    IMAP connection across threads is a well-known source of interleaved-response
    corruption, and a lock here would imply a safety this protocol does not have.
    """

    def __init__(self, user: str, app_password: str,
                 host: str = GMAIL_IMAP_HOST, port: int = GMAIL_IMAP_PORT,
                 mailbox: str = "INBOX",
                 on_message=None,
                 idle_seconds: int = DEFAULT_IDLE_SECONDS):
        if not _idle_supported():
            raise ImapUnsupported(
                "imaplib.IMAP4.idle() is unavailable on this interpreter "
                "(needs Python 3.14+). Refusing to construct rather than "
                "falling back to polling: a polling client would appear to "
                "work while silently not being push-driven.")
        if not user or not app_password:
            # Explicit, not a silent connect-and-fail: an empty credential
            # produces an auth error that reads like a wrong password.
            raise ValueError("user and app_password are both required")

        self.user = user
        # Google displays app passwords in four groups of four. Strip
        # whitespace here so a pasted value with spaces does not fail as what
        # looks like a wrong password.
        self._pw = "".join(app_password.split())
        self.host = host
        self.port = port
        self.mailbox = mailbox
        self.on_message = on_message
        self.idle_seconds = idle_seconds

        self._conn: imaplib.IMAP4_SSL | None = None
        self._uidvalidity: bytes | None = None
        self._last_uid: int | None = None
        self.capabilities: tuple = ()

    # ── Connection ─────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Open TLS, authenticate, select the mailbox. Idempotent."""
        if self._conn is not None:
            return
        try:
            conn = imaplib.IMAP4_SSL(
                self.host, self.port, ssl_context=ssl.create_default_context())
        except (OSError, ssl.SSLError) as exc:
            raise ImapTransientError(
                "connect to %s:%d failed: %s"
                % (self.host, self.port, type(exc).__name__)) from exc

        try:
            conn.login(self.user, self._pw)
        except imaplib.IMAP4.error as exc:
            try:
                conn.logout()
            except Exception:                                   # noqa: BLE001
                pass
            # Deliberately does NOT include the password or the server's raw
            # message, which can echo credential material.
            raise ImapAuthError(
                "login failed for %s -- check the app password, that 2-Step "
                "Verification is enabled, and that IMAP is turned on in Gmail "
                "settings. Not retried: none of those is fixed by retrying."
                % _mask(self.user)) from exc

        self.capabilities = conn.capabilities
        self._conn = conn
        self._select()

    def _select(self) -> None:
        conn = self._require_conn()
        try:
            typ, data = conn.select(self.mailbox, readonly=True)
        except imaplib.IMAP4.error as exc:
            raise ImapTransientError("SELECT %s failed: %s"
                                     % (self.mailbox, exc)) from exc
        if typ != "OK":
            raise ImapTransientError("SELECT %s returned %s"
                                     % (self.mailbox, typ))

        # UIDVALIDITY is the contract that makes stored UIDs meaningful. If the
        # server changes it, every UID this client remembers refers to nothing,
        # and treating the old high-water mark as current would silently skip
        # every message in the rebuilt mailbox. Detected explicitly and reset.
        typ, uv = conn.status(self.mailbox, "(UIDVALIDITY)")
        new_uv = None
        if typ == "OK" and uv and uv[0]:
            m = re.search(rb"UIDVALIDITY\s+(\d+)", uv[0])
            if m:
                new_uv = m.group(1)
        if new_uv is None:
            raise ImapTransientError(
                "could not read UIDVALIDITY for %s -- refusing to track UIDs "
                "without it, since a stale high-water mark silently skips mail"
                % self.mailbox)
        if self._uidvalidity is not None and new_uv != self._uidvalidity:
            log.warning("UIDVALIDITY changed for %s (%s -> %s); resetting "
                        "the high-water mark", self.mailbox,
                        self._uidvalidity, new_uv)
            self._last_uid = None
        self._uidvalidity = new_uv

        if self._last_uid is None:
            # Start from "now": this stage watches for ARRIVING mail, and
            # back-scanning an existing mailbox is a different operation with
            # different privacy implications. Recorded rather than assumed.
            self._last_uid = self._highest_uid()

    def close(self) -> None:
        """Idempotent. Safe to call on a half-open connection."""
        conn, self._conn = self._conn, None
        if conn is None:
            return
        for step in (conn.close, conn.logout):
            try:
                step()
            except Exception:                                   # noqa: BLE001
                pass

    def _require_conn(self) -> imaplib.IMAP4_SSL:
        if self._conn is None:
            raise ImapError("not connected -- call connect() first")
        return self._conn

    # ── UID tracking ───────────────────────────────────────────────────────

    def _highest_uid(self) -> int:
        """Highest UID currently in the mailbox, or 0 when empty.

        Raises on a failed search rather than returning 0. A search failure and
        an empty mailbox both produce "no UIDs", and defaulting the first to 0
        would set the high-water mark to zero -- which would then treat every
        message in the mailbox as newly arrived.
        """
        conn = self._require_conn()
        typ, data = conn.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise ImapTransientError("UID SEARCH failed: %s" % typ)
        if not data or not data[0]:
            return 0
        return max(int(x) for x in data[0].split())

    def new_uids(self) -> list[int]:
        """UIDs above the high-water mark. Does not advance it."""
        conn = self._require_conn()
        if self._last_uid is None:
            raise ImapError("high-water mark not initialised")
        typ, data = conn.uid("SEARCH", None, "UID %d:*" % (self._last_uid + 1))
        if typ != "OK":
            raise ImapTransientError("UID SEARCH failed: %s" % typ)
        if not data or not data[0]:
            return []
        # `UID n:*` is inclusive of n when the mailbox has nothing above it, so
        # the range can return the high-water mark itself. Filtered explicitly.
        return sorted(u for u in (int(x) for x in data[0].split())
                      if u > self._last_uid)

    def fetch_raw(self, uid: int) -> bytes:
        """Raw RFC822 bytes for one UID. Never logged, never stored here."""
        conn = self._require_conn()
        typ, data = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
        # BODY.PEEK, not BODY: fetching with BODY sets \Seen and would mark the
        # user's mail as read merely by scanning it. A security tool must not
        # mutate the mailbox it observes.
        if typ != "OK":
            raise ImapTransientError("UID FETCH %d failed: %s" % (uid, typ))
        for part in data or []:
            if isinstance(part, tuple) and len(part) > 1 and part[1]:
                return part[1]
        raise ImapTransientError("UID FETCH %d returned no body" % uid)

    # ── The IDLE loop ──────────────────────────────────────────────────────

    @staticmethod
    def announces_new_mail(responses) -> bool:
        """True when an IDLE response batch announces arriving mail.

        Static and pure so it can be tested without a server -- and it needs to
        be, because a loose match here would make the client report mail that
        never arrived, while a too-strict one would make it miss mail silently.
        Both failures are invisible from the outside.
        """
        for item in responses or []:
            typ, data = (item if isinstance(item, tuple) and len(item) == 2
                         else (item, None))
            if isinstance(typ, str):
                typ = typ.encode()
            if typ and _EXISTS_RE.match(typ.strip()):
                return True
            for d in (data or []):
                if isinstance(d, str):
                    d = d.encode()
                if isinstance(d, bytes) and _EXISTS_RE.match(d.strip()):
                    return True
        return False

    def idle_once(self, duration: int | None = None) -> list[int]:
        """One IDLE cycle. Returns UIDs of messages that arrived during it.

        Advances the high-water mark only for UIDs actually returned, so a
        crash mid-batch cannot skip messages on the next run.
        """
        conn = self._require_conn()
        secs = duration if duration is not None else self.idle_seconds
        try:
            with conn.idle(duration=secs) as idler:
                for typ, data in idler:
                    if self.announces_new_mail([(typ, data)]):
                        break
        except (imaplib.IMAP4.abort, OSError, ssl.SSLError,
                socket.timeout) as exc:
            raise ImapTransientError(
                "IDLE aborted: %s" % type(exc).__name__) from exc

        uids = self.new_uids()
        for uid in uids:
            if self.on_message is not None:
                raw = self.fetch_raw(uid)
                self.on_message(uid, raw)
            self._last_uid = max(self._last_uid or 0, uid)
        if uids:
            log.info("email_security: %d new message(s) in %s",
                     len(uids), self.mailbox)   # count only, never content
        return uids

    def run(self, stop: threading.Event) -> None:
        """Watch until `stop` is set. Reconnects on transient failure only.

        An `ImapAuthError` propagates and ENDS the loop: retrying a credential
        that cannot work would burn attempts against Google's rate limits and
        turn a config error into an account problem.
        """
        backoff = 5
        while not stop.is_set():
            try:
                self.connect()
                self.idle_once()
                backoff = 5
            except ImapAuthError:
                raise
            except ImapTransientError as exc:
                log.warning("email_security: %s; reconnecting in %ds",
                            exc, backoff)
                self.close()
                stop.wait(backoff)
                backoff = min(backoff * 2, 300)


def _mask(addr: str) -> str:
    """An address reduced enough to identify the account without printing it."""
    if "@" not in addr:
        return (addr[:2] + "***") if addr else "<empty>"
    local, _, domain = addr.partition("@")
    return "%s***@%s" % (local[:3], domain)


# ── Canary ──────────────────────────────────────────────────────────────────

def selftest() -> tuple[bool, str]:
    """Prove `announces_new_mail` can produce BOTH answers before it is trusted.

    The classifier decides whether the client believes mail arrived. One that
    always said True would fetch constantly; one that always said False would
    watch a mailbox forever and report a healthy connection while detecting
    nothing. Neither looks wrong from the outside, which is why this runs
    rather than living only in the test suite.
    """
    must_fire = [
        [(b"* 1 EXISTS", None)],
        [(b"EXISTS", [b"* 4 EXISTS"])],
        [(b"* 12 EXISTS", None)],
    ]
    must_not = [
        [],
        [(b"* 1 EXPUNGE", None)],
        [(b"* OK Still here", None)],
        [(b"* 3 FETCH (FLAGS (\\Seen))", None)],
        [(b"* 0 RECENT", None)],
    ]
    for i, r in enumerate(must_fire):
        if not ImapIdleClient.announces_new_mail(r):
            return False, "canary: EXISTS case %d not detected" % (i + 1)
    for i, r in enumerate(must_not):
        if ImapIdleClient.announces_new_mail(r):
            return False, ("canary: non-EXISTS case %d falsely reported new "
                           "mail" % (i + 1))
    return True, "8 canaries pass (3 must-fire, 5 must-not)"
