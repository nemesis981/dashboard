"""Gmail IMAP IDLE client. ADR 0028 D2/D3, build spec Stage 2.2.

SCOPE: PASSWORD-OVER-TLS PROVIDERS ONLY. THE OAUTH DEFERRAL STILL HOLDS.
    This file used to say GMAIL ONLY. It now also serves Proton (via Proton Mail
    Bridge), and the boundary it was protecting has been RESTATED rather than
    removed, because the original warning was right about the danger and wrong
    about where the line sits.

    The danger it named: someone adds a `provider=` argument, then an OAuth
    branch, and ADR 0028 D1's deferral of Outlook.com -- taken to avoid the cost
    of registering and getting review for a Microsoft OAuth app -- has been
    reversed by refactoring instead of by decision.

    THAT REMAINS FORBIDDEN, and it is what the line actually protects. What is
    permitted here is narrower than "any provider": every supported provider
    authenticates with a plain username + app password over TLS, and only the
    TRANSPORT SHAPE varies -- implicit TLS versus STARTTLS, and whether the
    endpoint is loopback. Those are mechanical facts about where to connect, not
    a second authentication model.

    So the rule is: a provider whose only difference is transport belongs in
    `providers.py` and needs no new code path here. A provider needing a
    different way to PROVE IDENTITY -- OAuth, XOAUTH2, a token refresh -- does
    NOT belong here and is still a real decision, not a refactor. If you find
    yourself adding a token-refresh branch to `connect()`, stop.

    Gmail app passwords are a TRANSITIONAL mechanism with no announced removal
    date. Proton requires Bridge to be installed and RUNNING on this machine.
    Both are real but shrinking escape hatches, not foundations.

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

#: TLS transport shapes. Mirrors providers.TLS_* -- kept as literals here so this
#: module still imports standalone (its suite runs without the provider table),
#: and `test_imap_idle.py` asserts the two definitions are identical rather than
#: trusting this comment to stay true.
TLS_IMPLICIT = "implicit"
TLS_STARTTLS = "starttls"

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


class ImapConfigError(ImapError):
    """A PERMANENT transport or configuration fault. Never retried.

    ⚠ THIS EXISTS BECAUSE THE ABSENCE OF IT WAS A REAL, EXPENSIVE BUG.
    A TLS certificate rejection is an `ssl.SSLError`, and `connect()` used to
    wrap every `ssl.SSLError` as `ImapTransientError`. So a permanent,
    never-going-to-succeed certificate failure was treated as a passing network
    blip and retried forever with exponential backoff (5s -> 300s) -- and
    because the wrapper reported only the exception TYPE, nothing in any log
    line ever said "certificate". The observable symptom was an endless,
    unexplained reconnect loop.

    That is this project's standing "a default that means something" failure in
    its most costly form: not a wrong answer, but a wrong CLASSIFICATION that
    routes a permanent fault into the retry path and hides its cause.

    Distinguished from ImapAuthError because the fixes differ and the person
    reading the message needs to know which: an auth error means the credential
    is wrong, a config error means the connection itself is misconfigured (wrong
    TLS mode, an untrusted certificate, Bridge not running).

    `run()` does not catch this, so it propagates and ends the loop -- which is
    correct. Retrying it is exactly the bug.
    """


class ImapUnsupported(ImapError):
    """The interpreter cannot support push IDLE. Raised at construction."""


def _idle_supported() -> bool:
    """True when the stdlib provides native IDLE (Python 3.14+)."""
    return hasattr(imaplib.IMAP4, "idle")


def _is_loopback(host: str) -> bool:
    """True only for an address that cannot leave this machine.

    This gates whether an unverifiable TLS certificate may be accepted, so it
    must FAIL CLOSED: anything it cannot positively confirm as loopback is
    treated as remote. A hostname that merely resolves to 127.0.0.1 is
    deliberately NOT accepted -- resolution can change under us, and a DNS
    answer is not a property of the connection. The literal 'localhost' is
    accepted because it is not resolvable to anything else in practice.
    """
    if not isinstance(host, str) or not host.strip():
        return False
    h = host.strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        import ipaddress                                        # noqa: PLC0415
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        # Not a literal address -- a hostname. Fail closed.
        return False


def _auth_help(provider) -> str:
    """Provider-appropriate advice for a login failure.

    Imported LAZILY and defensively. This runs on an error path, and an
    ImportError raised while explaining an error would replace a useful message
    with a traceback -- so a missing providers module degrades to generic advice
    rather than obscuring the failure being reported.
    """
    try:
        try:  # resolves under either caller PYTHONPATH shape
            from modules.email_security import providers        # noqa: PLC0415
        except ImportError:                                     # pragma: no cover
            import providers                                    # noqa: PLC0415
        return providers.auth_help(provider)
    except Exception:                                           # noqa: BLE001
        # ⚠ The fallback is a genuine last resort, NOT a normal path. Reaching it
        # means every provider silently gets generic advice while the specific
        # text sits unreachable -- the Gmail-advice-to-a-Proton-user defect
        # reappearing in a quieter form. Logged so it is visible rather than
        # merely survivable. Both import shapes are tried above precisely so this
        # is not reached by an ordinary difference in how the module was loaded.
        log.warning("email_security: provider advice unavailable; falling back "
                    "to generic text for provider=%r", provider)
        return ("Check that the app password was copied correctly and is still "
                "valid with your email provider.")


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
                 idle_seconds: int = DEFAULT_IDLE_SECONDS,
                 tls_mode: str = TLS_IMPLICIT,
                 allow_self_signed: bool = False,
                 provider: str | None = None,
                 strip_inner_whitespace: bool = True):
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
        if tls_mode not in (TLS_IMPLICIT, TLS_STARTTLS):
            raise ImapConfigError(
                "unknown tls_mode %r (expected %r or %r)"
                % (tls_mode, TLS_IMPLICIT, TLS_STARTTLS))

        # ⚠ ENFORCED HERE, IN CODE, NOT MERELY DOCUMENTED. Accepting a
        # certificate nothing can verify is defensible for loopback, where there
        # is no man-in-the-middle position to occupy, and indefensible for a
        # remote host, where the certificate is the ONLY thing authenticating
        # the server. A caller that asks for both a remote host and a
        # self-signed certificate is asking to have its mail read in transit,
        # and gets refused at construction rather than at first connect.
        if allow_self_signed and not _is_loopback(host):
            raise ImapConfigError(
                "refusing to accept unverified certificates for non-loopback "
                "host %r. Certificate leniency is permitted ONLY for 127.0.0.1 "
                "/ ::1, where there is no interception position; against a "
                "remote host it removes the only thing authenticating the "
                "server." % host)

        self.user = user
        # Google displays app passwords in four groups of four, so a pasted
        # value carries spaces that are not part of the secret. Stripping them
        # is CORRECT for Gmail and WRONG in general -- a provider whose password
        # may legitimately contain a space would be silently corrupted into
        # something that fails as a wrong password. Hence a flag, set from
        # providers.py, rather than an unconditional strip.
        self._pw = ("".join(app_password.split()) if strip_inner_whitespace
                    else app_password.strip())
        self.host = host
        self.port = port
        self.tls_mode = tls_mode
        self.allow_self_signed = allow_self_signed
        #: Only used to select the right advice on an auth failure. It does NOT
        #: drive any connection behaviour -- transport comes from tls_mode/port,
        #: so a wrong provider label cannot silently change how we connect.
        self.provider = provider
        self.mailbox = mailbox
        self.on_message = on_message
        self.idle_seconds = idle_seconds

        self._conn: imaplib.IMAP4_SSL | None = None
        self._uidvalidity: bytes | None = None
        self._last_uid: int | None = None
        self.capabilities: tuple = ()

    # ── Connection ─────────────────────────────────────────────────────────

    @property
    def uidvalidity(self):
        """The mailbox's current UIDVALIDITY as an int, or None before SELECT.

        Public because a UID is meaningless without it: the verdict table's
        uniqueness constraint spans (account_id, uidvalidity, uid), so any caller
        recording a UID needs this alongside it. Returning None rather than 0
        keeps "not selected yet" distinguishable from a real value -- a 0 would
        be a legal-looking integer that silently collides across mailboxes.
        """
        if self._uidvalidity is None:
            return None
        try:
            return int(self._uidvalidity)
        except (TypeError, ValueError):
            return None

    def _ssl_context(self) -> ssl.SSLContext:
        """The TLS context for this connection.

        Verification is FULL by default. It is relaxed only when
        `allow_self_signed` is set, which the constructor permits only for a
        loopback host -- so the two checks together mean an unverified
        certificate can never be accepted from a remote server, whatever a
        caller passes.
        """
        ctx = ssl.create_default_context()
        if self.allow_self_signed:
            # Proton Mail Bridge presents a self-signed certificate for
            # 127.0.0.1 that is in no CA store. Both must be relaxed:
            # check_hostname alone still fails on an untrusted issuer, and
            # setting verify_mode while check_hostname is True raises.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def connect(self) -> None:
        """Open TLS, authenticate, select the mailbox. Idempotent.

        Two transports, chosen by `tls_mode`:
          implicit -- TLS from the first byte (IMAPS, the :993 style). Gmail.
          starttls -- plaintext connect, then upgrade. Proton Bridge's :1143.

        Using the wrong one does not degrade gracefully; it fails in the
        handshake, which is why this is explicit configuration rather than a
        guess based on port number.
        """
        if self._conn is not None:
            return
        ctx = self._ssl_context()
        try:
            if self.tls_mode == TLS_STARTTLS:
                conn = imaplib.IMAP4(self.host, self.port)
                # If STARTTLS fails we must NOT continue: the connection is
                # still plaintext and carrying on would send the app password in
                # the clear. imaplib raises on a NO/BAD response, and the
                # handler below turns that into a permanent config error.
                conn.starttls(ssl_context=ctx)
            else:
                conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx)
        except ssl.SSLCertVerificationError as exc:
            # ⚠ PERMANENT, NOT TRANSIENT -- see ImapConfigError's docstring.
            # This was previously swallowed into ImapTransientError and retried
            # forever with backoff, with nothing in any message saying
            # "certificate". Naming it here is the entire fix.
            raise ImapConfigError(
                "TLS certificate for %s:%d could not be verified (%s). This "
                "will not fix itself, so it is not retried. If this is Proton "
                "Mail Bridge on loopback, the account must be enrolled as a "
                "provider that permits its self-signed certificate."
                % (self.host, self.port, exc.verify_message or "no detail")) from exc
        except ssl.SSLError as exc:
            # A non-verification TLS failure is usually a transport MISMATCH --
            # implicit TLS attempted against a STARTTLS port, or the reverse.
            # Also permanent: the same wrong setting will fail identically on
            # every retry.
            raise ImapConfigError(
                "TLS handshake with %s:%d failed (%s) using tls_mode=%r. This "
                "is usually the wrong transport for the port -- implicit TLS "
                "against a STARTTLS port, or the reverse. Not retried."
                % (self.host, self.port, type(exc).__name__, self.tls_mode)) from exc
        except imaplib.IMAP4.error as exc:
            # STARTTLS refused by the server, or an unusable greeting.
            raise ImapConfigError(
                "%s:%d refused STARTTLS or returned an unusable greeting (%s). "
                "Not retried: continuing would send the credential in "
                "plaintext." % (self.host, self.port, type(exc).__name__)) from exc
        except OSError as exc:
            # Genuinely transient: refused, unreachable, timed out. For a
            # loopback provider this is the ordinary "Bridge is not running"
            # case, which really can start working without a config change.
            raise ImapTransientError(
                "connect to %s:%d failed: %s%s"
                % (self.host, self.port, type(exc).__name__,
                   " -- for Proton this usually means Proton Mail Bridge is not "
                   "running" if _is_loopback(self.host) else "")) from exc

        try:
            conn.login(self.user, self._pw)
        except imaplib.IMAP4.error as exc:
            try:
                conn.logout()
            except Exception:                                   # noqa: BLE001
                pass
            # Deliberately does NOT include the password or the server's raw
            # message, which can echo credential material.
            #
            # The advice is PROVIDER-AWARE. It used to be hardcoded Gmail text
            # ("check that 2-Step Verification is enabled, and that IMAP is
            # turned on in Gmail settings"), which is not merely unhelpful to a
            # Proton user but actively wrong guidance sending them to settings
            # that do not exist for their account.
            raise ImapAuthError(
                "login failed for %s -- %s Not retried: none of those is fixed "
                "by retrying." % (_mask(self.user), _auth_help(self.provider))
            ) from exc

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
