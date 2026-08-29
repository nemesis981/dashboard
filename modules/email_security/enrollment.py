"""Email enrollment -- ADR 0028 D11.5 Option C (admin-initiated, owner-authorized).

THE SHAPE, AND WHY
    The admin creates a request and hands over a scoped, single-use, expiring link.
    The ACCOUNT OWNER opens it and enters their own app password. The credential is
    never seen, typed, or stored by the admin.

    Option B -- admin-adds-on-behalf-of-others -- is EXPLICITLY REJECTED, not merely
    un-chosen (decision record 2026-08-29). It would require an admin to handle
    another person's credential. Do not add it back as a convenience.

    Option A (self-service) is NOT rejected: it is this design's degenerate case,
    a user sending the link to themselves.

THE TOKEN IS HASHED AT REST, ALWAYS
    Only the hash is stored. The plaintext exists solely inside the link handed to
    the owner. A readable token column would let anyone with DB access complete
    someone else's enrollment -- precisely the power Option C withholds from the
    admin. `verify()` therefore hashes the presented token and looks THAT up; it
    never decrypts anything, because there is nothing to decrypt.

SINGLE-USE AND EXPIRY ARE ENFORCED HERE, NOT MERELY RECORDED
    `used_at` and `expires_at` are columns, but a column is a note, not a control.
    `check_request()` is the control, and it is PURE so both refusal branches can be
    tested without a database.

PURE CORE. No DB, no Flask, no clock -- callers pass `now`. That is what makes the
expiry and replay branches testable rather than merely present.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

#: 32 bytes -> 43 url-safe chars. This is the only secret in the flow and it is a
#: bearer credential for one enrollment, so it is sized like one.
TOKEN_BYTES = 32

#: Deliberately short. The link authorises connecting a mailbox; a week-long window
#: is a week-long window for a forwarded or screenshotted link to be replayed.
DEFAULT_TTL_HOURS = 24

OK = "ok"
NOT_FOUND = "not_found"
EXPIRED = "expired"
ALREADY_USED = "already_used"


def new_token() -> str:
    """A high-entropy, URL-safe enrollment token. Plaintext -- store the HASH."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_hash(token: str) -> str:
    """SHA-256 of the token. Unsalted BY DESIGN, unlike sender_id's HMAC.

    The threat models differ and the difference is the whole justification:
    sender_id hashes EMAIL ADDRESSES -- a small, guessable space where an unsalted
    digest is reversible against a contact list. A 256-bit random token has no such
    space to search, so a salt would add nothing an attacker could not already
    ignore. Constant-time comparison is what matters here, not salting.
    """
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def hashes_equal(a: str, b: str) -> bool:
    """Constant-time compare, so a token cannot be recovered by timing."""
    return hmac.compare_digest((a or ""), (b or ""))


def expiry_from(now: datetime, hours: int = DEFAULT_TTL_HOURS) -> datetime:
    return now + timedelta(hours=hours)


def _parse(ts):
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def check_request(row, now: datetime) -> str:
    """OK / NOT_FOUND / EXPIRED / ALREADY_USED for a request row.

    Ordering is deliberate: ALREADY_USED is checked BEFORE expiry so a replayed
    token reports replay rather than the blander 'expired' once its window passes.
    Both refuse; they are different facts and the log should say which.

    A row whose `expires_at` cannot be parsed is treated as EXPIRED, never as
    valid -- an unreadable expiry is not permission.
    """
    if not row:
        return NOT_FOUND
    if row.get("used_at"):
        return ALREADY_USED
    exp = _parse(row.get("expires_at"))
    if exp is None or now >= exp:
        return EXPIRED
    return OK


#: The owner-facing path. NO TOKEN IN IT -- see build_link.
ENROLL_PATH = "/email/enroll"


def build_link(base_url: str) -> str:
    """The owner-facing link. **The token is deliberately NOT in this URL.**

    ⚠ WHY, AND IT IS MEASURED, NOT THEORETICAL. werkzeug's access logging is
    active (dashboard.py's root handler is installed before Flask serves, so
    werkzeug does not attach its own). Confirmed live 2026-08-29: the dashboard
    journal holds request lines with full paths, readable WITHOUT sudo. A token in
    the path would therefore be written verbatim into the system journal -- the
    exact defect the 2026-08-27 route audit found on `/fw/revert`, where the
    logged value was "verified byte-identical to the minted token". It would also
    reach browser history and any future proxy.

    The token travels in the POST body instead, which the same journal does NOT
    record (measured on /fw/revert: POST lines appear without bodies).

    Log suppression for this path was REJECTED, for the reason fw_revert already
    recorded: it is a control that can silently regress with nobody noticing.

    `base_url` comes from config, never from a request header -- a
    Host-header-derived link is an open redirect waiting to happen.
    """
    return "%s%s" % ((base_url or "").rstrip("/"), ENROLL_PATH)


def delivery_message(link: str, token: str, address_hint=None) -> str:
    """A ready-to-send message pairing the link AND the code IN ONE PLACE.

    ⚠ THIS EXISTS FOR A UX REASON THAT IS ALSO A SECURITY ONE. Taking the token
    out of the URL means the owner needs two pieces of data, and two pieces of
    data is how a non-technical user gets stuck -- or worse, gives up and asks the
    admin to "just do it for them", which is Option B, the thing this whole design
    exists to prevent. So the admin is handed ONE block of text containing both,
    rather than being left to compose it and possibly send them separately.
    """
    who = (" for %s" % address_hint) if address_hint else ""
    return (
        "Nemesis can scan your email%s for threats.\n\n"
        "1. Open this page:  %s\n"
        "2. Paste this code: %s\n\n"
        "The page will then walk you through creating an app password with your "
        "email provider. You enter it yourself -- nobody else sees it, and it is "
        "not shown to whoever sent you this.\n\n"
        "This code can only be used once and expires in 24 hours."
        % (who, link, token))

# ── Rate limiting for the unauthenticated route (CLAUDE.md _AUTH_EXEMPT rule 3) ──

#: Attempts per window, per client address.
RATE_MAX = 10
RATE_WINDOW_S = 300
#: HARD CAP on distinct keys held. The key is a client-controlled value reachable
#: WITHOUT credentials, so an unbounded store is a memory-exhaustion vector for an
#: anonymous attacker. When full, the OLDEST entry is evicted -- never "stop
#: recording", which would silently disable the limiter under the exact load it
#: exists to survive.
RATE_MAX_KEYS = 4096


class RateLimiter:
    """Bounded, evicting, per-key fixed-window limiter. Pure: caller passes `now`.

    Deliberately NOT a decorator and NOT global state: it is constructed by the
    caller so tests can drive it directly rather than through a live Flask app.
    """

    def __init__(self, max_attempts=RATE_MAX, window_s=RATE_WINDOW_S,
                 max_keys=RATE_MAX_KEYS):
        self.max_attempts, self.window_s, self.max_keys = max_attempts, window_s, max_keys
        self._hits = {}                       # key -> [window_start_epoch, count]

    def check_and_count(self, key, now_epoch):
        """True if this attempt is ALLOWED. Counts the attempt either way.

        Counting a rejected attempt is deliberate: not counting them lets an
        attacker keep a key permanently just under the limit.
        """
        key = key or "unknown"
        win, cnt = self._hits.get(key, (None, 0))
        if win is None or now_epoch - win >= self.window_s:
            win, cnt = now_epoch, 0
        cnt += 1
        if len(self._hits) >= self.max_keys and key not in self._hits:
            # Evict the oldest window. Bounded memory is the property; perfect
            # LRU is not required and would cost more than it buys here.
            oldest = min(self._hits, key=lambda k: self._hits[k][0])
            del self._hits[oldest]
        self._hits[key] = (win, cnt)
        return cnt <= self.max_attempts

    def __len__(self):
        return len(self._hits)
