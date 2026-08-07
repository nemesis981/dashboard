"""Programmatic Tailscale auth-key minting via the OAuth API (ADR 0011 — installer
self-onboard). Replaces the manually-pasted pre-auth key at the single generate seam in
dashboard.py; everything downstream (the enrollment_tokens.preauth_key column, /zip conf
baking, the installer's consume-and-delete) is reused unchanged.

Flow: client_credentials -> short-lived access token (cached for its lifetime) -> mint a
SINGLE-USE (non-reusable, non-ephemeral), PRE-AUTHORIZED, TAGGED auth key. Schema verified
against the Tailscale API reference + the official tailscale-client-go-v2 structs
(capabilities.devices.create{reusable,ephemeral,preauthorized,tags}; secret in resp "key").

Rule 8: NEVER log the client_secret or a minted key. Logs carry only success/failure + the
key-id prefix. Creds live in /etc/nemesis.env (640 root:nemesis), never in the repo. Vendor
integration — see CUSTOM_TAILSCALE_OAUTH.md.
"""
import os
import re
import time
import logging

import requests

log = logging.getLogger("tailscale_api")

_TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"
_KEYS_URL  = "https://api.tailscale.com/api/v2/tailnet/{tailnet}/keys"
_TIMEOUT   = 15

# Access-token cache: the token is valid ~1h; reuse within its life (minus a safety margin)
# to avoid an extra round-trip per installer generate.
_token_cache = {"access_token": "", "expires_at": 0.0}


#: Retry policy for the mint path. 3 total attempts (initial + 2 retries), 1.5s apart.
#:
#: THE CONSTANT IS DELIBERATELY NOT the 30s used by the DHCP mode-failover rollback
#: (`dhcp-mode-failover-scope-2026-08-07.md`). That runs in a background daemon where a
#: minute of patience is free. THIS runs inside a synchronous HTTP download request: a
#: user is watching a browser wait for a zip. 2 retries at 30s would mean up to a minute
#: of dead air, indistinguishable from a hung page and long enough to trip proxy and
#: gateway timeouts. Same SHAPE (fixed small number of attempts, fixed delay, then a
#: clear failure), different constant — worst case here is ~3s of added latency.
_RETRY_ATTEMPTS = 3
_RETRY_DELAY    = 1.5


def _retryable_status(code):
    """429 and 5xx are transient; 4xx are not.

    Retrying a 4xx is worse than useless — a bad OAuth credential or a malformed tag
    fails identically every time, so it just triples the user's wait before showing the
    same error. Classification lives here, as a function of the STATUS CODE, rather than
    by matching on exception message text: message-matching would silently stop working
    the first time any of these strings is reworded.
    """
    return code == 429 or (code is not None and code >= 500)


class TailscaleAPIError(Exception):
    """Any failure exchanging creds or minting a key — caught by the caller's hybrid fallback.

    Carries `status` (HTTP code, or None for a transport-level failure) and `retryable`
    so the retry loop can decide from structured data instead of parsing the message.
    """

    def __init__(self, msg, status=None, retryable=False):
        super().__init__(msg)
        self.status = status
        self.retryable = retryable


def _client_creds():
    return (os.environ.get("TAILSCALE_OAUTH_CLIENT_ID", "").strip(),
            os.environ.get("TAILSCALE_OAUTH_CLIENT_SECRET", "").strip())


def is_configured():
    """True iff both OAuth creds are present — lets the caller skip the API path cleanly."""
    cid, sec = _client_creds()
    return bool(cid and sec)


def _get_access_token():
    """Exchange client creds for a short-lived access token (client_credentials grant).
    Cached for its lifetime. Rule 8: never logs the secret or the token."""
    now = time.time()
    if _token_cache["access_token"] and now < _token_cache["expires_at"]:
        return _token_cache["access_token"]
    cid, sec = _client_creds()
    if not (cid and sec):
        raise TailscaleAPIError("OAuth client creds not configured")
    try:
        r = requests.post(_TOKEN_URL, data={
            "client_id": cid, "client_secret": sec,
            "grant_type": "client_credentials"}, timeout=_TIMEOUT)
    except requests.RequestException as e:
        # Transport-level: no status. Always transient-until-proven-otherwise.
        raise TailscaleAPIError("token endpoint unreachable: " + str(e)[:80],
                                status=None, retryable=True)
    if r.status_code != 200:
        raise TailscaleAPIError("token exchange HTTP %d" % r.status_code,
                                status=r.status_code,
                                retryable=_retryable_status(r.status_code))
    try:
        j = r.json() or {}
    except ValueError:
        raise TailscaleAPIError("token response not JSON")
    tok = j.get("access_token", "")
    if not tok:
        raise TailscaleAPIError("no access_token in token response")
    ttl = int(j.get("expires_in", 3600) or 3600)
    _token_cache["access_token"] = tok
    _token_cache["expires_at"] = now + max(60, ttl - 120)   # 2-min safety margin
    return tok


def _safe_key_description(device_hint):
    """Tailscale rejects auth-key descriptions containing characters outside its allowed
    set (letters, digits, spaces, hyphens, underscores) — notably DOTS, which return
    HTTP 400 'keys: description had invalid characters'. Strip to that charset. (The
    installer conf renderer keeps its own separate, looser rule; only THIS Tailscale
    description needs the stricter charset.)"""
    raw = "nemesis installer " + (device_hint or "device")
    safe = re.sub(r"[^A-Za-z0-9 _-]", "", raw).strip()
    return (safe or "nemesis installer")[:100]


def mint_preauth_key(device_hint="", ttl_seconds=3600):
    """Mint a SINGLE-USE key, retrying transient failures. Returns (key_string, key_id).

    3 attempts, 1.5s apart, retrying ONLY transport errors / 429 / 5xx (see
    `_retryable_status`). A non-retryable failure raises immediately rather than making
    the caller wait out delays for an error that cannot change. Rule 8: never logs it.
    """
    last = None
    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            return _mint_preauth_key_once(device_hint, ttl_seconds)
        except TailscaleAPIError as e:
            last = e
            if not e.retryable or attempt == _RETRY_ATTEMPTS:
                raise
            log.warning("tailscale: mint attempt %d/%d failed (%s) — retrying in %.1fs",
                        attempt, _RETRY_ATTEMPTS, e, _RETRY_DELAY)
            time.sleep(_RETRY_DELAY)
    raise last   # unreachable; kept so a future edit cannot fall through returning None


#: How long a superseded key is left alive before it is retired. See
#: `should_retire_superseded_key` for why this is not zero.
_SUPERSEDE_GRACE_SECONDS = 600      # 10 minutes


def should_retire_superseded_key(minted_at, now=None, grace=None):
    """Is a superseded key old enough that revoking it cannot break a live install?

    WHY THIS EXISTS — the failure it prevents (found in the route audit, 2026-08-07).
    `/install/windows/<token>/zip` is deliberately re-downloadable (`uses` is incremented
    at ENROLMENT, not at download), and things other than the user fetch shared URLs:
    chat link-preview bots, antivirus URL scanners, browser prefetch. With an immediate
    revoke, this sequence breaks a legitimate install:

        user downloads (key B) -> starts the installer -> anything re-fetches the URL
        -> mints C and revokes B -> the installer is now holding a revoked key.

    The old stored-key design returned the SAME key on re-fetch, so it could not happen;
    it is a consequence of minting per download, not a pre-existing bug. Leaving a short
    grace window means an in-progress install keeps working, at the cost of at most one
    extra key living out its (1h) TTL.

    FAIL-SAFE DIRECTION: unknown age (`minted_at` is None — a row written before this
    column existed) returns **False**, i.e. do NOT revoke. Throughout this design an
    orphaned key that expires on its own is the acceptable failure and a dead installer
    is not, so anything unprovable resolves toward leaving the key alone.
    """
    if minted_at is None:
        return False
    try:
        age = (time.time() if now is None else now) - float(minted_at)
    except (TypeError, ValueError):
        return False                      # unparseable timestamp — same fail-safe
    return age > (_SUPERSEDE_GRACE_SECONDS if grace is None else grace)


def revoke_key(key_id):
    """Best-effort revoke of a previously-minted key. Returns True if it is gone.

    DELIBERATELY NEVER RAISES. This is called AFTER a replacement key has already been
    minted successfully (mint-then-revoke, operator decision 2026-08-07): a failure here
    must leave an ORPHANED key that expires on its own, never a dead installer. Raising
    would invert that and break the download for the user.

    A 404 counts as success — the key is already gone, which is the desired end state.
    """
    if not key_id:
        return False
    tailnet = os.environ.get("TAILSCALE_TAILNET", "-").strip() or "-"
    try:
        token = _get_access_token()
        r = requests.delete(
            _KEYS_URL.format(tailnet=tailnet) + "/" + str(key_id),
            headers={"Authorization": "Bearer " + token}, timeout=_TIMEOUT)
    except Exception as e:  # noqa: BLE001 — see docstring: never raises
        log.warning("tailscale: revoke of key id=%s failed (%s); it will expire on its "
                    "own TTL", str(key_id)[:12], str(e)[:80])
        return False
    if r.status_code in (200, 204, 404):
        log.info("tailscale: revoked superseded key id=%s (HTTP %d)",
                 str(key_id)[:12], r.status_code)
        return True
    log.warning("tailscale: revoke of key id=%s returned HTTP %d; it will expire on its "
                "own TTL", str(key_id)[:12], r.status_code)
    return False


def _mint_preauth_key_once(device_hint="", ttl_seconds=3600):
    """One mint attempt. SINGLE-USE, non-reusable, non-ephemeral, PRE-AUTHORIZED, tagged.
    Returns (key_string, key_id). Raises TailscaleAPIError, tagged with retryability."""
    tailnet = os.environ.get("TAILSCALE_TAILNET", "-").strip() or "-"
    tag = os.environ.get("TAILSCALE_TAG", "tag:nemesis-agent").strip() or "tag:nemesis-agent"
    token = _get_access_token()
    body = {
        "capabilities": {"devices": {"create": {
            "reusable": False,
            "ephemeral": False,
            "preauthorized": True,
            "tags": [tag],
        }}},
        "expirySeconds": int(ttl_seconds),
        "description": _safe_key_description(device_hint),
    }
    try:
        r = requests.post(_KEYS_URL.format(tailnet=tailnet),
                          headers={"Authorization": "Bearer " + token},
                          json=body, timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise TailscaleAPIError("keys endpoint unreachable: " + str(e)[:80],
                                status=None, retryable=True)
    if r.status_code not in (200, 201):
        raise TailscaleAPIError("key mint HTTP %d" % r.status_code,
                                status=r.status_code,
                                retryable=_retryable_status(r.status_code))
    try:
        data = r.json() or {}
    except ValueError:
        raise TailscaleAPIError("mint response not JSON")
    key = data.get("key", "")
    key_id = data.get("id", "")
    if not key:
        raise TailscaleAPIError("no key in mint response")
    # Rule 8: log the key-id prefix only — never the key secret.
    log.info("tailscale: minted single-use pre-auth key id=%s tag=%s",
             (key_id or "?")[:12], tag)
    return key, key_id
