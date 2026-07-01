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


class TailscaleAPIError(Exception):
    """Any failure exchanging creds or minting a key — caught by the caller's hybrid fallback."""


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
        raise TailscaleAPIError("token endpoint unreachable: " + str(e)[:80])
    if r.status_code != 200:
        raise TailscaleAPIError("token exchange HTTP %d" % r.status_code)
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
    """Mint a SINGLE-USE, non-reusable, non-ephemeral, PRE-AUTHORIZED, tagged auth key.
    Returns (key_string, key_id). Raises TailscaleAPIError on any failure so the caller can
    fall back. Rule 8: returns the secret to the caller but never logs it."""
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
        raise TailscaleAPIError("keys endpoint unreachable: " + str(e)[:80])
    if r.status_code not in (200, 201):
        raise TailscaleAPIError("key mint HTTP %d" % r.status_code)
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
