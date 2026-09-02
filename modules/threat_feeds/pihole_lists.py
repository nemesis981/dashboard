"""Pi-hole v6 adlist client — /api/lists ONLY.

⛔ THE SCOPE RESTRICTION IS THE POINT OF THIS FILE, NOT A STYLE CHOICE.

`core/vpn_dns_guard.py` also talks to this same Pi-hole. Its own client carries
the note "PATCH ONLY dns.upstreams. Listening posture is never touched here",
and it is load-bearing: that guard reconciles Pi-hole's upstream DNS servers on
every VPN transition, and a second writer touching `/api/config` could undo a
reconcile mid-flight, or be undone by one.

This module never writes `/api/config` at all. Adlists live on a DIFFERENT
endpoint, so the two writers cannot address the same object. That makes
non-collision STRUCTURAL rather than a matter of both sides remembering — the
same reason ADR-style chokepoints are preferred to conventions everywhere else
in this codebase.

⚠ If a future change here needs `/api/config` for any reason, that is not a
small edit. It reopens a collision this design closed by construction, and it
must be taken up with whoever owns `vpn_dns_guard` first.
"""
import logging

import requests

log = logging.getLogger("nemesis.threat_feeds.pihole")

#: Every path this module is permitted to touch. Asserted by the test suite
#: against the actual request calls, so adding a path here is a visible,
#: reviewed act rather than an incidental one.
ALLOWED_PATHS = ("/api/auth", "/api/lists")

_TIMEOUT = 8


class PiholeListsError(RuntimeError):
    """Any failure talking to Pi-hole. Raised, never swallowed into a default."""


class PiholeLists:
    """Minimal Pi-hole v6 client scoped to adlist management."""

    def __init__(self, ip, password):
        self._ip = ip
        self._pw = password
        self._sid = None

    # -- auth ---------------------------------------------------------------

    def _auth(self):
        """Session id, reusing a valid one. Mirrors vpn_dns_guard's shape."""
        if self._sid:
            try:
                r = requests.get("http://%s/api/auth" % self._ip,
                                 headers={"sid": self._sid}, timeout=4)
                if r.json().get("session", {}).get("valid"):
                    return self._sid
            except Exception:  # noqa: BLE001 — a stale sid is not an error
                pass
        try:
            r = requests.post("http://%s/api/auth" % self._ip,
                              json={"password": self._pw}, timeout=4)
            self._sid = r.json().get("session", {}).get("sid")
        except Exception as e:  # noqa: BLE001
            raise PiholeListsError("Pi-hole auth request failed: %s" % e) from e
        if not self._sid:
            raise PiholeListsError(
                "Pi-hole auth returned no session id (wrong PIHOLE_PASSWORD?)")
        return self._sid

    def _headers(self):
        return {"sid": self._auth()}

    # -- reads --------------------------------------------------------------

    def get_lists(self):
        """Every adlist Pi-hole knows about, ours and the operator's alike."""
        try:
            r = requests.get("http://%s/api/lists" % self._ip,
                             headers=self._headers(), timeout=_TIMEOUT)
            r.raise_for_status()
            return list(r.json().get("lists", []))
        except PiholeListsError:
            raise
        except Exception as e:  # noqa: BLE001
            raise PiholeListsError("could not read Pi-hole lists: %s" % e) from e

    # -- writes -------------------------------------------------------------

    def add_list(self, address, comment, enabled=True):
        """Add ONE adlist, carrying its ownership comment.

        The comment is written in the SAME request that creates the list, never
        as a follow-up PATCH. A list that existed for even a moment without its
        tag would be indistinguishable from an operator's own list, and the
        removal path would then be unable to claim it — so an interrupted add
        must leave either a correctly-tagged list or no list, never an untagged
        one.
        """
        payload = {"address": address, "type": "block",
                   "comment": comment, "enabled": bool(enabled)}
        try:
            r = requests.post("http://%s/api/lists" % self._ip,
                              headers=self._headers(), json=payload, timeout=_TIMEOUT)
            if r.status_code not in (200, 201):
                raise PiholeListsError(
                    "Pi-hole refused the list add (HTTP %s): %s"
                    % (r.status_code, (r.text or "")[:200]))
        except PiholeListsError:
            raise
        except Exception as e:  # noqa: BLE001
            raise PiholeListsError("could not add Pi-hole list: %s" % e) from e
        log.info("added adlist %s (comment=%s)", address, comment)

    def remove_list(self, address):
        """Remove ONE adlist by address.

        Callers must have established ownership BEFORE calling this — the client
        deliberately does not check, because a client that decides what it may
        delete based on its own read is one refactor away from deciding wrongly.
        Ownership is the module's decision and is tested there.
        """
        try:
            r = requests.delete(
                "http://%s/api/lists/%s" % (self._ip, requests.utils.quote(address, safe="")),
                headers=self._headers(), params={"type": "block"}, timeout=_TIMEOUT)
            if r.status_code not in (200, 204):
                raise PiholeListsError(
                    "Pi-hole refused the list delete (HTTP %s): %s"
                    % (r.status_code, (r.text or "")[:200]))
        except PiholeListsError:
            raise
        except Exception as e:  # noqa: BLE001
            raise PiholeListsError("could not remove Pi-hole list: %s" % e) from e
        log.info("removed adlist %s", address)
