#!/usr/bin/env python3
"""Session realms — a session issued at one door is invalid at the other.

WHY THIS EXISTS (operator decision, 2026-08-24)
-----------------------------------------------
Stage 0 gives the appliance two front doors: plain HTTP on the LAN (port 80,
kept working indefinitely) and TLS over the tailnet. Without realms, a session
cookie sniffed on the LAN — where it travels in clear — can simply be replayed
against the "secure" tailnet door.

That would defeat the entire admin-approval and WebAuthn design by the *easiest*
available attack rather than anything it was built to resist. "The LAN is
trusted" is not available as an answer here: this product's premise is that the
network itself may not be.

So a session carries the door it was born at, and is refused anywhere else.

⚠ THE SUBTLETY THAT RULES OUT THE OBVIOUS FIX
---------------------------------------------
Setting `Secure` only on HTTPS responses does NOT solve this. The same session
remains usable at both doors, so anything captured over HTTP still replays over
HTTPS. Conditional cookie flags protect only sessions that never touch port 80.
Realms are what actually separate them; the `Secure` flag is hygiene on top.

⚠ WHY THE SCHEME ALONE CANNOT BE TRUSTED
----------------------------------------
The dashboard binds `127.0.0.1:5000` and nginx proxies to it. `request.scheme` is
therefore always `http` from the app's point of view, and the naive fix —
trusting `X-Forwarded-Proto` — is worse than useless here: **any local process can
connect to :5000 and set that header itself**, claiming the TLS realm from a plain
HTTP connection. The loopback listener on this box is explicitly documented as
reachable by any local process, so that is not a hypothetical.

So the door is established by a SHARED SECRET that nginx injects and a local
process cannot read (`/etc/nemesis.env`, mode 640 root:nemesis). A request with no
valid door header is not "assumed LAN" — it gets its own `direct` realm, which
matches neither door, so it can never inherit a session from either.
"""

import hmac
import os

__all__ = ["REALM_LAN", "REALM_TLS", "REALM_DIRECT", "REALMS", "DOOR_HEADER",
           "RealmError", "door_secret", "realm_from_header", "stamp_realm",
           "session_realm", "realm_matches", "is_secure_realm"]

#: Issued at the plain-HTTP LAN door.
REALM_LAN = "lan"
#: Issued at the TLS tailnet door.
REALM_TLS = "tls"
#: Reached the app WITHOUT passing a door — i.e. straight to the loopback port.
#: A real, distinct realm rather than a fallback to `lan`: falling back would let
#: any local process mint a session indistinguishable from a real LAN one.
REALM_DIRECT = "direct"

REALMS = (REALM_LAN, REALM_TLS, REALM_DIRECT)

#: The header nginx sets. Value is "<realm>:<secret>".
DOOR_HEADER = "X-Nemesis-Door"

#: Session key holding the realm. Leading underscore to sit with Flask's own
#: internal keys and to make it obvious this is not user data.
SESSION_KEY = "_realm"


class RealmError(RuntimeError):
    """Realm handling could not be performed safely. Raised, never defaulted."""


def door_secret(env=None):
    """The shared secret nginx injects. None if unset.

    None means "no door secret configured", and callers must treat every request
    as `direct` in that case — NOT as trusted. An install that has not yet
    generated a secret must fail closed into the realm that inherits nothing,
    rather than silently trusting a header anyone can send.
    """
    env = env if env is not None else os.environ
    value = (env.get("NEMESIS_DOOR_SECRET") or "").strip()
    return value or None


def realm_from_header(header_value, secret):
    """Derive the realm from the door header. Never raises; never guesses.

    Returns `REALM_DIRECT` for anything it cannot positively verify: absent
    header, no configured secret, malformed value, unknown realm name, or a
    secret that does not match. Every one of those is "this did not come through
    a door I can prove", and they are deliberately collapsed into the SAME
    answer — distinguishing them in the return value would tempt a caller to
    treat some of them as good enough.
    """
    if not secret or not header_value or not isinstance(header_value, str):
        return REALM_DIRECT
    name, _, presented = header_value.partition(":")
    if name not in (REALM_LAN, REALM_TLS):
        return REALM_DIRECT
    # Constant-time. A timing-distinguishable comparison on a value an attacker
    # can submit repeatedly is exactly the shape that leaks a secret byte by byte.
    if not hmac.compare_digest(presented, secret):
        return REALM_DIRECT
    return name


def stamp_realm(session, realm):
    """Record the door a session was created at. Called once, at login."""
    if realm not in REALMS:
        raise RealmError("refusing to stamp unknown realm %r" % (realm,))
    session[SESSION_KEY] = realm
    return realm


def session_realm(session):
    """The realm a session was stamped with, or None if it carries none.

    None is a real state: a session created before realms existed. The CALLER
    decides what to do with it — see `realm_matches`, which treats it as a
    mismatch rather than as a wildcard.
    """
    value = session.get(SESSION_KEY) if session else None
    return value if value in REALMS else None


def realm_matches(session, request_realm):
    """May this session be used at this door?

    An UNSTAMPED session does NOT match. That is the fail-closed direction and it
    matters at rollout: every session in existence when this ships is unstamped,
    and treating unstamped as "valid anywhere" would leave exactly the
    cross-door replay this exists to stop, for as long as those sessions live.
    The cost is that everyone logs in once after deploy, which is the correct
    trade and should be expected rather than debugged.
    """
    stamped = session_realm(session)
    if stamped is None:
        return False
    return stamped == request_realm


def is_secure_realm(realm):
    """Should the session cookie carry `Secure` for this realm?

    True only for the TLS door. Setting it for the LAN door would stop the
    browser sending the cookie over port 80 at all, which breaks the LAN access
    the operator requires — the conflict that made realms necessary in the first
    place.
    """
    return realm == REALM_TLS
