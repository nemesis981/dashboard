#!/usr/bin/env python3
"""Session realms — the cross-door replay this exists to stop.

THE ATTACK BEING TESTED. A session cookie travels in clear on the LAN door
(plain HTTP, kept open indefinitely by operator requirement). Without realms it
replays against the TLS tailnet door, defeating the admin-approval/WebAuthn work
via LAN sniffing rather than via anything that design resists.

THE SECOND ATTACK, which is easy to miss. The dashboard binds loopback and nginx
proxies to it, so `request.scheme` is always http and the naive fix is to trust
`X-Forwarded-Proto`. Any local process can connect to :5000 and set that header
itself. Every "forged door" case below is that attack.

Run: python3 alert_manager/test_session_realm.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.environ.get("NEMESIS_ROOT", "/opt/nemesis"),
                                "alert_manager"))

import session_realm as R                                          # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


SECRET = "s3cr3t-door-value-not-guessable"


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE CROSS-DOOR REPLAY IS REFUSED (the whole point) ==")

lan_session = {}
R.stamp_realm(lan_session, R.REALM_LAN)
tls_session = {}
R.stamp_realm(tls_session, R.REALM_TLS)

check("a LAN session works at the LAN door",
      R.realm_matches(lan_session, R.REALM_LAN))
check("a TLS session works at the TLS door",
      R.realm_matches(tls_session, R.REALM_TLS))
check("*** a LAN-issued session is REFUSED at the TLS door ***",
      not R.realm_matches(lan_session, R.REALM_TLS),
      "this is the LAN-sniff-then-replay attack")
check("*** a TLS-issued session is REFUSED at the LAN door ***",
      not R.realm_matches(tls_session, R.REALM_LAN))
check("neither is usable at the direct (no-door) realm",
      not R.realm_matches(lan_session, R.REALM_DIRECT)
      and not R.realm_matches(tls_session, R.REALM_DIRECT))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== A FORGED DOOR HEADER CANNOT CLAIM A REALM ==")
#
# Each of these is a local process talking straight to :5000 and asserting a door.

for value, why in (
        ("tls:wrong-secret", "right realm, WRONG secret"),
        ("tls:", "realm with an empty secret"),
        ("tls", "realm with no secret at all"),
        ("lan:wrong-secret", "LAN door, wrong secret"),
        ("admin:" + SECRET, "an invented realm name with the REAL secret"),
        ("" , "empty header"),
        (None, "absent header"),
        (12345, "a non-string"),
        (":" + SECRET, "empty realm, real secret"),
        ("tls:" + SECRET + "x", "secret with a trailing byte"),
        ("tls:" + SECRET[:-1], "secret one byte short"),
):
    check("forged %-34r -> direct" % (value,),
          R.realm_from_header(value, SECRET) == R.REALM_DIRECT, why)

check("CONTROL: the correct header DOES yield the tls realm",
      R.realm_from_header("tls:" + SECRET, SECRET) == R.REALM_TLS)
check("CONTROL: the correct LAN header yields the lan realm",
      R.realm_from_header("lan:" + SECRET, SECRET) == R.REALM_LAN)

# No configured secret must not mean "trust the header".
check("with NO secret configured, even a well-formed header is direct",
      R.realm_from_header("tls:anything", None) == R.REALM_DIRECT,
      "an install without a secret must fail closed, not trust anyone")
check("  ...and door_secret() reports None rather than empty string",
      R.door_secret({"NEMESIS_DOOR_SECRET": "   "}) is None)
check("  ...and reads the value when set",
      R.door_secret({"NEMESIS_DOOR_SECRET": "abc"}) == "abc")


# ═══════════════════════════════════════════════════════════════════════════
print("\n== UNSTAMPED SESSIONS FAIL CLOSED (the rollout case) ==")

check("a session with no realm matches NOTHING",
      not R.realm_matches({}, R.REALM_LAN)
      and not R.realm_matches({}, R.REALM_TLS)
      and not R.realm_matches({}, R.REALM_DIRECT),
      "every pre-existing session is unstamped at deploy; treating unstamped as "
      "valid-anywhere would leave the replay open for their whole lifetime")
check("session_realm() reports None for an unstamped session",
      R.session_realm({}) is None)
check("a session with a GARBAGE realm value also matches nothing",
      not R.realm_matches({R.SESSION_KEY: "superuser"}, R.REALM_TLS))
check("  ...and reports None rather than echoing the garbage back",
      R.session_realm({R.SESSION_KEY: "superuser"}) is None)
check("None session is handled without crashing", R.session_realm(None) is None)

try:
    R.stamp_realm({}, "wildcard")
    check("stamping an unknown realm RAISES", False, "it was accepted")
except R.RealmError:
    check("stamping an unknown realm RAISES", True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE Secure FLAG FOLLOWS THE REALM, NOT THE APP CONFIG ==")

check("the TLS realm gets Secure", R.is_secure_realm(R.REALM_TLS))
check("the LAN realm does NOT (or port 80 login breaks)",
      not R.is_secure_realm(R.REALM_LAN),
      "a global SESSION_COOKIE_SECURE is what forced this to be per-realm")
check("the direct realm does not", not R.is_secure_realm(R.REALM_DIRECT))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== ROUND TRIP: stamp at one door, present at the other ==")

# The full attack, end to end, with the realm derived from headers rather than
# handed in — so the test exercises the same path a request would.
sess = {}
R.stamp_realm(sess, R.realm_from_header("lan:" + SECRET, SECRET))
check("session created at the LAN door is stamped lan",
      R.session_realm(sess) == R.REALM_LAN)
stolen = dict(sess)          # exactly what a sniffer captures
check("*** the stolen cookie is REFUSED at the TLS door ***",
      not R.realm_matches(stolen, R.realm_from_header("tls:" + SECRET, SECRET)))
check("  ...and still works at the door it came from (not simply broken)",
      R.realm_matches(stolen, R.realm_from_header("lan:" + SECRET, SECRET)))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
