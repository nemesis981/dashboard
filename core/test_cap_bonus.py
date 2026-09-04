"""Free-tier purchased capacity: `remote_cap_bonus` on a signed licence.

The key pack sells +5 remote-device capacity to an install that STAYS on the free
tier. Before 2026-09-04 `remote_cap_for_license()` returned the hardcoded free cap
before ever reading the payload, so a signed cap on a free licence was ignored and a
bought pack was indistinguishable from not buying one.

WHY A DELTA AND NOT AN ABSOLUTE. The issuer cannot know the client's
FREE_TIER_REMOTE_CAP -- it cannot observe which build is installed. Signing an
absolute would mean guessing that constant across a version boundary, so a later
change to the free base would silently shrink what existing holders had bought.
The issuer signs only what was PURCHASED; the client adds its own current base.

The node-lock is stubbed in these tests (`verify_install` -> MATCH_OK) because what
is under test is cap DERIVATION, not hardware binding -- which has its own coverage
in test_licensing.py. The signature is NEVER stubbed: test_bonus_requires_a_valid_signature
depends on real verification actually rejecting a foreign key.
"""
import base64
import os
import json
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_failures = []
_ran = []


def check(label, got, want):
    # Counted unconditionally: a suite whose assertion COUNT changes under failure
    # cannot be compared between runs -- a run with less coverage would report as a
    # smaller suite rather than a failing one.
    _ran.append(label)
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok   %s" % label)


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


_PRIV = Ed25519PrivateKey.generate()
_PUB_B64 = _b64u(_PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

from core import license_key as lk  # noqa: E402

# The issuer public key is compiled in and deliberately NOT environment-overridable
# (2026-08-23: a runtime override let anyone point the verifier at their own keypair).
# Tests monkeypatch the module attribute, which exists only in-process and ships in no
# build. Do NOT reload the module here -- a reload restores the hardcoded constant and
# silently undoes this assignment.
lk.PUBLIC_KEY_B64 = _PUB_B64

from core import install_id as iid  # noqa: E402
from core import entitlements as ent  # noqa: E402

_INSTALL = "INSTALL-CAPBONUS"

# Cap derivation is the subject; node-locking is not. Stubbed so a signed key binds.
iid.verify_install = lambda bound, signals, conf: (iid.MATCH_OK, "stubbed for cap tests")


def make_key(tier="free", bonus=None, remote_cap=None, priv=None, expires_at=None):
    payload = {"install_id": _INSTALL, "tier": tier,
               "issued_at": int(time.time()), "licence_id": "test-capbonus"}
    if expires_at is not None:
        payload["expires_at"] = expires_at
    if bonus is not None:
        payload["remote_cap_bonus"] = bonus
    if remote_cap is not None:
        payload["remote_cap"] = remote_cap
    body = lk.encode_payload(payload)
    sig = (priv or _PRIV).sign(body)
    return "%s.%s.%s" % (lk.KEY_PREFIX, _b64u(body), _b64u(sig))


def db_with(key):
    """A throwaway alerts.db carrying exactly one licence row."""
    path = tempfile.mktemp(suffix=".db", prefix="capbonus-")
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE license_state (
        id INTEGER PRIMARY KEY CHECK (id = 1), install_id TEXT,
        install_signals TEXT, install_conf TEXT, license_key TEXT, tier TEXT)""")
    if key is not None:
        conn.execute("INSERT INTO license_state VALUES (1,?,?,?,?,?)",
                     (_INSTALL, json.dumps({"t": 1}), "high", key, "free"))
    conn.commit()
    conn.close()
    return path


def cap_for(**kw):
    p = db_with(make_key(**kw))
    try:
        return ent.remote_cap_for_license(p)
    finally:
        os.unlink(p)


BASE = ent.FREE_TIER_REMOTE_CAP


# ── the branch this change adds ──────────────────────────────────────────────

def test_purchased_bonus_is_granted():
    print("\n[a purchased bonus raises the free cap]")
    # THE case the product depends on. If this passes and everything else in this
    # file passes, a bought pack is visible to the enforcement seams.
    check("free + bonus 5 -> base + 5", cap_for(bonus=5), BASE + 5)
    check("free + bonus 10 (two packs) -> base + 10", cap_for(bonus=10), BASE + 10)
    check("the bonus is ADDITIVE to the base, not a replacement",
          cap_for(bonus=5) - BASE, 5)


def test_no_bonus_is_unchanged():
    print("\n[absence of a bonus changes nothing]")
    check("free licence, no bonus field -> base", cap_for(), BASE)
    check("no licence installed at all -> base",
          ent.remote_cap_for_license(db_with(None)), BASE)


# ── fail-narrow: a corrupted value must never widen an entitlement ───────────

def test_unusable_bonus_falls_back_to_base():
    print("\n[an unusable bonus falls toward the NARROWER entitlement]")
    check("non-numeric -> base", cap_for(bonus="lots"), BASE)
    check("zero -> base", cap_for(bonus=0), BASE)
    check("negative must not SHRINK the cap either", cap_for(bonus=-3), BASE)
    check("null -> base", cap_for(bonus=None), BASE)
    check("float -> base", cap_for(bonus=2.5), BASE)
    check("boolean True is not a quantity", cap_for(bonus=True), BASE)
    check("absurd value is refused, not clamped", cap_for(bonus=10 ** 9), BASE)
    check("just past the ceiling is refused",
          cap_for(bonus=ent.MAX_REMOTE_CAP_BONUS + 1), BASE)
    check("[control] exactly at the ceiling is still granted",
          cap_for(bonus=ent.MAX_REMOTE_CAP_BONUS),
          BASE + ent.MAX_REMOTE_CAP_BONUS)


# ── the security property ────────────────────────────────────────────────────

def test_bonus_requires_a_valid_signature():
    print("\n[an unverified payload grants nothing]")
    # The whole entitlement rests on this. If the bonus could be read from an
    # unverified payload, anyone could mint themselves capacity by editing a key --
    # the same shape as the NEMESIS_LICENSE_PUBKEY override removed on 2026-08-23.
    forged = Ed25519PrivateKey.generate()
    check("a key signed by a DIFFERENT issuer grants no bonus",
          cap_for(bonus=50, priv=forged), BASE)

    # Control: identical payload under the REAL issuer key IS granted. Without this,
    # the assertion above would also pass if the bonus were broken for every input.
    check("[control] the same payload correctly signed IS granted",
          cap_for(bonus=50), BASE + 50)

    # A structurally intact key whose body was tampered with after signing.
    good = make_key(bonus=5)
    prefix, body_b64, sig_b64 = good.split(".")
    tampered_body = _b64u(lk.encode_payload(
        {"install_id": _INSTALL, "tier": "free", "issued_at": int(time.time()),
         "licence_id": "test-capbonus", "remote_cap_bonus": 500}))
    tampered = "%s.%s.%s" % (prefix, tampered_body, sig_b64)
    p = db_with(tampered)
    try:
        check("a payload edited after signing grants no bonus",
              ent.remote_cap_for_license(p), BASE)
    finally:
        os.unlink(p)


def test_expired_licence_grants_no_bonus():
    print("\n[an EXPIRED licence grants no bonus]")
    # This is the case that makes the explicit `if not res.valid` check load-bearing,
    # and it was missing until a mutation test exposed it: verify() returns a
    # POPULATED payload alongside Verdict.EXPIRED (core/license_key.py:207-208), so
    # unlike a bad signature -- where the payload comes back empty and the bonus
    # would be dropped incidentally -- an expired key really does carry a readable
    # remote_cap_bonus. Without the check, expired capacity would be granted forever.
    # Not hypothetical: time-limited demo keys are exactly this shape.
    past = int(time.time()) - 86400
    check("expired licence carrying a bonus grants none",
          cap_for(bonus=25, expires_at=past), BASE)
    check("[control] the same key unexpired IS granted",
          cap_for(bonus=25, expires_at=int(time.time()) + 86400), BASE + 25)


# ── the commercial path must be untouched ────────────────────────────────────

def test_commercial_path_unchanged():
    print("\n[commercial semantics are not disturbed]")
    check("commercial + remote_cap 12 -> 12 (absolute, as before)",
          cap_for(tier="commercial", remote_cap=12), 12)
    check("commercial with no cap -> unlimited",
          cap_for(tier="commercial"), ent.COMMERCIAL_REMOTE_CAP)
    # bonus is a FREE-tier concept: commercial is already unlimited or explicitly
    # capped, so a bonus there must not quietly become a third precedence rule.
    check("commercial ignores remote_cap_bonus entirely",
          cap_for(tier="commercial", remote_cap=12, bonus=50), 12)
    check("free ignores an absolute remote_cap (bonus is the free-tier field)",
          cap_for(tier="free", remote_cap=99), BASE)


# ── the budget helper must agree with the derivation ─────────────────────────

def test_budget_reports_the_raised_limit():
    print("\n[the budget helper reports the raised limit]")
    # cap_guard and the dashboard both read the limit through this, so a fix that
    # stopped here would enforce the old cap while the derivation reported the new.
    p = db_with(make_key(bonus=5))
    try:
        _used, limit, _census = ent.remote_device_budget(p)
        check("remote_device_budget() limit reflects the bonus", limit, BASE + 5)
    finally:
        os.unlink(p)


EXPECTED_CHECKS = 24

if __name__ == "__main__":
    print("=" * 60)
    print("free-tier purchased capacity (remote_cap_bonus)")
    print("=" * 60)
    test_purchased_bonus_is_granted()
    test_no_bonus_is_unchanged()
    test_unusable_bonus_falls_back_to_base()
    test_bonus_requires_a_valid_signature()
    test_expired_licence_grants_no_bonus()
    test_commercial_path_unchanged()
    test_budget_reports_the_raised_limit()

    print("\n" + "=" * 60)
    print("checks run: %d" % len(_ran))
    if len(_ran) != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d. A silently smaller suite is "
              "not a passing one -- update EXPECTED_CHECKS deliberately."
              % (len(_ran), EXPECTED_CHECKS))
        sys.exit(1)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
