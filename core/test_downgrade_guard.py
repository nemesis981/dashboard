"""Installing an OLDER licence key must not silently shrink what you bought.

THE HAZARD (F13 in the key-pack design). Every pack purchase reissues a key that
supersedes the last, and each arrives by email. The client stores exactly one licence
(`license_state` id=1), and every one of those keys is genuinely signed and genuinely
bound to this machine. So re-activating an older one -- restoring a machine, or just
clicking the first email in the thread -- silently drops capacity the customer paid
for. Nothing errors. The dashboard simply shows a smaller number, which is
indistinguishable from the pack never having worked.

WHAT THIS ADDS. `issued_at` is already in every payload, so ordering needs no new
field and no server contact: refuse a key older than the one installed, and say by how
much, with an explicit override for the legitimate restore case.

⚠ THE GUARD IS NOT AN ACCESS CONTROL, AND MUST NOT BE READ AS ONE. Both keys are
validly signed and bound to this machine; possessing one is already full authorisation
to install it. This protects against an ACCIDENT, not an attacker. That is why an
unreadable stored key falls through to allowing the install (section C) -- refusing
would lock a user out of their own product to prevent a downgrade that, in that state,
cannot occur anyway: an unverifiable stored key contributes 0 capacity, so there is
nothing left to lose.

WHY THE OVERRIDE IS HARDER TO REACH THAN THE ACTIVATION IT OVERRIDES. `/api/license/
activate` accepts form-encoded POST, and a cross-origin form can be submitted. Today
that is nearly harmless -- forging it requires a key already bound to the victim's
machine. But an override flag readable from a form would let the same forged request
re-open exactly the downgrade this guard closes, turning the fix into the vector. So
the override is honoured only on a JSON content-type, matching the reasoning already
applied to `api_ram_recovery_clean`: a form cannot set it, and a cross-origin fetch
that does is stopped by CORS preflight.
"""
import base64
import json
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_failures = []
_ran = []


def check(label, got, want):
    _ran.append(label)
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok   %s" % label)


def check_true(label, ok, detail=""):
    _ran.append(label)
    if ok:
        print("  ok   %s" % label)
    else:
        _failures.append("%s %s" % (label, detail))
        print("  FAIL %s %s" % (label, detail))


def die(msg):
    print("\n!! DEAD INSTRUMENT: %s" % msg)
    raise SystemExit(1)


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


_PRIV = Ed25519PrivateKey.generate()
_PUB_B64 = _b64u(_PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

from core import license_key as lk  # noqa: E402

# Patch the module attribute, never the env var: the env override was removed on
# 2026-08-23 as a proven forgery vector. Do NOT reload the module -- a reload restores
# the compiled-in key and silently undoes this line.
lk.PUBLIC_KEY_B64 = _PUB_B64

from core import install_id as iid  # noqa: E402
from core import entitlements as ent  # noqa: E402

_INSTALL = "INSTALL-DOWNGRADE"
iid.verify_install = lambda bound, signals, conf: (iid.MATCH_OK, "stubbed")
iid.compute = lambda: {"stable_id": _INSTALL, "signal_hashes": {"t": 1},
                       "confidence": "high"}

BASE = ent.FREE_TIER_REMOTE_CAP
T0 = 1757000000          # a fixed epoch, so "older" and "newer" are unambiguous


def make_key(tier="free", bonus=None, remote_cap=None, issued_at=T0, priv=None):
    payload = {"install_id": _INSTALL, "tier": tier, "issued_at": issued_at,
               "licence_id": "test-downgrade"}
    if bonus is not None:
        payload["remote_cap_bonus"] = bonus
    if remote_cap is not None:
        payload["remote_cap"] = remote_cap
    body = lk.encode_payload(payload)
    return "%s.%s.%s" % (lk.KEY_PREFIX, _b64u(body),
                         _b64u((priv or _PRIV).sign(body)))


def payload_of(key):
    res = lk.verify(key, install_id=None)
    if not res.valid:
        die("a key built by this suite does not verify (%s) -- every assertion "
            "below would be measuring a broken fixture" % res.verdict)
    return res.payload


def db_with(key):
    path = tempfile.mktemp(suffix=".db", prefix="downgrade-")
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE license_state (
        id INTEGER PRIMARY KEY CHECK (id = 1), install_id TEXT,
        install_signals TEXT, install_conf TEXT, license_key TEXT, tier TEXT,
        bound_at TEXT, created_at TEXT, updated_at TEXT, updated_actor TEXT)""")
    if key is not None:
        conn.execute("INSERT INTO license_state (id, install_id, install_signals, "
                     "install_conf, license_key, tier) VALUES (1,?,?,?,?,?)",
                     (_INSTALL, json.dumps({"t": 1}), "high", key, "free"))
    conn.commit()
    conn.close()
    return path


# ── A. bonus_from_payload: the rule, extracted and shared ───────────────────

def test_bonus_from_payload_is_strict():
    print("\n[bonus_from_payload keeps the strict validation]")
    f = ent.bonus_from_payload
    check("a valid bonus is read", f({"remote_cap_bonus": 5}), 5)
    check("absent is 0", f({}), 0)
    check("None is 0", f({"remote_cap_bonus": None}), 0)
    # Every rejection returns 0 -- the NARROWER answer -- so a corrupted value can
    # only ever cost capacity, never create it.
    check("a bool is refused", f({"remote_cap_bonus": True}), 0)
    check("a float is refused", f({"remote_cap_bonus": 5.0}), 0)
    check("a numeric string is refused", f({"remote_cap_bonus": "5"}), 0)
    check("zero is refused", f({"remote_cap_bonus": 0}), 0)
    check("negative is refused", f({"remote_cap_bonus": -5}), 0)
    check("above the ceiling is refused",
          f({"remote_cap_bonus": ent.MAX_REMOTE_CAP_BONUS + 1}), 0)
    check("the ceiling itself is allowed",
          f({"remote_cap_bonus": ent.MAX_REMOTE_CAP_BONUS}),
          ent.MAX_REMOTE_CAP_BONUS)
    check("a non-dict is 0, not an exception", f(None), 0)


def test_purchased_bonus_delegates_rather_than_duplicating():
    print("\n[_purchased_bonus and bonus_from_payload cannot drift apart]")
    # The point of the extraction. If _purchased_bonus kept its own copy of these
    # rules, this suite would pass while the two implementations diverged -- the
    # failure that mutation testing found in the rebind suite on the same feature.
    for label, bonus in [("a valid bonus", 5), ("a refused bool", True),
                         ("an over-ceiling value", ent.MAX_REMOTE_CAP_BONUS + 1),
                         ("no bonus at all", None)]:
        key = make_key(bonus=bonus)
        p = db_with(key)
        try:
            check("stored and pure agree: %s" % label,
                  ent._purchased_bonus(p), ent.bonus_from_payload(payload_of(key)))
        finally:
            os.unlink(p)


# ── B. cap_from_payload: what a candidate key WOULD grant ───────────────────

def test_cap_from_payload():
    print("\n[cap_from_payload previews a key without installing it]")
    f = ent.cap_from_payload
    check("free + a pack", f({"tier": "free", "remote_cap_bonus": 5}), BASE + 5)
    check("free, no pack", f({"tier": "free"}), BASE)
    check("free + an unusable bonus falls to the base",
          f({"tier": "free", "remote_cap_bonus": -1}), BASE)
    check("commercial with an absolute cap",
          f({"tier": "commercial", "remote_cap": 25}), 25)
    check("commercial with no cap is unlimited",
          f({"tier": "commercial"}), ent.COMMERCIAL_REMOTE_CAP)
    # Fail toward the NARROWER entitlement, matching remote_cap_for_license.
    check("commercial with an unusable cap falls to the base",
          f({"tier": "commercial", "remote_cap": "twenty"}), BASE)
    check("a free key ignores remote_cap entirely",
          f({"tier": "free", "remote_cap": 99}), BASE)


def test_preview_agrees_with_the_installed_derivation():
    print("\n[the preview and the live derivation give the same number]")
    # cap_from_payload is deliberately NOT wired into remote_cap_for_license: that
    # function takes tier from license_status(), which accounts for expiry and
    # verdict, while this one answers a different question ("what would this key
    # give me") from the payload alone. Unifying them would risk changing live
    # entitlement behaviour. Asserting they AGREE is the anti-divergence mechanism
    # that a shared implementation would otherwise have provided.
    for label, kw in [("free + pack", dict(bonus=5)),
                      ("free, no pack", dict()),
                      ("commercial + cap", dict(tier="commercial", remote_cap=25)),
                      ("commercial unlimited", dict(tier="commercial"))]:
        key = make_key(**kw)
        p = db_with(key)
        try:
            check("preview == live: %s" % label,
                  ent.cap_from_payload(payload_of(key)),
                  ent.remote_cap_for_license(p))
        finally:
            os.unlink(p)


def test_installed_payload_reads_only_a_verified_key():
    print("\n[installed_payload refuses anything unverified]")
    good = make_key(bonus=5)
    p = db_with(good)
    try:
        got = ent.installed_payload(p)
        check_true("a valid stored key yields its payload",
                   isinstance(got, dict) and got.get("remote_cap_bonus") == 5,
                   "%r" % got)
    finally:
        os.unlink(p)

    # Signed by a DIFFERENT issuer: if this returned a payload, anyone could mint
    # themselves an entitlement by editing the licence row.
    other = Ed25519PrivateKey.generate()
    p = db_with(make_key(bonus=500, priv=other))
    try:
        check("a foreign-signed key yields nothing", ent.installed_payload(p), None)
    finally:
        os.unlink(p)

    p = db_with(None)
    try:
        check("no licence at all yields nothing", ent.installed_payload(p), None)
    finally:
        os.unlink(p)


# ── C. the guard, through the real route ────────────────────────────────────

_DGDB = os.path.join(tempfile.mkdtemp(prefix="dg-"), "alerts.db")
os.environ["NEMESIS_DB_PATH"] = _DGDB
os.replace(db_with(None), _DGDB)         # borrow the schema, then move it into place

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# MIRRORS the production PYTHONPATH exactly, read from dashboard.service:
#   /opt/nemesis/alert_manager:/opt/nemesis/core_module/hw_monitor
# Copied from core/test_admin_approval_routes.py rather than invented: importing
# dashboard under a DIFFERENT path than the service uses would test a module graph
# that never runs in production, and the failure would look like a test-only quirk
# in either direction.
for _p in (_REPO,
           os.path.join(_REPO, "alert_manager"),
           os.path.join(_REPO, "core_module", "hw_monitor"),
           os.path.join(_REPO, "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import dashboard
except Exception:
    import traceback
    traceback.print_exc()
    die("could not import dashboard")

app = dashboard.app
app.config["TESTING"] = True


def _bypass_auth():
    """Reach the handler without a session. The auth gate is test_roles.py's
    assertion; what is under test here is the downgrade decision."""
    removed = []
    for fn in list(app.before_request_funcs.get(None, [])):
        if fn.__name__ in ("_enforce_setup_and_auth", "_enforce_session_realm",
                           "_enforce_role"):
            app.before_request_funcs[None].remove(fn)
            removed.append(fn.__name__)
    return removed


_removed = _bypass_auth()
if not _removed:
    die("no auth gate was found to bypass -- the handler names have changed, and a "
        "suite that silently bypasses nothing would be testing the login redirect")

# The before_request gates are only half of it: `@login_required` is a flask_login
# DECORATOR, already applied at import, so removing before_request handlers does not
# touch it. LOGIN_DISABLED is flask_login's own supported way past it.
app.config["LOGIN_DISABLED"] = True
client = app.test_client()

# ⛔ PROVE THE BYPASS TOOK. Without this, every assertion below would be comparing
# against a 302-to-login: "the licence was not replaced" is trivially true when the
# request never reached the handler, so the suite would pass while testing nothing.
# This cost a debugging cycle here already -- a truncated `tail` hid the 302s and the
# one check that survived was the one a redirect satisfies by accident.
_probe = client.post("/api/license/activate", json={"license_key": ""})
if _probe.status_code == 302:
    die("still redirecting to login (%s) -- the auth bypass did not take, and every "
        "route assertion below would be measuring the redirect"
        % _probe.headers.get("Location"))
print("  (bypassed: %s + LOGIN_DISABLED; probe returned %d, not a redirect)"
      % (", ".join(_removed), _probe.status_code))


def set_stored(key):
    """Put exactly one licence row (or none) in the DB the route actually reads."""
    conn = sqlite3.connect(_DGDB)
    conn.execute("DELETE FROM license_state")
    if key is not None:
        conn.execute("INSERT INTO license_state (id, install_id, install_signals, "
                     "install_conf, license_key, tier) VALUES (1,?,?,?,?,?)",
                     (_INSTALL, json.dumps({"t": 1}), "high", key, "free"))
    conn.commit()
    conn.close()


def stored_key():
    row = sqlite3.connect(_DGDB).execute(
        "SELECT license_key FROM license_state WHERE id=1").fetchone()
    return row[0] if row else None


def activate(key, confirm=None, as_form=False):
    """POST to the real route, exactly as the browser does."""
    payload = {"license_key": key}
    if confirm is not None:
        payload["confirm_downgrade"] = confirm
    if as_form:
        return client.post("/api/license/activate", data=payload)
    return client.post("/api/license/activate", json=payload)


def test_an_older_key_is_refused_with_real_numbers():
    print("\n[an older key is refused, and says what it would cost]")
    newer = make_key(bonus=10, issued_at=T0 + 1000)
    older = make_key(bonus=5, issued_at=T0)
    set_stored(newer)

    r = activate(older)
    body = r.get_json() or {}
    check("refused with 409", r.status_code, 409)
    check("...naming the reason", body.get("verdict"), "older_key")
    # The operator decision was an override showing REAL before/after numbers, not a
    # generic warning -- a user cannot weigh "are you sure?".
    check("...reporting the capacity now held", body.get("current_cap"), BASE + 10)
    check("...and what the older key would give", body.get("incoming_cap"), BASE + 5)
    check_true("...and it says the install is unchanged",
               "unchanged" in (body.get("detail") or "").lower(), body.get("detail"))
    check("the stored licence was NOT replaced", stored_key(), newer)


def test_newer_and_equal_keys_still_install():
    print("\n[the guard does not block a legitimate upgrade or a reinstall]")
    older = make_key(bonus=5, issued_at=T0)
    newer = make_key(bonus=10, issued_at=T0 + 1000)

    set_stored(older)
    check("a NEWER key installs", activate(newer).status_code, 200)
    check("...and replaced the stored one", stored_key(), newer)

    # Re-pasting the key you already have is not a downgrade.
    set_stored(older)
    check("the SAME key re-installs", activate(older).status_code, 200)

    # Nothing stored yet: there is no "before", so nothing to protect.
    set_stored(None)
    check("a first installation is unaffected", activate(older).status_code, 200)


def test_the_override_works_but_only_over_json():
    print("\n[the override is honoured on JSON, refused from a form]")
    newer = make_key(bonus=10, issued_at=T0 + 1000)
    older = make_key(bonus=5, issued_at=T0)

    set_stored(newer)
    check("an explicit JSON confirm installs the older key",
          activate(older, confirm=True).status_code, 200)
    check("...and it really was stored", stored_key(), older)

    # A cross-origin FORM post can carry confirm_downgrade=true. If that were
    # honoured, this guard would become the mechanism for the very downgrade it
    # exists to prevent.
    set_stored(newer)
    check("a FORM confirm is not honoured",
          activate(older, confirm="true", as_form=True).status_code, 409)
    check("...and the licence is untouched", stored_key(), newer)

    # Control: the same form post WITHOUT a downgrade still works, so the refusal
    # above is about the override and not about forms being rejected wholesale.
    set_stored(older)
    check("[control] a form post that is not a downgrade still installs",
          activate(newer, as_form=True).status_code, 200)


def test_an_unverifiable_stored_key_does_not_lock_you_out():
    print("\n[a corrupt stored licence must not block a valid install]")
    # Fail-safe direction: an unverifiable stored key already grants 0 capacity, so
    # there is no downgrade available to prevent -- and refusing here would lock a
    # user out of their own product to protect capacity they do not have.
    other = Ed25519PrivateKey.generate()
    set_stored(make_key(bonus=500, issued_at=T0 + 9999, priv=other))
    check("a valid key installs over an unverifiable one",
          activate(make_key(bonus=5, issued_at=T0)).status_code, 200)

    # And a stored key with no issued_at gives nothing to compare against.
    body = lk.encode_payload({"install_id": _INSTALL, "tier": "free",
                              "licence_id": "no-timestamp"})
    keyless = "%s.%s.%s" % (lk.KEY_PREFIX, _b64u(body), _b64u(_PRIV.sign(body)))
    set_stored(keyless)
    check("...and so does one carrying no issued_at",
          activate(make_key(bonus=5, issued_at=T0)).status_code, 200)


EXPECTED_CHECKS = 46

if __name__ == "__main__":
    print("=" * 66)
    print("downgrade guard: an older key must not silently cost you capacity")
    print("=" * 66)
    test_bonus_from_payload_is_strict()
    test_purchased_bonus_delegates_rather_than_duplicating()
    test_cap_from_payload()
    test_preview_agrees_with_the_installed_derivation()
    test_installed_payload_reads_only_a_verified_key()
    test_an_older_key_is_refused_with_real_numbers()
    test_newer_and_equal_keys_still_install()
    test_the_override_works_but_only_over_json()
    test_an_unverifiable_stored_key_does_not_lock_you_out()

    print("\n" + "=" * 66)
    print("checks run: %d" % len(_ran))
    if len(_ran) != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d, expected %d" % (len(_ran), EXPECTED_CHECKS))
        sys.exit(1)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
