"""write_email_secret -- the second credential-exempt op. ADR 0028 D11.5 Option C.

WHAT THIS SUITE IS FOR
    `write_email_secret` lets an UNAUTHENTICATED household member cause a write to
    a root-owned file. That is the most dangerous shape in this helper, so every
    control that makes it safe is asserted here rather than assumed from the
    docstring: the key regex, the value shape rules, the atomic single-use
    consume, the destination file, and the peer/credential wiring.

⚠ THE CHOWN IS INTERCEPTED, NOT SKIPPED, AND THE DISTINCTION MATTERS
    `_merge_write_env_file` chowns to root:nemesis, which only root may do. A
    suite that ran as root would be a suite nobody runs; a suite that simply
    skipped the ownership step would assert the file is written while proving
    NOTHING about the permission model -- the exact "instrument that cannot fail"
    shape this project treats as a standing defect.

    So os.chown is REPLACED WITH A RECORDER and the recorded arguments are
    asserted: uid 0, gid = group `nemesis`. The ownership intent is verified
    without needing the privilege to perform it. Same for the mode.

ASSERTION COUNT IS FIXED. Every check below runs unconditionally -- none sits
inside a success-path `if`. A suite whose total shrinks under failure cannot be
compared between runs (CLAUDE.md, 2026-08-29).
"""
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Point the DB somewhere disposable BEFORE importing the helper: nemesis_fwd
# resolves db_path() at call time, but being explicit here means a mistake shows
# up as "no such table" rather than as a write to the live alerts.db.
_TMPDIR = tempfile.mkdtemp(prefix="nemesis-email-secret-test-")
os.environ["NEMESIS_DB_PATH"] = os.path.join(_TMPDIR, "alerts.db")
os.environ["NEMESIS_EMAIL_SECRETS_PATH"] = os.path.join(_TMPDIR, "email-secrets.env")
os.environ["NEMESIS_ENV_PATH"] = os.path.join(_TMPDIR, "nemesis.env")

import nemesis_fwd as fwd                                        # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s\n         got=%r want=%r" % (label, got, want))


def denied(fn, *a, **kw):
    """Return the Denied KIND, or None if the call did NOT raise Denied.

    `.kind` is the machine-readable classification ("bad_request",
    "peer_denied", "internal"); str(exc) is the human message. Asserting on kind
    keeps these checks from breaking every time a message is reworded, and it is
    the field the dispatch actually branches on.
    """
    try:
        fn(*a, **kw)
    except fwd.Denied as exc:
        return exc.kind
    except Exception as exc:                                     # noqa: BLE001
        return "NOT-DENIED:%s" % type(exc).__name__
    return None


def denied_message(fn, *a, **kw):
    """The human message. Used ONLY for the no-oracle comparison, where the
    point is that two different internal facts produce identical caller-visible
    text."""
    try:
        fn(*a, **kw)
    except fwd.Denied as exc:
        return str(exc)
    except Exception as exc:                                     # noqa: BLE001
        return "NOT-DENIED:%s" % type(exc).__name__
    return None


# ── the recorder that stands in for root ─────────────────────────────────────
_chown_calls = []
_chmod_calls = []
_real_chown, _real_chmod = os.chown, os.chmod


def _fake_chown(path, uid, gid):
    _chown_calls.append((uid, gid))


def _fake_chmod(path, mode):
    _chmod_calls.append(mode)
    _real_chmod(path, mode)


os.chown, os.chmod = _fake_chown, _fake_chmod


def _fresh_db():
    """A DB with just the enrollment table. Mirrors the canonical DDL's columns."""
    path = os.environ["NEMESIS_DB_PATH"]
    if os.path.exists(path):
        os.unlink(path)
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE email_enrollment_requests (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash     TEXT UNIQUE NOT NULL,
            owner_user_id  INTEGER,
            created_by     INTEGER,
            address_hint   TEXT,
            created_at     TEXT,
            expires_at     TEXT,
            used_at        TEXT,
            account_id     INTEGER,
            actor          TEXT
        )""")
    conn.commit()
    conn.close()
    return path


def _add_request(token, *, owner=7, hint="owner@example.com", ttl_hours=24):
    import hashlib
    th = hashlib.sha256(token.encode()).hexdigest()
    exp = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours))
    conn = sqlite3.connect(os.environ["NEMESIS_DB_PATH"])
    conn.execute(
        "INSERT INTO email_enrollment_requests "
        "(token_hash, owner_user_id, address_hint, created_at, expires_at) "
        "VALUES (?,?,?,?,?)",
        (th, owner, hint,
         datetime.now(timezone.utc).isoformat(timespec="seconds"),
         exp.isoformat(timespec="seconds")))
    conn.commit()
    conn.close()


def _secrets_text():
    p = os.environ["NEMESIS_EMAIL_SECRETS_PATH"]
    if not os.path.exists(p):
        return None
    with open(p) as fh:
        return fh.read()


print("== 1. THE FILE IS SEPARATE FROM /etc/nemesis.env ==")
# The whole operator rationale (2026-08-31): core secrets and enrollment-path
# secrets must not share a file, or routine enrollment writes pollute the
# change-monitoring signal on the high-value one.
check("the two paths are not the same file",
      fwd.EMAIL_SECRETS_PATH != fwd.NEMESIS_ENV_PATH)
# The live value is env-overridden to a temp path by this harness, so asserting
# on it would prove nothing about the shipped default. Read the DEFAULT out of
# the source instead -- the thing an install actually gets.
with open(os.path.join(ROOT, "nemesis_fwd.py")) as _fh:
    _src = _fh.read()
check("the shipped default destination is /etc/nemesis-email-secrets.env",
      '"/etc/nemesis-email-secrets.env"' in _src)
check("...and it is reached via an overridable env var",
      'os.environ.get("NEMESIS_EMAIL_SECRETS_PATH"' in _src)
check("write_email_secret does NOT appear in the nemesis.env allowlist",
      not any(k.startswith("EMAIL_SEC_APPPW")
              for k in fwd.ENV_WRITE_ALLOWED_KEYS))

print("\n== 2. KEY REGEX -- anchored at BOTH ends ==")
ok_keys = ["EMAIL_SEC_APPPW_0", "EMAIL_SEC_APPPW_1", "EMAIL_SEC_APPPW_999"]
for k in ok_keys:
    check("accepts %s" % k, bool(fwd.EMAIL_SECRET_KEY_RE.match(k)))
# The unanchored-pattern failures. Each of these WOULD match a naive
# `startswith("EMAIL_SEC_APPPW")` or an unanchored search.
bad_keys = ["EMAIL_SEC_APPPW_1000", "EMAIL_SEC_APPPW_1_PATH",
            "X_EMAIL_SEC_APPPW_1", "EMAIL_SEC_APPPW_", "EMAIL_SEC_APPPW_1a",
            "email_sec_apppw_1", "PATH", "LD_PRELOAD", "ANTHROPIC_API_KEY"]
for k in bad_keys:
    check("rejects %s" % k, not fwd.EMAIL_SECRET_KEY_RE.match(k))

print("\n== 3. PAYLOAD VALIDATION ==")
V = fwd._validate_email_secret_updates
check("no values -> bad_request", denied(V, {}), "bad_request")
check("empty dict -> bad_request", denied(V, {"values": {}}), "bad_request")
check("non-dict values -> bad_request", denied(V, {"values": "x"}), "bad_request")
check("disallowed key -> bad_request",
      denied(V, {"values": {"PATH": "/evil"}}), "bad_request")
check("denylisted key -> bad_request",
      denied(V, {"values": {"LD_PRELOAD": "/evil.so"}}), "bad_request")
check("non-string value -> bad_request",
      denied(V, {"values": {"EMAIL_SEC_APPPW_1": 5}}), "bad_request")
check("EMPTY value -> bad_request (a slot that authenticates nothing)",
      denied(V, {"values": {"EMAIL_SEC_APPPW_1": ""}}), "bad_request")
check("newline injection -> bad_request",
      denied(V, {"values": {"EMAIL_SEC_APPPW_1": "a\nPATH=/evil"}}), "bad_request")
check("carriage return -> bad_request",
      denied(V, {"values": {"EMAIL_SEC_APPPW_1": "a\rb"}}), "bad_request")
check("NUL -> bad_request",
      denied(V, {"values": {"EMAIL_SEC_APPPW_1": "a\x00b"}}), "bad_request")
check("oversize value -> bad_request",
      denied(V, {"values": {"EMAIL_SEC_APPPW_1": "x" * (fwd.ENV_VALUE_MAX + 1)}}),
      "bad_request")
check("too many keys -> bad_request",
      denied(V, {"values": {"EMAIL_SEC_APPPW_%d" % i: "v"
                            for i in range(fwd.EMAIL_SECRET_MAX_KEYS + 1)}}),
      "bad_request")
check("a good payload passes",
      V({"values": {"EMAIL_SEC_APPPW_1": "abcd efgh ijkl mnop"}}),
      {"EMAIL_SEC_APPPW_1": "abcd efgh ijkl mnop"})

print("\n== 4. THE TOKEN IS THE CREDENTIAL -- consume before writing ==")
_fresh_db()
_add_request("good-token-1")
GOOD = {"values": {"EMAIL_SEC_APPPW_1": "abcd efgh ijkl mnop"},
        "token": "good-token-1"}

check("missing token -> bad_request",
      denied(fwd.op_write_email_secret,
             {"values": {"EMAIL_SEC_APPPW_1": "v"}}), "bad_request")
check("unknown token -> peer_denied",
      denied(fwd.op_write_email_secret,
             {"values": {"EMAIL_SEC_APPPW_1": "v"}, "token": "nope"}),
      "peer_denied")

res = fwd.op_write_email_secret(dict(GOOD))
check("a valid code writes the slot", res.get("updated"), ["EMAIL_SEC_APPPW_1"])
check("...and returns the owner FROM THE ROW, not from the caller",
      res.get("owner_user_id"), 7)
check("...and the address hint", res.get("address_hint"), "owner@example.com")
check("the secret really is in the file",
      "EMAIL_SEC_APPPW_1=abcd efgh ijkl mnop" in (_secrets_text() or ""))

# THE replay check. This is the single most important assertion in the suite.
check("REPLAY of the same code is refused",
      denied(fwd.op_write_email_secret, dict(GOOD)), "peer_denied")

_add_request("expired-token", ttl_hours=-1)
check("an EXPIRED code is refused",
      denied(fwd.op_write_email_secret,
             {"values": {"EMAIL_SEC_APPPW_2": "v"}, "token": "expired-token"}),
      "peer_denied")
check("...and its MESSAGE is identical to an unknown code's (no oracle)",
      denied_message(fwd.op_write_email_secret,
                     {"values": {"EMAIL_SEC_APPPW_2": "v"},
                      "token": "expired-token"})
      == denied_message(fwd.op_write_email_secret,
                        {"values": {"EMAIL_SEC_APPPW_2": "v"},
                         "token": "no-such-token"})
      == "enrollment code not valid")
check("a refused write left NO slot 2 behind",
      "EMAIL_SEC_APPPW_2" not in (_secrets_text() or ""))

print("\n== 5. FILE MODE AND OWNERSHIP (recorded, then asserted) ==")
import grp                                                       # noqa: E402
want_gid = grp.getgrnam("nemesis").gr_gid
check("chmod was requested as 0640", _chmod_calls[-1], 0o640)
check("chown was requested as uid 0 (root)", _chown_calls[-1][0], 0)
check("chown was requested as group 'nemesis'", _chown_calls[-1][1], want_gid)
check("the live file is not group-writable or world-readable",
      oct(os.stat(os.environ["NEMESIS_EMAIL_SECRETS_PATH"]).st_mode)[-3:], "640")

print("\n== 6. MERGE PRESERVES THE FILE, and nemesis.env is UNTOUCHED ==")
with open(os.environ["NEMESIS_EMAIL_SECRETS_PATH"], "w") as fh:
    fh.write("# a human-written comment\nEMAIL_SEC_APPPW_1=old\n\n")
_add_request("good-token-2")
fwd.op_write_email_secret({"values": {"EMAIL_SEC_APPPW_1": "new"},
                           "token": "good-token-2"})
txt = _secrets_text() or ""
check("the comment survived a rewrite", "# a human-written comment" in txt)
check("the value was replaced in place", "EMAIL_SEC_APPPW_1=new" in txt)
check("...and the old value is gone", "EMAIL_SEC_APPPW_1=old" not in txt)
check("/etc/nemesis.env was never created by any of this",
      not os.path.exists(os.environ["NEMESIS_ENV_PATH"]))

print("\n== 7. WIRING -- registered, credential-exempt, dashboard-only ==")
check("the op is dispatchable", "write_email_secret" in fwd.OPS)
check("it is credential-EXEMPT", "write_email_secret" in fwd.NO_CREDENTIAL_OPS)
check("the dashboard peer may call it",
      "write_email_secret" in fwd.PEER_POLICY["dashboard"]["ops"])
for peer in ("alert-watcher", "fail2ban"):
    check("the unattended %s peer may NOT" % peer,
          "write_email_secret" not in fwd.PEER_POLICY[peer]["ops"])
check("it has its own audit action",
      fwd.audit_action_for("write_email_secret"), "email_write_secret")
check("...distinct from write_env's",
      fwd.audit_action_for("write_email_secret")
      != fwd.audit_action_for("write_env"))
check("it has its own audit ACTOR, not failsafe-revert's",
      fwd.NO_CREDENTIAL_ACTOR.get("write_email_secret"), "token:email-enrollment")
check("failsafe_revert's actor is unchanged",
      fwd.NO_CREDENTIAL_ACTOR.get("failsafe_revert"), "token:failsafe-revert")
check("it is NOT in WRITE_OPS (that path is unreachable for exempt ops)",
      "write_email_secret" not in fwd.WRITE_OPS)

os.chown, os.chmod = _real_chown, _real_chmod
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
