"""Credential store reader -- ADR 0028 D11.5 Option C.

The reader's whole job is to either produce a real app password or FAIL LOUDLY.
The bugs worth catching here are all the same shape: a failed read wearing the
costume of a legitimate answer -- an empty string handed to IMAP login, an empty
dict meaning "no mailboxes", a False meaning "not configured" when the truth is
"the store is unreadable". Every one of those renders as a calm, wrong UI.

ASSERTION COUNT IS FIXED -- no check sits inside a success-path branch.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for p in (ROOT, os.path.join(ROOT, "alert_manager")):
    if p not in sys.path:
        sys.path.insert(0, p)

from modules.email_security import credential_store as cs      # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s\n         got=%r want=%r" % (label, got, want))


def raises(exc_type, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc_type:
        return True
    except Exception as exc:                                    # noqa: BLE001
        return "WRONG-EXC:%s" % type(exc).__name__
    return False


def write_store(text):
    fd, path = tempfile.mkstemp(prefix="email-secrets-", suffix=".env")
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return path


print("== 1. THE READER AND THE WRITER AGREE ON THE KEY SHAPE ==")
# If these two ever drift, the reader looks up keys the writer can never have
# written -- and the symptom is "enrollment succeeded but scanning never starts",
# with nothing in either half looking wrong on its own.
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))
os.environ.setdefault("NEMESIS_DB_PATH", "/nonexistent/not/here/alerts.db")
import nemesis_fwd as fwd                                       # noqa: E402

check("reader regex == writer regex",
      cs.CREDENTIAL_REF_RE.pattern, fwd.EMAIL_SECRET_KEY_RE.pattern)
check("reader path default == writer path default",
      cs.SECRETS_PATH, fwd.EMAIL_SECRETS_PATH)
check("MAX_SLOT matches the 3-digit key shape", cs.MAX_SLOT, 999)

print("\n== 2. SLOT REFS ==")
check("slot 0 -> EMAIL_SEC_APPPW_0", cs.slot_ref(0), "EMAIL_SEC_APPPW_0")
check("slot 7 -> EMAIL_SEC_APPPW_7", cs.slot_ref(7), "EMAIL_SEC_APPPW_7")
check("slot 999 -> EMAIL_SEC_APPPW_999", cs.slot_ref(999), "EMAIL_SEC_APPPW_999")
check("every generated ref is one the WRITER would accept",
      all(bool(fwd.EMAIL_SECRET_KEY_RE.match(cs.slot_ref(n)))
          for n in (0, 1, 9, 10, 99, 100, 999)))
check("slot 1000 raises (keyspace exhausted, loudly)",
      raises(cs.CredentialError, cs.slot_ref, 1000))
check("a negative slot raises", raises(cs.CredentialError, cs.slot_ref, -1))
check("a non-int slot raises", raises(cs.CredentialError, cs.slot_ref, "3"))
check("True is not accepted as the int 1",
      raises(cs.CredentialError, cs.slot_ref, True))

print("\n== 3. REF VALIDATION MIRRORS THE WRITER ==")
check("accepts a real ref", cs.is_valid_ref("EMAIL_SEC_APPPW_12"))
for bad in ("EMAIL_SEC_APPPW_1000", "X_EMAIL_SEC_APPPW_1", "EMAIL_SEC_APPPW_1_X",
            "email_sec_apppw_1", "PATH", "", None, 5):
    check("rejects %r" % (bad,), not cs.is_valid_ref(bad))

print("\n== 4. PARSING ==")
p = write_store(
    "# a comment\n"
    "\n"
    "EMAIL_SEC_APPPW_1=abcd efgh ijkl mnop\n"
    "  EMAIL_SEC_APPPW_2 = spaced out value \n"
    "export EMAIL_SEC_APPPW_3=exported\n"
    "EMAIL_SEC_APPPW_4='single quoted'\n"
    'EMAIL_SEC_APPPW_5="double quoted"\n'
    "EMAIL_SEC_APPPW_6=has=equals=inside\n"
    "# EMAIL_SEC_APPPW_9=commented out\n")
check("a plain value", cs.get_secret("EMAIL_SEC_APPPW_1", p), "abcd efgh ijkl mnop")
check("surrounding whitespace is stripped",
      cs.get_secret("EMAIL_SEC_APPPW_2", p), "spaced out value")
check("`export ` prefix tolerated", cs.get_secret("EMAIL_SEC_APPPW_3", p), "exported")
check("single quotes stripped", cs.get_secret("EMAIL_SEC_APPPW_4", p), "single quoted")
check("double quotes stripped", cs.get_secret("EMAIL_SEC_APPPW_5", p), "double quoted")
# An app password containing '=' must survive verbatim -- splitting on every '='
# would silently truncate a real credential to "has".
check("a value containing '=' is NOT truncated",
      cs.get_secret("EMAIL_SEC_APPPW_6", p), "has=equals=inside")
check("a commented-out entry is not found",
      raises(cs.CredentialMissing, cs.get_secret, "EMAIL_SEC_APPPW_9", p))

print("\n== 5. FAILED READS ARE EXPLICIT, NEVER A DEFAULT ==")
# The four assertions this whole module exists for.
check("a MISSING FILE raises Unavailable, not an empty dict",
      raises(cs.CredentialUnavailable, cs.load_all, "/nonexistent/store.env"))
check("...and get_secret on it raises Unavailable too",
      raises(cs.CredentialUnavailable, cs.get_secret,
             "EMAIL_SEC_APPPW_1", "/nonexistent/store.env"))
check("an ABSENT ENTRY raises Missing, never returns ''",
      raises(cs.CredentialMissing, cs.get_secret, "EMAIL_SEC_APPPW_77", p))
empty = write_store("EMAIL_SEC_APPPW_1=\n")
check("a PRESENT-BUT-EMPTY value raises Missing, never returns ''",
      raises(cs.CredentialMissing, cs.get_secret, "EMAIL_SEC_APPPW_1", empty))
check("an INVALID ref raises before touching the filesystem",
      raises(cs.CredentialError, cs.get_secret, "PATH", "/nonexistent/store.env"))

print("\n== 6. has_secret SWALLOWS 'missing' BUT NOT 'unreadable' ==")
# The asymmetry that keeps a deployment fault from rendering as "not configured"
# on every mailbox at once.
check("True for a stored credential", cs.has_secret("EMAIL_SEC_APPPW_1", p))
check("False for an absent one", cs.has_secret("EMAIL_SEC_APPPW_77", p), False)
check("an UNREADABLE STORE still RAISES rather than reporting False",
      raises(cs.CredentialUnavailable, cs.has_secret,
             "EMAIL_SEC_APPPW_1", "/nonexistent/store.env"))

print("\n== 7. NO SECRET IS EVER RETURNED BY THE ERROR PATH ==")
try:
    cs.get_secret("EMAIL_SEC_APPPW_77", p)
    msg = ""
except cs.CredentialMissing as exc:
    msg = str(exc)
check("the not-found message names the KEY", "EMAIL_SEC_APPPW_77" in msg)
check("...and leaks no other mailbox's password", "abcd efgh ijkl mnop" not in msg)

for _p in (p, empty):
    os.unlink(_p)
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
