"""Enrollment, composed end to end, for BOTH providers. ADR 0028 D11.5 Option C.

WHAT THIS COVERS THAT NOTHING ELSE DOES
    test_enroll_route_public.py reads dashboard.py's source and proves the route
    is wired, exempt and escaped. test_fwd_email_secret.py proves the privileged
    op consumes and writes. Neither proves the PIECES COMPOSE -- that a code
    minted by the admin API is the same code the helper consumes, that the slot
    the allocator returns is the key the reader later resolves, and that a
    provider's host and port survive the trip into the account row.

    Every one of those is a seam between two modules that were tested apart.

WHY BOTH PROVIDERS, EXPLICITLY
    The instruction this was built to satisfy was "verify it works for both
    rather than assuming it is provider-agnostic". So the Gmail and Proton paths
    are run separately AND their results are compared: §5 asserts the two
    mailboxes landed on DIFFERENT hosts, ports and TLS modes. Without that
    comparison a build that silently used Gmail's settings for every provider
    would pass every other check here.

WHAT IS SIMULATED, STATED PLAINLY
    The Flask layer is NOT exercised (importing dashboard.py pulls in the whole
    appliance). This drives the same calls, in the same order, that
    `email_enroll_complete` makes. So it verifies the composition, not the HTTP
    plumbing -- the route's own wiring is what the static suite covers, and the
    two together are what make the claim.

    os.chown is intercepted because the writer chowns to root; see
    test_fwd_email_secret.py for why that is a recorder rather than a skip.

NO NETWORK, NO REAL MAILBOX, NO REAL CREDENTIALS, NO LIVE DB.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

_TMP = tempfile.mkdtemp(prefix="emailsec-e2e-")
_DB = os.path.join(_TMP, "alerts.db")
_SECRETS = os.path.join(_TMP, "email-secrets.env")
os.environ["NEMESIS_DB_PATH"] = _DB
os.environ["NEMESIS_EMAIL_SECRETS_PATH"] = _SECRETS
os.environ["NEMESIS_ENV_PATH"] = os.path.join(_TMP, "nemesis.env")

import modules                                                  # noqa: E402
import database                                                 # noqa: E402
import data_manager as dm_mod                                   # noqa: E402
import nemesis_fwd as fwd                                       # noqa: E402

database.DB_PATH = _DB
modules.set_shared_db_path(_DB)
database.init_email_security_tables()

from modules.email_security import writes                       # noqa: E402
from modules.email_security import enrollment                   # noqa: E402
from modules.email_security import providers                    # noqa: E402
from modules.email_security import credential_store as cs       # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s\n         got=%r want=%r" % (label, got, want))


# chown-to-root recorder (see module header)
_real_chown = os.chown
os.chown = lambda p, u, g: None

# The reader caches nothing, but it read SECRETS_PATH at import. Point it at the
# harness file explicitly rather than relying on import order -- an ordering
# assumption is exactly the kind of premise that quietly stops holding.
cs.SECRETS_PATH = _SECRETS
fwd.EMAIL_SECRETS_PATH = _SECRETS


def account_row(address):
    conn = modules.get_data_manager().connect("email_security")
    try:
        cur = conn.execute(
            "SELECT address, provider, imap_host, imap_port, mailbox, "
            "       credential_ref, enabled, owner_user_id "
            "  FROM email_accounts WHERE address=?",
            (address,))
        row = cur.fetchone()
        return dict(zip([d[0] for d in cur.description], row)) if row else None
    finally:
        conn.close()


def enrol(provider_key, address, secret, *, owner=42):
    """Drive the exact sequence email_enroll_complete performs."""
    now = datetime.now(timezone.utc)
    code = enrollment.new_token()
    writes.create_enrollment_request(
        enrollment.token_hash(code), owner, created_by=None,
        address_hint=address, created_at=now.isoformat(timespec="seconds"),
        expires_at=enrollment.expiry_from(now).isoformat(timespec="seconds"))

    prov = providers.get(provider_key)
    slot = writes.allocate_credential_slot()
    ref = cs.slot_ref(slot)
    res = fwd.op_write_email_secret(
        {"values": {ref: secret}, "token": code, "source_ip": "203.0.113.7"})
    # owner_user_id comes from the row the consume WON -- mirroring what
    # email_enroll_complete does. Passing it from the caller instead would make
    # this test unable to catch the defect where it is dropped.
    writes.add_account(address, prov["imap_host"], ref,
                       provider=provider_key, imap_port=prov["imap_port"],
                       enabled=False, owner_user_id=res.get("owner_user_id"))
    return code, ref, res


print("== 0. CONTROLS: the harness is what it claims to be ==")
check("throwaway DB, not the live one",
      "/var/lib/nemesis" not in _DB and os.path.exists(_DB))
check("REAL DataManager, not a stub",
      isinstance(modules.get_data_manager(), dm_mod.DataManager))
check("grant enforcement is ON (so a missing grant would FAIL, not warn)",
      dm_mod.namespace_mode("email_security"), dm_mod.MODE_ENFORCE)
# The regression guard for the bug found 2026-08-31: both tables the enrollment
# path writes must be granted, or the whole flow 500s on its first step.
check("email_enrollment_requests is granted",
      dm_mod.allowed("email_security", "email_enrollment_requests"))
check("email_credential_seq is granted",
      dm_mod.allowed("email_security", "email_credential_seq"))
check("the secrets file does not exist yet", not os.path.exists(_SECRETS))

print("\n== 1. GMAIL: mint -> complete -> stored ==")
g_code, g_ref, g_res = enrol("gmail", "owner@gmail.com", "abcd efgh ijkl mnop")
check("the credential is readable back through the reader",
      cs.get_secret(g_ref), "abcd efgh ijkl mnop")
check("...including its inner spaces, verbatim",
      " " in cs.get_secret(g_ref))
check("the helper returned the owner from the CONSUMED ROW",
      g_res.get("owner_user_id"), 42)
g_row = account_row("owner@gmail.com")
check("account row exists", g_row is not None)
check("  provider recorded", g_row["provider"], "gmail")
check("  imap_host is Gmail's", g_row["imap_host"], "imap.gmail.com")
check("  imap_port is 993", g_row["imap_port"], 993)
check("  credential_ref names the slot", g_row["credential_ref"], g_ref)
check("  mailbox defaults to INBOX", g_row["mailbox"], "INBOX")
check("  SCANNING IS OFF -- adding and reading are two consents",
      g_row["enabled"], 0)
# ⚠ REGRESSION GUARD (audit, 2026-08-31). This column was uniformly NULL while
# the route docstring claimed the owner came back from the helper and was stored.
# It was returned, written to a log line, and dropped.
check("  the OWNER from the consumed row is STORED, not just logged",
      g_row["owner_user_id"], 42)

print("\n== 2. PROTON: the same flow, different transport ==")
p_code, p_ref, p_res = enrol("proton", "owner@proton.me", "bridge-generated-pw")
check("the credential is readable back", cs.get_secret(p_ref), "bridge-generated-pw")
p_row = account_row("owner@proton.me")
check("account row exists", p_row is not None)
check("  provider recorded", p_row["provider"], "proton")
check("  imap_host is LOOPBACK (Bridge, not a Proton server)",
      p_row["imap_host"], "127.0.0.1")
check("  imap_port is Bridge's 1143", p_row["imap_port"], 1143)
check("  credential_ref names its own slot", p_row["credential_ref"], p_ref)
check("  SCANNING IS OFF here too", p_row["enabled"], 0)
check("  the owner is recorded here too", p_row["owner_user_id"], 42)

print("\n== 3. THE TWO ENROLLMENTS DID NOT COLLIDE ==")
check("they were given DIFFERENT credential slots", g_ref != p_ref)
check("each slot still holds its OWN secret",
      (cs.get_secret(g_ref), cs.get_secret(p_ref)),
      ("abcd efgh ijkl mnop", "bridge-generated-pw"))
check("both slots coexist in one file",
      sorted(k for k in cs.load_all() if k.startswith("EMAIL_SEC_APPPW_")),
      sorted([g_ref, p_ref]))

print("\n== 4. SINGLE-USE HELD ACROSS THE REAL FLOW ==")
# Replaying a spent code must not write anything, even with a fresh slot.
spare = cs.slot_ref(writes.allocate_credential_slot())
try:
    fwd.op_write_email_secret({"values": {spare: "attacker"}, "token": g_code})
    replayed = True
except fwd.Denied:
    replayed = False
check("replaying Gmail's spent code is REFUSED", replayed, False)
check("...and wrote no credential for the spare slot",
      spare in cs.load_all(), False)

print("\n== 5. PROVIDER-SPECIFIC, NOT PROVIDER-AGNOSTIC ==")
# ⚠ THE CONTROL FOR THIS WHOLE FILE. Without these three, a build that used
# Gmail's transport for every provider would pass every assertion above.
check("the two mailboxes got DIFFERENT hosts",
      g_row["imap_host"] != p_row["imap_host"])
check("...DIFFERENT ports", g_row["imap_port"] != p_row["imap_port"])
check("...and DIFFERENT TLS modes in the provider table",
      providers.get("gmail")["tls_mode"] != providers.get("proton")["tls_mode"])
check("only Proton is allowed a self-signed certificate",
      (providers.get("gmail")["allow_self_signed"],
       providers.get("proton")["allow_self_signed"]), (False, True))
check("...and it is loopback-only, which is what makes that defensible",
      providers.get("proton")["loopback_only"])

print("\n== 6. THE FILE ITSELF ==")
check("mode is 0640", oct(os.stat(_SECRETS).st_mode)[-3:], "640")
check("/etc/nemesis.env was never created by any of this",
      not os.path.exists(os.environ["NEMESIS_ENV_PATH"]))
with open(_SECRETS) as fh:
    body = fh.read()
check("the file holds ONLY EMAIL_SEC_APPPW_ keys",
      all(l.split("=")[0].strip().startswith("EMAIL_SEC_APPPW_")
          for l in body.splitlines() if l.strip() and not l.startswith("#")))

os.chown = _real_chown
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
