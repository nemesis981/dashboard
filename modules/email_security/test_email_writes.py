"""Stage 2.7 -- the write layer, against a REAL Data Manager.

DELIBERATELY NOT STUBBED, unlike test_module.py. That suite fakes the Data
Manager because it is testing lifecycle and status logic, which is right for it.
It is exactly wrong here: data_manager.py's own dhcp comment warns that a module
whose suite builds tables on a plain connection will PASS every test with a
missing namespace grant, and fail only in production as a `WOULD DENY` log line
with the write silently not happening. A stubbed DM cannot observe the grant at
all, so every check below runs against a genuine DataManager on a throwaway DB.

NO NETWORK, NO REAL MAILBOX, NO CREDENTIALS, NO LIVE DB.
"""
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")   # mirrors dashboard.service

import modules                                              # noqa: E402
import database                                             # noqa: E402
import data_manager as dm_mod                               # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


# ── real DM on a throwaway DB ───────────────────────────────────────────────
_TMPDB = os.path.join(tempfile.mkdtemp(prefix="emailsec-writes-"), "t.db")
database.DB_PATH = _TMPDB
modules.set_shared_db_path(_TMPDB)
database.init_email_security_tables()

import writes                                               # noqa: E402

DM = modules.get_data_manager()

print("-- 0. CONTROLS: the harness is what it claims to be --")
check("throwaway DB in use, not the live one",
      "/var/lib/nemesis" not in _TMPDB and os.path.exists(_TMPDB), _TMPDB)
check("CONTROL: this is a REAL DataManager, not a stub",
      isinstance(DM, dm_mod.DataManager), type(DM))
check("CONTROL: enforcement is ON for this module (grant is load-bearing)",
      dm_mod.namespace_mode("email_security") == dm_mod.MODE_ENFORCE,
      dm_mod.namespace_mode("email_security"))

print("\n-- 1. The namespace grant: present, and EXACT-match not prefix --")
check("email_accounts is writable", dm_mod.allowed("email_security", "email_accounts"))
check("email_message_verdicts is writable",
      dm_mod.allowed("email_security", "email_message_verdicts"))
# A bare tuple ("email_",) would fall through to startswith() and pass these.
for t in ("email_accounts_archive", "email_anything", "email_"):
    check("DENIES %s (exact-match, not a prefix grant)" % t,
          dm_mod.allowed("email_security", t) is False)
check("DENIES a table owned by someone else",
      dm_mod.allowed("email_security", "malware_findings") is False)

print("\n-- 2. add_account: actor stamped on OUR column, not just the op log --")
DM.set_actor("user:alice")
writes.add_account("a@example.com", "imap.example.com", "EMAIL_SEC_APPPW_1")
conn = DM.connect("email_security")
row = conn.execute("SELECT id, enabled, created_actor, created_at FROM "
                   "email_accounts WHERE address='a@example.com'").fetchone()
conn.close()
_acct_id, _enabled, _actor, _created = row
check("created_actor stamped from current_actor()", _actor == "user:alice", _actor)
check("enabled defaults FALSE (adding != consenting to read)", _enabled == 0, _enabled)

# The op-log actor is a DIFFERENT mechanism; both must be present.
raw = DM.connect("email_security")
oplog = raw.execute(
    "SELECT actor, table_name FROM %s WHERE table_name='email_accounts' "
    "ORDER BY rowid DESC LIMIT 1" % dm_mod.OP_LOG_TABLE).fetchone()
raw.close()
check("op-log row also written, with its own actor",
      oplog is not None and oplog[0] == "user:alice", oplog)

print("\n-- 3. Re-registering must NOT rewrite who created it --")
DM.set_actor("user:bob")
writes.add_account("a@example.com", "imap2.example.com", "EMAIL_SEC_APPPW_2")
conn = DM.connect("email_security")
r2 = conn.execute("SELECT created_actor, created_at, imap_host, credential_ref "
                  "FROM email_accounts WHERE address='a@example.com'").fetchone()
n_rows = conn.execute("SELECT COUNT(*) FROM email_accounts").fetchone()[0]
conn.close()
check("still ONE row (upsert, not a duplicate)", n_rows == 1, n_rows)
check("created_actor still alice, NOT bob", r2[0] == "user:alice", r2[0])
check("created_at unchanged", r2[1] == _created, (r2[1], _created))
check("connection settings DID update", r2[2] == "imap2.example.com", r2[2])
check("credential_ref DID update", r2[3] == "EMAIL_SEC_APPPW_2", r2[3])

print("\n-- 4. THE ONE THAT MATTERS: a re-scan must not un-quarantine --")
writes.record_verdict(_acct_id, 100, 5, verdict="phish", confidence=0.9,
                      reason="first scan")
writes.set_quarantine_state(_acct_id, 100, 5, "quarantined")
conn = DM.connect("email_security")
q1 = conn.execute("SELECT quarantine_state, quarantine_actor FROM "
                  "email_message_verdicts WHERE uid=5").fetchone()
conn.close()
check("quarantined, with quarantine_actor stamped",
      q1[0] == "quarantined" and q1[1] == "user:bob", q1)

# Re-scan the SAME message. This is where the upsert default would wipe it.
writes.record_verdict(_acct_id, 100, 5, verdict="clean", confidence=0.1,
                      reason="second scan")
conn = DM.connect("email_security")
q2 = conn.execute("SELECT quarantine_state, quarantine_actor, verdict, reason "
                  "FROM email_message_verdicts WHERE uid=5").fetchone()
n_v = conn.execute("SELECT COUNT(*) FROM email_message_verdicts").fetchone()[0]
conn.close()
check("quarantine_state SURVIVED the re-scan", q2[0] == "quarantined", q2[0])
check("quarantine_actor SURVIVED the re-scan", q2[1] == "user:bob", q2[1])
check("verdict DID update", q2[2] == "clean", q2[2])
check("reason DID update", q2[3] == "second scan", q2[3])
check("still ONE verdict row", n_v == 1, n_v)

print("\n-- 5. uidvalidity is part of the identity, not decoration --")
writes.record_verdict(_acct_id, 200, 5, verdict="clean")   # same uid, new validity
conn = DM.connect("email_security")
n_v2 = conn.execute("SELECT COUNT(*) FROM email_message_verdicts").fetchone()[0]
still_q = conn.execute("SELECT quarantine_state FROM email_message_verdicts "
                       "WHERE uidvalidity=100 AND uid=5").fetchone()[0]
conn.close()
check("UID 5 at a NEW uidvalidity is a SEPARATE message", n_v2 == 2, n_v2)
check("...and did not disturb the original", still_q == "quarantined", still_q)

print("\n-- 6. verdict stays NULL when scanned-but-not-judged --")
writes.record_verdict(_acct_id, 100, 9, signals_json='{"has_form":true}')
conn = DM.connect("email_security")
v = conn.execute("SELECT verdict, scanned_at, quarantine_state FROM "
                 "email_message_verdicts WHERE uid=9").fetchone()
conn.close()
check("verdict is NULL, not a manufactured 'clean'", v[0] is None, v[0])
check("...but scanned_at IS set (it WAS scanned)", bool(v[1]), v[1])
check("...and quarantine_state defaults to 'none'", v[2] == "none", v[2])

print("\n-- 7. A bad quarantine state is refused, not stored --")
try:
    writes.set_quarantine_state(_acct_id, 100, 5, "quarrantined")   # typo
    check("typo'd state raises", False, "it was ACCEPTED")
except ValueError:
    check("typo'd state raises ValueError rather than storing it", True)
conn = DM.connect("email_security")
unchanged = conn.execute("SELECT quarantine_state FROM email_message_verdicts "
                         "WHERE uidvalidity=100 AND uid=5").fetchone()[0]
conn.close()
check("...and the row is untouched", unchanged == "quarantined", unchanged)

print("\n-- 8. set_account_enabled reports reality --")
n = writes.set_account_enabled("a@example.com", True)
check("enabling an existing mailbox affects 1 row", n == 1, n)
# RE-READ, don't trust rowcount. A missing conn.commit() still reports rowcount=1
# while discarding the write at close() -- this assertion is what distinguishes
# "reported success" from "actually persisted".
conn = DM.connect("email_security")
_en = conn.execute("SELECT enabled FROM email_accounts "
                   "WHERE address='a@example.com'").fetchone()[0]
conn.close()
check("...and the change actually PERSISTED (re-read, not rowcount)",
      _en == 1, _en)
n0 = writes.set_account_enabled("nobody@example.com", True)
check("enabling a NON-existent mailbox returns 0, invents nothing", n0 == 0, n0)
conn = DM.connect("email_security")
n_after = conn.execute("SELECT COUNT(*) FROM email_accounts").fetchone()[0]
conn.close()
check("...and created no phantom row", n_after == 1, n_after)

print("\n-- 9. MUTATION: prove section 4 can actually go red --")
# Re-run the critical write with the upsert default (update omitted), which is
# the "simplification" the module header warns against. It MUST clobber.
_probe_db = os.path.join(tempfile.mkdtemp(prefix="emailsec-mut-"), "m.db")
database.DB_PATH = _probe_db
database.init_email_security_tables()
mdm = dm_mod.DataManager(_probe_db)
mdm.set_actor("user:mut")
mdm.upsert("email_security", "email_accounts",
           {"address": "m@example.com", "imap_host": "h", "credential_ref": "R",
            "created_at": "t", "enabled": 0},
           conflict_cols=("address", "mailbox"))
mdm.upsert("email_security", "email_message_verdicts",
           {"account_id": 1, "uidvalidity": 1, "uid": 1, "scanned_at": "t",
            "verdict": "phish", "quarantine_state": "quarantined"},
           conflict_cols=("account_id", "uidvalidity", "uid"))
# Same row again WITHOUT the explicit update list -> default clobbers everything.
mdm.upsert("email_security", "email_message_verdicts",
           {"account_id": 1, "uidvalidity": 1, "uid": 1, "scanned_at": "t2",
            "verdict": "clean", "quarantine_state": "none"},
           conflict_cols=("account_id", "uidvalidity", "uid"))
mc = mdm.connect("email_security")
mq = mc.execute("SELECT quarantine_state FROM email_message_verdicts "
                "WHERE uid=1").fetchone()[0]
mc.close()
check("MUTANT (upsert default) DOES un-quarantine -> section 4 is a real check",
      mq == "none", "got %r; if this is 'quarantined' the section-4 checks are vacuous" % mq)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
