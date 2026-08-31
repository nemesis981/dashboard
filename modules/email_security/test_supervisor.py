"""The mailbox supervisor. ADR 0028 build spec stage 2.8.

THE ASSERTION THIS FILE EXISTS FOR IS IN SECTION 2.
    `ImapIdleClient.run()` ends the loop on a permanent auth failure by design.
    That is correct, and one layer up it creates a silent failure: a thread that
    has exited is not connected, not retrying, and not visibly broken. Without
    the supervisor recording it, a single wrong password stops a mailbox being
    scanned FOREVER while the dashboard keeps reporting the module healthy.

    So section 2 forces exactly that -- a client whose run() raises
    ImapAuthError -- and asserts the mailbox becomes VISIBLY broken. Every other
    section supports it.

NO NETWORK, NO REAL MAILBOX, NO REAL CREDENTIALS. The client and the account
loader are injected; §5 uses a real Data Manager on a throwaway DB, because a
stubbed one cannot observe the namespace grant (data_manager.py's own warning).

ASSERTION COUNT IS FIXED -- no check sits inside a success-path branch.
"""
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

_TMP = tempfile.mkdtemp(prefix="emailsec-sup-")
os.environ["NEMESIS_DB_PATH"] = os.path.join(_TMP, "alerts.db")

import modules                                                  # noqa: E402
import database                                                 # noqa: E402
import data_manager as dm_mod                                   # noqa: E402

database.DB_PATH = os.environ["NEMESIS_DB_PATH"]
modules.set_shared_db_path(os.environ["NEMESIS_DB_PATH"])
database.init_email_security_tables()

from modules.email_security import imap_idle                    # noqa: E402
from modules.email_security import supervisor as sup_mod        # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s\n         got=%r want=%r" % (label, got, want))


ACCOUNT = {"id": 1, "address": "owner@example.com", "provider": "gmail",
           "imap_host": "imap.example.com", "imap_port": 993,
           "mailbox": "INBOX", "credential_ref": "EMAIL_SEC_APPPW_1"}


class FakeClient:
    """Stands in for ImapIdleClient. `raises` is what run() does."""

    def __init__(self, raises=None, uidvalidity=99, block=True):
        self.raises = raises
        self.uidvalidity = uidvalidity
        self.closed = False
        self.ran = threading.Event()
        self._block = block
        self.on_message = None

    def run(self, stop):
        self.ran.set()
        if self.raises is not None:
            raise self.raises
        if self._block:
            stop.wait(5)          # returns when stop is set, like the real one

    def close(self):
        self.closed = True


def make_sup(client, accounts=None):
    return sup_mod.MailboxSupervisor(
        client_factory=lambda acct, cb: (setattr(client, "on_message", cb)
                                         or client),
        account_loader=lambda: list(accounts if accounts is not None
                                    else [ACCOUNT]))


def first(seq, key=None, default=None):
    """Element 0, or a default. NEVER an IndexError.

    ⚠ ADDED AFTER A MUTATION RUN PROVED THE SUITE COULD NOT REPORT ITS OWN
    FAILURES. Indexing [0] directly meant that when the very defect this file
    guards against was introduced, the suite died with an IndexError partway
    through section 2 instead of printing the remaining checks -- so the
    assertion total shrank under failure, which is exactly the run-to-run
    comparison hazard the header claims this suite avoids. A suite that crashes
    when the thing it tests breaks is reporting less, not more.
    """
    if not seq:
        return default
    return seq[0].get(key, default) if key else seq[0]


def wait_for(pred, timeout=3.0):
    """Poll a condition. Returns whether it became true -- never asserts on a
    sleep, which would make the suite timing-dependent."""
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


print("== 1. A HEALTHY WATCHER ==")
c = FakeClient()
s = make_sup(c)
started = s.start()
check("start() launches one watcher per enabled mailbox", started, 1)
check("the client's run() was actually entered", c.ran.wait(3))
check("state becomes connected", wait_for(
    lambda: first(s.states(), "state") == sup_mod.CONNECTED))
check("no mailbox is reported as a problem", s.problem_accounts(), [])
check("start() is idempotent", s.start(), 1)
s.stop(timeout=3)
check("stop() clears the watchers", s.states(), [])
check("...and closed the client", c.closed)
check("stop() is idempotent (a second call must not raise)",
      (s.stop(timeout=1), True)[1])

print("\n== 2. ⚠ A DEAD WATCHER IS VISIBLE -- the whole point of this file ==")
c = FakeClient(raises=imap_idle.ImapAuthError("credential rejected"))
s = make_sup(c)
s.start()
check("the watcher reaches a TERMINAL state, not silence", wait_for(
    lambda: first(s.states(), "state") in sup_mod.TERMINAL_STATES))
st = first(s.states(), default={"state": None, "detail": ""})
check("  ...specifically auth_failed", st["state"], sup_mod.AUTH_FAILED)
check("  ...and it is NOT reported as connected",
      st["state"] == sup_mod.CONNECTED, False)
check("problem_accounts() names it", len(s.problem_accounts()), 1)
check("  ...with the address, so the operator knows WHICH mailbox",
      first(s.problem_accounts(), "address"), "owner@example.com")
check("  ...and a non-empty reason", bool(st["detail"]))
check("the client was closed even on the failure path", wait_for(
    lambda: c.closed))
# THE REGRESSION GUARD. If the supervisor ever went back to letting the thread
# die unrecorded, the watcher list would be empty or still say 'starting' and
# problem_accounts() would be [] -- which is what "healthy" looks like.
check("a dead watcher is NEVER an empty problem list", s.problem_accounts() != [])
s.stop(timeout=2)

print("\n== 3. TERMINAL STATES ARE DISTINGUISHED, not collapsed ==")
for exc, want in ((imap_idle.ImapAuthError("bad pw"), sup_mod.AUTH_FAILED),
                  (imap_idle.ImapConfigError("bad tls"), sup_mod.CONFIG_ERROR),
                  (RuntimeError("bug"), sup_mod.CRASHED)):
    c = FakeClient(raises=exc)
    s = make_sup(c)
    s.start()
    ok = wait_for(lambda: first(s.states(), "state") == want)
    check("%s -> %s" % (type(exc).__name__, want), ok)
    s.stop(timeout=2)
# The distinction matters because the fixes differ: a crash is a bug here, an
# auth failure is a credential to replace. Same message would misdirect.
check("the three terminal states are genuinely distinct values",
      len({sup_mod.AUTH_FAILED, sup_mod.CONFIG_ERROR, sup_mod.CRASHED}), 3)

print("\n== 4. A BROKEN CLIENT FACTORY IS CONFIG_ERROR, NOT A LOST MAILBOX ==")
def _boom(acct, cb):
    raise RuntimeError("no credential stored")
s = sup_mod.MailboxSupervisor(client_factory=_boom,
                              account_loader=lambda: [ACCOUNT])
s.start()
check("the mailbox still has a watcher record", wait_for(
    lambda: len(s.states()) == 1))
check("  ...in config_error, not silently skipped", wait_for(
    lambda: first(s.states(), "state") == sup_mod.CONFIG_ERROR))
check("  ...and it is listed as a problem", len(s.problem_accounts()), 1)
s.stop(timeout=2)

print("\n== 5. THE CALLBACK: parse -> check -> persist ==")
from modules.email_security import writes                       # noqa: E402

check("CONTROL: real DataManager, grant enforcement ON",
      isinstance(modules.get_data_manager(), dm_mod.DataManager)
      and dm_mod.namespace_mode("email_security") == dm_mod.MODE_ENFORCE)

RAW = (b"From: Someone <someone@example.com>\r\n"
       b"To: owner@example.com\r\n"
       b"Subject: hello\r\n"
       b"Message-ID: <abc123@example.com>\r\n"
       b"Date: Mon, 1 Sep 2026 10:00:00 +0000\r\n"
       b"\r\nhello there\r\n")

c = FakeClient(uidvalidity=4242)
s = make_sup(c)
s.start()
c.ran.wait(3)
c.on_message(7, RAW)


def verdict_rows():
    conn = modules.get_data_manager().connect("email_security")
    try:
        cur = conn.execute(
            "SELECT account_id, uidvalidity, uid, verdict, signals_json, "
            "       message_id_hdr FROM email_message_verdicts")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


rows = verdict_rows()
check("a verdict row was written", len(rows), 1)
check("  keyed to the account", first(rows, "account_id"), 1)
check("  UIDVALIDITY came from the CLIENT, not invented",
      first(rows, "uidvalidity"), 4242)
check("  and the uid", first(rows, "uid"), 7)
# ⚠ The most important assertion in this section. fast_check returns signals and
# auth FACTS and deliberately no verdict; writing "clean" would manufacture a
# judgement nothing made and serve it with full confidence.
check("  verdict stays NULL -- no judgement was manufactured",
      first(rows, "verdict"), None)
check("  signals were captured", bool(first(rows, "signals_json")))
check("  the Message-ID header was recorded",
      first(rows, "message_id_hdr"), "<abc123@example.com>")
check("the watcher counted it", first(s.states(), "messages_scanned"), 1)

print("\n== 6. ONE BAD MESSAGE MUST NOT KILL THE MAILBOX ==")
# An exception escaping the callback would propagate through the client's fetch
# loop and stop the watcher for every message behind it -- a denial of service
# delivered by email.
raised = None
try:
    c.on_message(8, None)              # not bytes at all
except Exception as exc:               # noqa: BLE001
    raised = type(exc).__name__
check("a hostile/garbage message does NOT raise into the client", raised, None)
try:
    c.on_message("not-an-int", RAW)    # unusable uid
except Exception as exc:               # noqa: BLE001
    raised = type(exc).__name__
check("neither does an unusable uid", raised, None)
check("the watcher is still alive and connected",
      first(s.states(), "state"), sup_mod.CONNECTED)

# ⚠ AN UNPARSEABLE MESSAGE IS *RECORDED*, NOT DROPPED, and that is deliberate
# rather than an accident of error handling. mime_parse never raises and turns
# every failure into a recorded problem; a message silently absent from the
# verdict table would be indistinguishable from one that never arrived, which is
# the "failed read as a legitimate answer" shape this repo refuses. So the row
# exists and carries the problem.
garbage = [r for r in verdict_rows() if r["uid"] == 8]
check("the unparseable message WAS recorded, not silently dropped",
      len(garbage), 1)
check("  ...with its parse problem preserved in the signals",
      "input_not_bytes" in ((first(garbage, "signals_json") or "")))
check("  ...and still no manufactured verdict", first(garbage, "verdict"), None)
check("the unusable uid wrote NOTHING (it cannot be keyed)",
      [r for r in verdict_rows() if r["uid"] not in (7, 8)], [])

# A missing UIDVALIDITY must REFUSE to write rather than invent a 0, which would
# collapse this message onto another mailbox generation's row.
before = len(verdict_rows())
c.uidvalidity = None
c.on_message(9, RAW)
check("no UIDVALIDITY -> refuses to write rather than inventing a key",
      len(verdict_rows()), before)
s.stop(timeout=2)

print("\n== 7. NO CONTENT IS RETAINED IN WATCHER STATE ==")
c2 = FakeClient()
s2 = make_sup(c2)
s2.start()
c2.ran.wait(3)
c2.on_message(21, RAW)
snapshots = s2.states()
snap = str(snapshots)
check("the snapshot carries no message body", "hello there" not in snap)
check("...and no subject line", "Subject: hello" not in snap)
# Assert the SHAPE, not just the absence of one string: a field added later that
# happened to carry content would slip past a substring check but not this.
check("the snapshot exposes exactly the intended fields, no credential field",
      sorted((first(snapshots) or {}).keys()),
      ["account_id", "address", "alive", "detail", "mailbox",
       "messages_scanned", "provider", "state"])
s2.stop(timeout=2)

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
