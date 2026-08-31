"""The scanning consent gate -- POST /api/email-security/account/scanning.

WHAT THIS ROUTE IS, AND WHY IT GETS ITS OWN SUITE
    Enrollment deliberately stores a mailbox with `enabled=0`: adding a mailbox
    and beginning to READ A PERSON'S MAIL are two separate consents. This route
    is the second consent. Turning it on starts reading correspondence; turning
    it off is detection-disabling. Both directions are admin-only.

    So the interesting assertions are not "does the bit flip". They are: can the
    bit flip WITHOUT a usable credential (it must not), can a non-boolean turn
    surveillance on by accident (it must not), and does flipping the bit actually
    change what is running (it must -- otherwise the route reports success for
    something that will not happen until the next restart).

REAL FLASK, REAL DataManager, REAL DB -- same harness shape as test_views.py.
A stubbed DM cannot observe the namespace grant, which data_manager.py's own
comment warns produces a suite that passes while production silently denies.

NO NETWORK, NO MAILBOX, NO REAL CREDENTIALS, NO LIVE DB.

ASSERTION COUNT IS FIXED -- no check sits inside a success-path branch.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

_TMP = tempfile.mkdtemp(prefix="emailsec-scanroute-")
_DB = os.path.join(_TMP, "t.db")
_SECRETS = os.path.join(_TMP, "email-secrets.env")
os.environ["NEMESIS_DB_PATH"] = _DB
os.environ["NEMESIS_EMAIL_SECRETS_PATH"] = _SECRETS

import modules                                                  # noqa: E402
import database                                                 # noqa: E402
import data_manager as dm_mod                                   # noqa: E402

database.DB_PATH = _DB
modules.set_shared_db_path(_DB)
database.init_email_security_tables()

from modules.email_security import views                        # noqa: E402
from modules.email_security import writes                       # noqa: E402
from modules.email_security import credential_store as cs       # noqa: E402

cs.SECRETS_PATH = _SECRETS

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s\n         got=%r want=%r" % (label, got, want))


from flask import Flask                                         # noqa: E402
app = Flask(__name__)
for rule, fn, opts in views.routes():
    app.add_url_rule(rule, fn.__name__, fn, **opts)
client = app.test_client()
URL = "/api/email-security/account/scanning"

DM = modules.get_data_manager()
DM.set_actor("user:tester")

# Two enrolled mailboxes: one WITH a stored credential, one without.
writes.add_account("has@example.com", "imap.example.com", "EMAIL_SEC_APPPW_1",
                   provider="gmail", enabled=False, owner_user_id=42)
writes.add_account("nocred@example.com", "imap.example.com", "EMAIL_SEC_APPPW_9",
                   provider="gmail", enabled=False, owner_user_id=43)
with open(_SECRETS, "w") as fh:
    fh.write("EMAIL_SEC_APPPW_1=abcd efgh ijkl mnop\n")


def post(body, as_json=True):
    if as_json:
        return client.post(URL, data=json.dumps(body),
                           content_type="application/json")
    return client.post(URL, data=body)


def enabled_of(addr):
    row = writes.get_account(addr)
    return None if row is None else row["enabled"]


print("== 0. CONTROLS ==")
check("throwaway DB, not the live one",
      "/var/lib/nemesis" not in _DB and os.path.exists(_DB))
check("REAL DataManager", isinstance(DM, dm_mod.DataManager))
check("grant enforcement ON",
      dm_mod.namespace_mode("email_security"), dm_mod.MODE_ENFORCE)
check("both mailboxes start DISABLED (enrollment's default)",
      (enabled_of("has@example.com"), enabled_of("nocred@example.com")), (0, 0))

print("\n== 1. METHOD + CSRF POSTURE (matches api_release exactly) ==")
rules = {r: o["methods"] for r, _f, o in views.routes()}
check("the route is POST-only", rules[URL], ["POST"])
check("GET is refused (405) -- never a GET-as-write",
      client.get(URL).status_code, 405)
# A form POST is the CSRF vector this gate exists for: forms cannot send a JSON
# content-type, so requiring one blocks a cross-origin form submission.
check("a FORM-encoded POST is refused with 415",
      post({"address": "has@example.com", "enabled": "true"},
           as_json=False).status_code, 415)
check("  ...and it did NOT change anything", enabled_of("has@example.com"), 0)

print("\n== 2. INPUT VALIDATION -- a typo must not enable surveillance ==")
# ⚠ THE ASSERTION THAT MATTERS MOST HERE. With a truthiness check instead of a
# strict isinstance, the STRING "false" would ENABLE scanning, because every
# non-empty string is truthy. A caller's typo would start reading someone's mail.
for bad in ("true", "false", 1, 0, None, "yes"):
    r = post({"address": "has@example.com", "enabled": bad})
    check("enabled=%r is REFUSED (strict bool)" % (bad,), r.status_code, 400)
check("  ...and none of those changed the row", enabled_of("has@example.com"), 0)
check("a missing address is refused",
      post({"enabled": True}).status_code, 400)
check("a non-string address is refused",
      post({"address": 5, "enabled": True}).status_code, 400)
check("an over-long address is refused",
      post({"address": "a" * 400, "enabled": True}).status_code, 400)
check("an unknown mailbox is 404, not silently created",
      post({"address": "nobody@example.com", "enabled": True}).status_code, 404)
check("  ...and no row was invented",
      writes.get_account("nobody@example.com"), None)

print("\n== 3. ⚠ REFUSES TO ENABLE WITHOUT A USABLE CREDENTIAL ==")
# Without this the route sets enabled=1 on a mailbox it has just guaranteed
# cannot scan: the supervisor spawns a watcher that parks in CONFIG_ERROR while
# the admin was told "scanning enabled".
r = post({"address": "nocred@example.com", "enabled": True})
check("enabling a mailbox with no stored credential -> 409", r.status_code, 409)
check("  ...and the row is STILL disabled", enabled_of("nocred@example.com"), 0)
check("  ...with a reason naming the real problem",
      "credential" in (r.get_json() or {}).get("error", ""))
# DISABLING must not require a credential -- refusing to switch OFF a mailbox
# whose credential vanished would trap it in a scanning state nobody can exit.
r = post({"address": "nocred@example.com", "enabled": False})
check("DISABLING without a credential is ALLOWED (never trap it on)",
      r.status_code, 200)

print("\n== 4. THE HAPPY PATH ==")
r = post({"address": "has@example.com", "enabled": True})
body = r.get_json() or {}
check("enabling a credentialled mailbox succeeds", r.status_code, 200)
check("  ...the row really is enabled", enabled_of("has@example.com"), 1)
check("  ...and the reply says so", body.get("enabled"), True)
check("  ...reporting rows actually affected", body.get("updated"), 1)
# ⚠ HONESTY, not reassurance. No supervisor is loaded in this harness, so the
# route MUST report that nothing is watching yet rather than implying scanning
# began. A route that returned a bare ok:true here would be claiming coverage it
# had not established -- the exact shape status() exists to refuse.
check("  ⚠ scanning_active is FALSE when no supervisor was reconciled",
      body.get("scanning_active"), False)
check("  ...and it says why", "not reconciled" in (body.get("detail") or ""))

r = post({"address": "has@example.com", "enabled": False})
check("disabling works too", r.status_code, 200)
check("  ...and the row is disabled", enabled_of("has@example.com"), 0)

print("\n== 5. THE SUPERVISOR IS ACTUALLY RECONCILED ==")
# The route reports what the supervisor did. Proven directly against a real
# supervisor rather than through the route, because the route reaches it via
# modules_loader, which this harness has no live module in.
from modules.email_security import supervisor as sup_mod       # noqa: E402
import threading                                               # noqa: E402


class FakeClient:
    def __init__(self):
        self.closed = False

    def run(self, stop):
        stop.wait(5)

    def close(self):
        self.closed = True


_accounts = []
sup = sup_mod.MailboxSupervisor(
    client_factory=lambda a, cb: FakeClient(),
    account_loader=lambda: list(_accounts))
sup.start()
check("no watchers while nothing is enabled", len(sup.states()), 0)

_accounts.append({"id": 1, "address": "has@example.com", "provider": "gmail",
                  "imap_host": "h", "imap_port": 993, "mailbox": "INBOX",
                  "credential_ref": "EMAIL_SEC_APPPW_1"})
res = sup.refresh()
check("refresh STARTS a watcher for a newly enabled mailbox",
      res, {"started": 1, "stopped": 0})
check("  ...and it is now tracked", len(sup.states()), 1)

_accounts.clear()
res = sup.refresh()
check("refresh STOPS the watcher when the mailbox is disabled",
      res, {"started": 0, "stopped": 1})
check("  ...and it is gone from the state list", len(sup.states()), 0)
res = sup.refresh()
check("refresh is idempotent when nothing changed",
      res, {"started": 0, "stopped": 0})
sup.stop(timeout=2)
check("refresh on a STOPPED supervisor does nothing (no resurrection)",
      sup.refresh(), {"started": 0, "stopped": 0})

print("\n== 6. THE ROUTE ACTUALLY REACHES THE LIVE SUPERVISOR ==")
# ⚠ THE ONE SEAM §4 AND §5 BOTH MISS. §4 proves the route is honest when it
# CANNOT find a supervisor; §5 proves refresh() works when called directly.
# Neither exercises the lookup BETWEEN them --
# modules_loader.get_loaded_modules()[MODULE_NAME]._supervisor -- which is a
# private attribute reached by name across a module boundary. A rename of
# `_supervisor` would break scanning-on-toggle while every other assertion here
# still passed, and the only symptom would be scanning_active:false in a reply
# nobody reads closely.
import modules_loader                                          # noqa: E402


class _FakeModule:
    def __init__(self, sup):
        self._supervisor = sup


_live_accounts = []
live_sup = sup_mod.MailboxSupervisor(
    client_factory=lambda a, cb: FakeClient(),
    account_loader=lambda: list(_live_accounts))
live_sup.start()

_real_get_loaded = modules_loader.get_loaded_modules
modules_loader.get_loaded_modules = lambda: {"email_security": _FakeModule(live_sup)}
try:
    _live_accounts.append({"id": 1, "address": "has@example.com",
                           "provider": "gmail", "imap_host": "h",
                           "imap_port": 993, "mailbox": "INBOX",
                           "credential_ref": "EMAIL_SEC_APPPW_1"})
    r = post({"address": "has@example.com", "enabled": True})
    body = r.get_json() or {}
    check("enabling succeeds with a live supervisor", r.status_code, 200)
    check("  ⚠ the route RECONCILED it -- a watcher actually started",
          body.get("watchers"), {"started": 1, "stopped": 0})
    check("  ...so scanning_active is TRUE, and earned",
          body.get("scanning_active"), True)
    check("  ...and the supervisor really is watching it",
          len(live_sup.states()), 1)

    _live_accounts.clear()
    r = post({"address": "has@example.com", "enabled": False})
    body = r.get_json() or {}
    check("disabling stops the watcher through the route",
          body.get("watchers"), {"started": 0, "stopped": 1})
    check("  ...and nothing is being watched", len(live_sup.states()), 0)
finally:
    modules_loader.get_loaded_modules = _real_get_loaded
    live_sup.stop(timeout=2)

print("\n== 7. AUDIT FINDINGS (2026-08-31 review) -- regression guards ==")

# ── F5: the consent decision is attributable on the ROW, not just the op log ──
# The Data Manager op log is metadata-only (module/table/operation/actor/rowcount
# /ts, no parameters), so it cannot say WHICH mailbox or in WHICH direction.
_live_accounts2 = []
sup2 = sup_mod.MailboxSupervisor(client_factory=lambda a, cb: FakeClient(),
                                 account_loader=lambda: list(_live_accounts2))
sup2.start()
_real2 = modules_loader.get_loaded_modules
modules_loader.get_loaded_modules = lambda: {"email_security": _FakeModule(sup2)}
try:
    DM.set_actor("user:auditor")
    post({"address": "has@example.com", "enabled": False})
    row = writes.get_account("has@example.com")
    conn = DM.connect("email_security")
    try:
        who, when = conn.execute(
            "SELECT enabled_actor, enabled_at FROM email_accounts WHERE address=?",
            ("has@example.com",)).fetchone()
    finally:
        conn.close()
    check("F5: the DECIDING ACTOR is recorded on the row", who, "user:auditor")
    check("  ...with a timestamp", bool(when))

    # ── F3: scanning_active must describe THIS mailbox, not fleet-wide counts ──
    # The case needing no race: a watcher parked in a TERMINAL state. refresh()
    # deliberately leaves it alone, so a retry produces {"started": 0} -- and the
    # old code answered scanning_active:true for a mailbox provably not scanning.
    _live_accounts2.append({"id": row["id"], "address": "has@example.com",
                            "provider": "gmail", "imap_host": "h",
                            "imap_port": 993, "mailbox": "INBOX",
                            "credential_ref": "EMAIL_SEC_APPPW_1"})
    r = post({"address": "has@example.com", "enabled": True})
    body = r.get_json() or {}
    check("a healthy watcher reports scanning_active TRUE",
          body.get("scanning_active"), True)
    check("  ...and names the watcher state", body.get("watcher_state"),
          sup_mod.CONNECTED)

    # Force that watcher terminal, then retry the toggle exactly as an admin would.
    for w in sup2._watchers.values():
        w.state = sup_mod.AUTH_FAILED
        w.detail = "credential rejected"
    r = post({"address": "has@example.com", "enabled": True})
    body = r.get_json() or {}
    check("F3: refresh() reports NO change for an already-tracked mailbox",
          body.get("watchers"), {"started": 0, "stopped": 0})
    check("  ⚠ but scanning_active is FALSE -- the mailbox is NOT being scanned",
          body.get("scanning_active"), False)
    check("  ...the terminal state is named", body.get("watcher_state"),
          sup_mod.AUTH_FAILED)
    check("  ...and the reason is surfaced at the moment of the toggle",
          "credential rejected" in (body.get("detail") or ""))
finally:
    modules_loader.get_loaded_modules = _real2
    sup2.stop(timeout=2)
    DM.set_actor("user:tester")

# ── F1: concurrent refresh() must not leak a live, untracked watcher ──
# REPRODUCED against the pre-fix code: 2 threads started, 1 tracked, 1 still
# reading after stop(). The window is between the `have` read and the insert, so
# it is widened here deliberately -- a real window, not an invented one.
import time as _time                                           # noqa: E402

_created = []


class _CountingClient:
    def __init__(self):
        self.stopped = False
        _created.append(self)

    def run(self, stop):
        while not stop.is_set():
            _time.sleep(0.01)
        self.stopped = True

    def close(self):
        pass


_RealWatcher = sup_mod._Watcher


class _SlowWatcher(_RealWatcher):
    def __init__(self, account):
        _time.sleep(0.15)
        super().__init__(account)


_ACC = [{"id": 7, "address": "race@example.com", "provider": "gmail",
         "imap_host": "h", "imap_port": 993, "mailbox": "INBOX",
         "credential_ref": "EMAIL_SEC_APPPW_1"}]
sup_mod._Watcher = _SlowWatcher
try:
    sup3 = sup_mod.MailboxSupervisor(
        client_factory=lambda a, cb: _CountingClient(),
        account_loader=lambda: list(_ACC))
    sup3._started = True
    threads = [threading.Thread(target=sup3.refresh) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _time.sleep(0.3)
    check("F1: two concurrent refreshes start exactly ONE watcher",
          len(_created), 1)
    check("  ...and it is tracked (none leaked)", len(sup3.states()), 1)
    _ACC.clear()
    sup3.stop(timeout=2)
    _time.sleep(0.4)
    check("  ⚠ nothing is still reading after stop()",
          [c for c in _created if not c.stopped], [])
finally:
    sup_mod._Watcher = _RealWatcher

# ── F2: refresh() must not resurrect watchers after stop() ──
# The old guard checked _started, released the lock for a DB read, and never
# re-checked -- so stop() completing during that read left refresh() starting a
# watcher for EVERY enabled mailbox on a module that had just been disabled.
_after_stop = []


def _slow_loader():
    _time.sleep(0.2)          # stop() lands during this window
    return [{"id": 9, "address": "ghost@example.com", "provider": "gmail",
             "imap_host": "h", "imap_port": 993, "mailbox": "INBOX",
             "credential_ref": "EMAIL_SEC_APPPW_1"}]


sup4 = sup_mod.MailboxSupervisor(
    client_factory=lambda a, cb: _after_stop.append(1) or FakeClient(),
    account_loader=_slow_loader)
sup4._started = True
t = threading.Thread(target=sup4.refresh)
t.start()
_time.sleep(0.05)
sup4.stop(timeout=2)          # completes while the loader is still sleeping
t.join()
_time.sleep(0.3)
check("F2: a refresh racing stop() starts NOTHING", _after_stop, [])
check("  ...and no watcher is tracked on a stopped supervisor",
      len(sup4.states()), 0)

# ── F4: a decode error is a STORE fault, not a per-mailbox one ──
_bad = os.path.join(_TMP, "bad-secrets.env")
with open(_bad, "wb") as fh:
    fh.write(b"EMAIL_SEC_APPPW_1=caf\xe9\n")      # latin-1 byte, not UTF-8
raised = None
try:
    cs.load_all(_bad)
except cs.CredentialUnavailable:
    raised = "Unavailable"
except Exception as exc:                                       # noqa: BLE001
    raised = type(exc).__name__
check("F4: a non-UTF-8 store raises Unavailable, not a bare ValueError",
      raised, "Unavailable")
check("  ...and Unavailable is NOT swallowed by has_secret",
      isinstance(cs.CredentialUnavailable("x"), cs.CredentialError))

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
