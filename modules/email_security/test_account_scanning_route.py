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

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
