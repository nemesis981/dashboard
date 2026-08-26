"""Load-time RBAC registration gate — drives the REAL modules_loader.

A route absent from roles.ROUTE_MINIMUMS resolves to admin-only via the auth
gate's fail-closed path: SAFE, but its access level was never DECIDED, and
nothing forced anyone to decide it. The runtime drift signal (E-RBAC-002) is
meant to say so — and recorded NOTHING AT ALL until the connect("core") bug was
fixed on 2026-08-26. A ledger of zero rows read exactly like "no drift".

So the enforcement is behavioural, not a log line: an unregistered route is not
registered, and therefore 404s. THE SIGNAL IS THE BEHAVIOUR — a warning can go
unread for months, which is precisely how the broken recorder survived.

⚠ THIS SUITE DRIVES modules_loader.init() ON A REAL ON-DISK MODULE. It does NOT
reimplement the registration branch — a test that re-runs a copy of the logic
proves the copy works, not the shipped code. Assertions read the actual Flask
url_map and real HTTP status codes.

NO NETWORK. The probe module is generated into a tempdir and removed after.
"""
import os, sys, json, tempfile, shutil
sys.path.insert(0,"/opt/nemesis"); sys.path.insert(0,"/opt/nemesis/alert_manager")
from flask import Flask
import modules_loader, modules, roles

passed = failed = 0
def check(l,c,d=""):
    global passed,failed
    if c: passed+=1; print("  [PASS] %s"%l)
    else: failed+=1; print("  [FAIL] %s %s"%(l,d))

# A real on-disk module with two routes: one registered, one not.
tmp = tempfile.mkdtemp(prefix="loadertest-")
mdir = os.path.join(tmp, "probemod"); os.makedirs(mdir)
open(os.path.join(mdir,"manifest.json"),"w").write(json.dumps({
    "name":"probemod","display_name":"Probe","version":"0.1","description":"t",
    "category":"test","provides_dashboard_card":False,
    "requires_background_service":False,"config_keys":[],
    "enabled_by_default":True,"confirmation_required":False,
    "apt_deps":[],"pip_deps":[],"required":False}))
open(os.path.join(mdir,"module.py"),"w").write('''
from modules import NemesisModule
def view_good(): return "good"
def view_ungated(): return "ungated"
class Module(NemesisModule):
    def start(self): pass
    def stop(self): pass
    def status(self): return {"state":"running","detail":"t"}
    def get_dashboard_card(self): return None
    def get_routes(self):
        return [("/probe/good", view_good, {"methods":["GET"]}),
                ("/probe/ungated", view_ungated, {"methods":["GET"]})]
''')

db = os.path.join(tmp,"t.db")
app = Flask("realload")
roles.ROUTE_MINIMUMS["module_probemod_view_good"] = ("admin","admin")
assert "module_probemod_view_ungated" not in roles.ROUTE_MINIMUMS

modules_loader.init(app, db, tmp)          # THE REAL LOADER

eps = {r.endpoint for r in app.url_map.iter_rules()}
print("-- REAL _load_module, real Flask app --")
check("CONTROL: the module actually loaded",
      "probemod" in modules_loader.get_loaded_modules(),
      list(modules_loader.get_loaded_modules()))
check("CONTROL: its REGISTERED route is in the url_map",
      "module_probemod_view_good" in eps, sorted(e for e in eps if "probemod" in e))
check("⭐ its UNREGISTERED route was REFUSED",
      "module_probemod_view_ungated" not in eps, sorted(e for e in eps if "probemod" in e))
c = app.test_client()
check("registered route serves 200", c.get("/probe/good").status_code == 200)
check("⭐ unregistered route 404s", c.get("/probe/ungated").status_code == 404)
check("⭐ the module is still LOADED despite the refused route (not killed)",
      modules_loader.get_loaded_modules().get("probemod") is not None)

del roles.ROUTE_MINIMUMS["module_probemod_view_good"]
shutil.rmtree(tmp, ignore_errors=True)
print("\n-- REAL modules that ship routes must LOAD and REGISTER --")
# ⚠ THE GAP THIS CLOSES. email_security's get_routes() used `from . import views`.
# modules_loader loads module.py via spec_from_file_location("nemesis_module_..."),
# so there is NO parent package: the relative import raised ImportError, the
# loader's caller swallowed it, and the module NEVER LOADED — routes absent,
# silently. Every email_security suite passed throughout, because none of them
# ever called get_routes(); they imported views.py directly and bypassed it.
# A module that cannot load is not something unit tests can see.
import os, tempfile, logging
os.environ.setdefault("NEMESIS_DB_PATH", os.path.join(tempfile.mkdtemp(), "gate.db"))
logging.disable(logging.CRITICAL)
for p_ in ("/opt/nemesis/core_module/hw_monitor",):
    if p_ not in sys.path: sys.path.insert(0, p_)
import dashboard as _dash
import modules_loader as _ml

_real_failures = []
for _name in sorted(_ml._manifests or {}):
    try:
        _ml._load_module(_name)
    except Exception as exc:
        _real_failures.append((_name, "%s: %s" % (type(exc).__name__, exc)))
check("every discovered module LOADS through the real loader",
      _real_failures == [], _real_failures)

_live = {r.endpoint for r in _dash.app.url_map.iter_rules()}
for _ep in ("module_email_security_api_quarantine_list",
            "module_email_security_api_release"):
    check("%s is REGISTERED on the live app" % _ep, _ep in _live)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
