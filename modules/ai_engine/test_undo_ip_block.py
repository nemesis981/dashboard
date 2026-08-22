#!/usr/bin/env python3
"""`_undo_ip_block` -- the reversal handler for the two IP action classes.

Run: python3 modules/ai_engine/test_undo_ip_block.py   (exit 0 = all pass)

WHY THIS FILE EXISTS SEPARATELY. The handler lives in `dashboard.py`, which pulls
in Flask, the module loader and a live DB path -- importing it to test one
function would test the import, not the function. So the function's SOURCE is
extracted and executed against stubs. That means these checks run the REAL
production code (not a copy that can drift), while still being able to simulate a
firewall that refuses, a ruleset read-back that disagrees, and a missing
credential.

THE PROPERTY UNDER TEST. Ordering: the firewall call goes FIRST and the database
is touched only if it succeeded. Recording a block as lifted while its ufw rule
is still in place is the one state an operator would most confidently misread
during an incident -- worse than refusing outright.

NO NETWORK, NO FIREWALL. Every external call is a stub.
"""
import re
import sys

sys.path.insert(0, "/opt/nemesis")

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


# ── extract the real function source out of dashboard.py ─────────────────────
SRC = open("/opt/nemesis/dashboard.py").read()
m = re.search(r"\ndef _undo_ip_block\(.*?\n(?=\ntry:|\ndef |\n@)", SRC, re.S)
assert m, "could not locate _undo_ip_block in dashboard.py"
FN_SRC = m.group(0)
check("the handler source was located in dashboard.py", bool(FN_SRC.strip()))
check("CONTROL: it is the real function, not an empty match",
      "ufw_delete" in FN_SRC and "list_blocked" in FN_SRC, len(FN_SRC))


class FirewallError(Exception):
    pass


class _Cur:
    def __init__(self, rowcount):
        self.rowcount = rowcount


class _Conn:
    """Records every statement so we can assert the DB was (or was not) touched."""

    def __init__(self, rowcount=1):
        self.stmts = []
        self._rowcount = rowcount
        self.closed = False

    def execute(self, sql, args=()):
        self.stmts.append((sql, args))
        return _Cur(self._rowcount)

    def commit(self):
        pass

    def close(self):
        self.closed = True


def build(fw_raises=None, still_blocked=False, credential="s3cret",
          rowcount=1, listing_raises=False):
    """Assemble a namespace with the stubs the handler expects."""
    state = {"unblocked": [], "audits": [], "conn": _Conn(rowcount)}

    def ufw_delete(ip, actor, session, cred):
        if fw_raises:
            raise fw_raises
        state["unblocked"].append((ip, actor, cred))

    def list_blocked(actor, session, cred):
        if listing_raises:
            raise RuntimeError("helper unavailable")
        return [{"ip": "192.88.99.7"}] if still_blocked else []

    class _Log:
        def exception(self, *a, **k):
            state.setdefault("logged", []).append(a)

    ns = {
        "ufw_delete": ufw_delete,
        "list_blocked": list_blocked,
        "FirewallError": FirewallError,
        "_actor": lambda: "paul",
        "_fw_session_id": lambda: "sess-1",
        "_fw_credential": lambda: credential,
        "_dm_conn": lambda: state["conn"],
        "_audit": lambda **kw: state["audits"].append(kw),
        "log": _Log(),
    }
    exec(compile(FN_SRC, "<handler>", "exec"), ns)
    return ns["_undo_ip_block"], state


PROP = {"id": 42, "row_id": "192.88.99.7", "action_class": "ip_block_permanent",
        "proposed_action": "block permanently", "surface_key": "alerts"}

print("\n== THE HAPPY PATH ACTUALLY UNBLOCKS ==")
fn, st = build()
ok, detail = fn(PROP, {"credential": "from-session", "actor": "paul"})
check("it reports success", ok, detail)
check("the firewall was actually called", len(st["unblocked"]) == 1, st["unblocked"])
check("with the IP from the proposal", st["unblocked"][0][0] == "192.88.99.7")
check("using the CONTEXT credential, not an ambient one",
      st["unblocked"][0][2] == "from-session", st["unblocked"])
check("the quarantine row was marked lifted",
      any("quarantines" in s and "lifted" in s for s, _ in st["conn"].stmts),
      st["conn"].stmts)
check("an audit row was written", len(st["audits"]) == 1, st["audits"])

print("\n== NO CREDENTIAL: an explicit refusal, not a silent failure ==")
fn, st = build(credential=None)
ok, detail = fn(PROP, {})
check("it refuses", not ok, detail)
check("and says a credential is required", "credential" in detail, detail)
check("it explains the engine cannot lift blocks by design",
      "by design" in detail, detail)
check("CONTROL: the firewall was NEVER called", st["unblocked"] == [], st["unblocked"])
check("CONTROL: and the database was NOT touched", st["conn"].stmts == [],
      st["conn"].stmts)

print("\n== FIREWALL REFUSES: nothing is recorded as lifted ==")
fn, st = build(fw_raises=FirewallError("admin_denied: bad password"))
ok, detail = fn(PROP, {"credential": "wrong"})
check("it reports failure", not ok, detail)
check("and surfaces the firewall's own reason", "admin_denied" in detail, detail)
check("CONTROL: the DB was not updated -- no 'lifted' claim",
      not any("lifted" in s for s, _ in st["conn"].stmts), st["conn"].stmts)

print("\n== READ-BACK DISAGREES: reported success but the rule is still there ==")
# ufw_delete returning without raising is the HELPER's report. This is our own
# confirmation. If the rule survives, saying "undone" would be a lie in the exact
# record an operator consults during an incident.
fn, st = build(still_blocked=True)
ok, detail = fn(PROP, {"credential": "s3cret"})
check("it refuses to call this a reversal", not ok, detail)
check("and says the IP is STILL present in the ruleset", "STILL present" in detail,
      detail)
check("CONTROL: the DB was not marked lifted",
      not any("lifted" in s for s, _ in st["conn"].stmts), st["conn"].stmts)

print("\n== READ-BACK UNAVAILABLE: a partial, not a false failure ==")
# The firewall call DID succeed here. Refusing outright would leave the block
# lifted but the proposal un-undone, which is its own kind of wrong record.
fn, st = build(listing_raises=True)
ok, detail = fn(PROP, {"credential": "s3cret"})
check("it still reports success (the unblock genuinely happened)", ok, detail)
check("the failure to verify was logged, not swallowed silently",
      st.get("logged"), st.get("logged"))

print("\n== A PERMANENT BLOCK HAS NO QUARANTINE ROW -- that is expected ==")
# block_ip_permanent deliberately never creates a `quarantines` row, so zero
# matched rows here is normal. This is the ONE place where "zero rows" must NOT
# be read as failure -- the firewall rule was what mattered and it is gone.
fn, st = build(rowcount=0)
ok, detail = fn(PROP, {"credential": "s3cret"})
check("zero quarantine rows is still a success", ok, detail)
check("and it says so explicitly rather than silently",
      "permanent block" in detail, detail)
check("CONTROL: the firewall was still called", len(st["unblocked"]) == 1)

print("\n== A PROPOSAL WITH NO IP IS REFUSED ==")
fn, st = build()
ok, detail = fn({"id": 1, "row_id": "", "surface_key": "alerts"}, {"credential": "x"})
check("an empty row_id is refused", not ok, detail)
check("CONTROL: the firewall was not called", st["unblocked"] == [])

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
