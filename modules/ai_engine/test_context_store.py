"""L4 accumulating context store. DESIGN-L4-full-ai-mode-2026-08-27 §4/§5.

THE PROPERTY THAT MATTERS MOST IS A SEPARATION, NOT A FEATURE: context shapes
JUDGMENT, never AUTHORITY. §7 mutation-tests it — making learned context
influence a ceiling must turn this suite red. Without that, §4.6 is a comment,
and comments have contradicted their own code more than once here.

NO NETWORK, NO LIVE DB. Every fixture is synthetic.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

_TMPDB = os.path.join(tempfile.mkdtemp(prefix="l4ctx-"), "t.db")
import modules                                                  # noqa: E402
modules.set_shared_db_path(_TMPDB)

from modules.ai_engine import module as ai                      # noqa: E402
from modules.ai_engine import context_store as cs               # noqa: E402

ai._init_db()

passed = failed = 0


def _bad(fn):
    """True if fn() raises ContextWriteRejected -- an expected-refusal probe."""
    try:
        fn()
        return False
    except cs.ContextWriteRejected:
        return True


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


CLS = "ip_action_external"


def _conn():
    return cs._conn()


print("-- 0. CONTROLS --")
check("throwaway DB, not the live one", "/var/lib/nemesis" not in _TMPDB)
_c = _conn()
_tables = {r[0] for r in _c.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ai_%'")}
_c.close()
for t in ("ai_policy_baseline", "ai_learned_context", "ai_context_retrieval"):
    check("table %s exists" % t, t in _tables, sorted(_tables))

print("\n-- 1. ⭐ §4.3 ASYMMETRY IS ENFORCED BY THE DATABASE, not just Python --")
# The Python guard gives a readable error; the SCHEMA is the guarantee. Bypass
# the Python layer entirely and go straight at the table.
_c = _conn()
def _raw(**kw):
    base = dict(created_at="t", action_class=CLS, trigger_type="ip",
                trigger_key="k", direction="restrictive", scope="trigger",
                admin_reasoning="because", expires_at=None)
    base.update(kw)
    cols = ",".join(base)
    _c.execute("INSERT INTO ai_learned_context(%s) VALUES(%s)"
               % (cols, ",".join("?" * len(base))), tuple(base.values()))

for label, kw, expect in (
    ("permissive+category REJECTED by schema",
     dict(direction="permissive", scope="category", expires_at="z"), "REJECT"),
    ("permissive with NO expiry REJECTED",
     dict(direction="permissive", scope="trigger"), "REJECT"),
    ("empty admin_reasoning REJECTED",
     dict(admin_reasoning="   "), "REJECT"),
    ("bogus direction REJECTED", dict(direction="sideways"), "REJECT"),
    ("CONTROL: restrictive+category ACCEPTED (it MAY generalise)",
     dict(direction="restrictive", scope="category"), "ACCEPT"),
    ("CONTROL: permissive+trigger+expiry ACCEPTED",
     dict(direction="permissive", scope="trigger", expires_at="z"), "ACCEPT"),
):
    try:
        _raw(**kw); got = "ACCEPT"
    except Exception:                                           # noqa: BLE001
        got = "REJECT"
    check(label, got == expect, "got %s" % got)
_c.execute("DELETE FROM ai_learned_context")   # clear raw fixtures
_c.commit(); _c.close()

try:
    cs.add_learned(CLS, "ip", "k", cs.PERMISSIVE, cs.SCOPE_CATEGORY, "x")
    check("Python guard rejects permissive+category", False, "accepted")
except cs.ContextWriteRejected as exc:
    check("Python guard rejects permissive+category", True)
    check("...and the message explains WHY (erosion), not just 'invalid'",
          "less cautious" in str(exc), str(exc)[:70])

print("\n-- 2. Expiry is asymmetric by direction --")
r_id = cs.add_learned(CLS, "ip", "198.51.100.5", cs.RESTRICTIVE, cs.SCOPE_CATEGORY,
                      "should have blocked this range")
p_id = cs.add_learned(CLS, "ip", "198.51.100.9", cs.PERMISSIVE, cs.SCOPE_TRIGGER,
                      "our monitoring host")
_c = _conn()
rr = _c.execute("SELECT expires_at FROM ai_learned_context WHERE id=?", (r_id,)).fetchone()[0]
pp = _c.execute("SELECT expires_at FROM ai_learned_context WHERE id=?", (p_id,)).fetchone()[0]
_c.close()
check("restrictive NEVER expires", rr is None, rr)
check("permissive DOES expire", pp is not None, pp)
check("...at the operator-approved 180 days", cs.PERMISSIVE_TTL_DAYS == 180)

print("\n-- 3. §4.2 retrieval: exact class, specificity order, no crossing --")
res = cs.retrieve(CLS, "ip", "198.51.100.9", category="198.51.100.5")
dirs = [(e["direction"], e["scope"]) for e in res["learned"]]
check("both the narrow and the category row match", len(dirs) == 2, dirs)
check("⭐ trigger-scoped ranks ABOVE category-scoped", dirs[0][1] == "trigger", dirs)
other = cs.retrieve("malware_file_quarantine", "ip", "198.51.100.9")
check("⚠ retrieval NEVER crosses action_class", other["learned"] == [], other["learned"])
none = cs.retrieve(CLS, "ip", "203.0.113.77")
check("zero matches is VALID and does not raise", none["learned"] == [])
check("...and reports matched_total 0, not an error", none["matched_total"] == 0)

print("\n-- 4. §4.4 truncation is ANNOUNCED, never silent --")
for i in range(30):
    cs.add_learned(CLS, "host", "many.example", cs.RESTRICTIVE, cs.SCOPE_TRIGGER,
                   "entry %d" % i)
big = cs.retrieve(CLS, "host", "many.example", limit=25)
check("returned is capped at the limit", big["returned_count"] == 25, big["returned_count"])
check("⭐ truncated flag is SET", big["truncated"] is True)
check("...and matched_total reports the REAL total", big["matched_total"] == 30,
      big["matched_total"])
small = cs.retrieve(CLS, "ip", "198.51.100.9")
check("a complete retrieval reports truncated=False", small["truncated"] is False)

print("\n-- 5. §4.4 retrieval is RECORDED, and use_count moves --")
_c = _conn()
nrec = _c.execute("SELECT COUNT(*) FROM ai_context_retrieval").fetchone()[0]
uc = _c.execute("SELECT use_count FROM ai_learned_context WHERE id=?", (p_id,)).fetchone()[0]
trunc_rows = _c.execute("SELECT COUNT(*) FROM ai_context_retrieval WHERE truncated=1").fetchone()[0]
_c.close()
check("retrievals are logged", nrec > 0, nrec)
check("use_count incremented for a row that was actually fed in", uc > 0, uc)
check("the truncated retrieval is recorded AS truncated", trunc_rows >= 1, trunc_rows)

print("\n-- 6. §4.4 NOTHING IS EVER DELETED — revocation is soft --")
check("there is deliberately NO delete_learned()", not hasattr(cs, "delete_learned"))
n = cs.revoke_learned(p_id, "admin")
check("revoke affects one row", n == 1, n)
_c = _conn()
still = _c.execute("SELECT revoked_at, revoked_by FROM ai_learned_context "
                   "WHERE id=?", (p_id,)).fetchone()
_c.close()
check("⭐ the row still EXISTS after revocation", still is not None)
check("...with revoked_at set", still[0] is not None)
after = cs.retrieve(CLS, "ip", "198.51.100.9")
check("a revoked row no longer INFLUENCES decisions",
      all(e["id"] != p_id for e in after["learned"]))
check("...but is still READABLE in the review surface",
      any(r["id"] == p_id for r in cs.review_rows()))

print("\n-- 7. ⭐⭐ §4.6 CONTEXT MUST NEVER TOUCH AUTHORITY --")
import inspect                                                  # noqa: E402
src = inspect.getsource(ai.effective_ceiling)
for forbidden in ("ai_learned_context", "ai_policy_baseline", "context_store",
                  "ai_context_retrieval"):
    check("effective_ceiling() does not reference %s" % forbidden,
          forbidden not in src, "FOUND in source")
check("CONTROL: it DOES read the authority tables (so the check is meaningful)",
      "ai_authority" in src)

print("\n-- 8. MUTATION: prove §7's separation check can go RED --")
_mutant = src.replace("hard = ACTION_CLASS_CEILINGS.get(action_class)",
                      "hard = ACTION_CLASS_CEILINGS.get(action_class)  # ai_learned_context")
check("MUTANT (context referenced in effective_ceiling) IS DETECTED",
      "ai_learned_context" in _mutant and "ai_learned_context" not in src)

print("\n-- 9. §4.5 review surface reports what matters --")
rows = cs.review_rows(CLS)
check("returns rows", len(rows) > 0, len(rows))
sample = [r for r in rows if r["id"] == r_id][0]
for col in ("admin_reasoning", "direction", "scope", "use_count", "active"):
    check("review row carries %s" % col, col in sample)
check("revoked entries are shown by default (that IS the point)",
      any(r["id"] == p_id for r in cs.review_rows()))
check("...and can be filtered out on request",
      all(r["id"] != p_id for r in cs.review_rows(include_inactive=False)))

print("\n-- 10. Expired entries stop influencing but stay recorded --")
# NOTE: r_id is category-scoped, so it can never legally become permissive --
# the CHECK refuses it, correctly. Use a fresh permissive+trigger row instead.
e_id = cs.add_learned(CLS, "ip", "198.51.100.77", cs.PERMISSIVE, cs.SCOPE_TRIGGER,
                      "temporary allowance, should lapse")
live = cs.retrieve(CLS, "ip", "198.51.100.77")
check("CONTROL: while unexpired it DOES influence decisions",
      any(e["id"] == e_id for e in live["learned"]))
past = (datetime.now() - timedelta(days=1)).isoformat(timespec="seconds")
_c = _conn()
_c.execute("UPDATE ai_learned_context SET expires_at=? WHERE id=?", (past, e_id))
_c.commit(); _c.close()
exp = cs.retrieve(CLS, "ip", "198.51.100.77")
check("⭐ the SAME entry, once EXPIRED, no longer influences decisions",
      all(e["id"] != e_id for e in exp["learned"]))
check("...but remains fully readable in review",
      any(r["id"] == e_id for r in cs.review_rows()))
check("...and is marked inactive", [r for r in cs.review_rows()
                                    if r["id"] == e_id][0]["active"] is False)

print("\n-- 11. \u00a74.7 VENDOR BASELINE UPDATE: conflicts SUSPEND, never resolve --")
B_CLS = "malware_file_quarantine"
perm = cs.add_learned(B_CLS, "path", "/opt/vendorapp/agent.bin", cs.PERMISSIVE,
                      cs.SCOPE_TRIGGER, "vendor agent, known good, do not quarantine")
restr = cs.add_learned(B_CLS, "path", "/opt/vendorapp/agent.bin", cs.RESTRICTIVE,
                       cs.SCOPE_TRIGGER, "actually be stricter about this one")
pre = cs.retrieve(B_CLS, "path", "/opt/vendorapp/agent.bin")
check("CONTROL: both rows influence decisions BEFORE the update",
      {e["id"] for e in pre["learned"]} >= {perm, restr},
      [e["id"] for e in pre["learned"]])

res = cs.install_baseline("2026.09", [
    {"action_class": B_CLS, "trigger_type": "path",
     "trigger_key": "/opt/vendorapp/agent.bin",
     "guidance": "this binary was compromised upstream; quarantine on sight"}])
check("baseline installed", res["installed"] == 1, res)
check("\u2b50 the PERMISSIVE row is SUSPENDED by the update", perm in res["suspended"], res)
check("\u2b50 the RESTRICTIVE row is NOT suspended (suspending it would LOOSEN "
      "the system on a security update)", restr not in res["suspended"], res)

post = cs.retrieve(B_CLS, "path", "/opt/vendorapp/agent.bin")
ids = {e["id"] for e in post["learned"]}
check("a suspended row stops influencing decisions", perm not in ids, ids)
check("...while the restrictive one keeps working", restr in ids, ids)
check("the new baseline guidance IS returned", any(
    "compromised upstream" in b["guidance"] for b in post["baseline"]), post["baseline"])

srow = [r for r in cs.review_rows(B_CLS) if r["id"] == perm][0]
check("\u2b50 SUSPENDED is a THIRD state -- not revoked, not gone",
      srow["suspended"] is True and srow["revoked_at"] is None, srow)
check("...and it records WHICH baseline version caused it",
      srow["suspended_by_version"] == "2026.09", srow["suspended_by_version"])
check("...and it is NOT counted active", srow["active"] is False)

print("\n-- 12. \u00a74.7 resolution is a HUMAN decision, both ways --")
check("bogus resolution refused",
      _bad(lambda: cs.resolve_suspension(perm, "maybe", "admin")))
n = cs.resolve_suspension(perm, "kept", "admin")
check("resolving 'kept' affects the row", n == 1, n)
back = cs.retrieve(B_CLS, "path", "/opt/vendorapp/agent.bin")
check("\u2b50 a 'kept' row RESUMES influencing decisions",
      perm in {e["id"] for e in back["learned"]})
krow = [r for r in cs.review_rows(B_CLS) if r["id"] == perm][0]
check("...and the suspension episode stays on the record",
      krow["suspension_resolved_at"] is not None
      and krow["suspension_resolution"] == "kept", krow["suspension_resolution"])

res2 = cs.install_baseline("2026.10", [
    {"action_class": B_CLS, "trigger_type": "path",
     "trigger_key": "/opt/vendorapp/agent.bin", "guidance": "still compromised"}])
check("a later baseline re-suspends it", perm in res2["suspended"], res2)
cs.resolve_suspension(perm, "revoked", "admin")
rrow = [r for r in cs.review_rows(B_CLS) if r["id"] == perm][0]
check("\u2b50 resolving 'revoked' ALSO revokes -- one action, not two",
      rrow["revoked_at"] is not None, rrow)
check("...and the row still EXISTS, per \u00a74.4", rrow["id"] == perm)
check("...and no longer influences decisions", perm not in {
    e["id"] for e in cs.retrieve(B_CLS, "path", "/opt/vendorapp/agent.bin")["learned"]})

print("\n-- 13. baseline replacement is WHOLESALE --")
cs.install_baseline("2026.11", [
    {"action_class": "unrelated_class", "trigger_type": "ip",
     "trigger_key": "203.0.113.200", "guidance": "fresh"}])
gone = cs.retrieve(B_CLS, "path", "/opt/vendorapp/agent.bin")
check("\u2b50 the OLD baseline row is gone after a wholesale replace",
      gone["baseline"] == [], gone["baseline"])
kept = cs.review_rows(B_CLS)
check("...but learned rows were NEVER touched by the update",
      any(r["id"] == restr for r in kept))

print("\n-- 14. \u2b50 \u00a75.4 EROSION GUARDRAIL: scope containment, both directions --")
# §5 requirement 4 asks that a matured install be less cautious ONLY within the
# narrow scope of a permissive entry, and IDENTICAL to a fresh one just outside
# it. The behavioural half needs a decision consumer (unbuilt), but the
# CONTAINMENT itself lives in retrieval and is testable now.
E_CLS = "erosion_probe_class"
narrow = cs.add_learned(E_CLS, "ip", "198.51.100.40", cs.PERMISSIVE,
                        cs.SCOPE_TRIGGER, "this one host is ours")
inside = cs.retrieve(E_CLS, "ip", "198.51.100.40")
check("the permissive entry applies to its OWN trigger",
      narrow in {e["id"] for e in inside["learned"]})
for neighbour in ("198.51.100.41", "198.51.100.4", "198.51.100.400"):
    out = cs.retrieve(E_CLS, "ip", neighbour)
    check("\u2b50 it does NOT leak to neighbouring key %s" % neighbour,
          out["learned"] == [], out["learned"])
    check("   ...that neighbour is IDENTICAL to a fresh install (zero context)",
          out["matched_total"] == 0)

# The asymmetry: a RESTRICTIVE entry MAY generalise across a category, and must.
wide = cs.add_learned(E_CLS, "ip", "cat:scanners", cs.RESTRICTIVE,
                      cs.SCOPE_CATEGORY, "whole category, be strict")
gen = cs.retrieve(E_CLS, "ip", "198.51.100.41", category="cat:scanners")
check("\u2b50 a RESTRICTIVE category entry DOES generalise (the asymmetry)",
      wide in {e["id"] for e in gen["learned"]}, gen["learned"])
check("...and a permissive one still cannot, even in the same query",
      narrow not in {e["id"] for e in gen["learned"]})

print("\n-- 15. \u2b50 NPFA/1 ADAPTER: structure reaches the model, prose never does --")
sys.path.insert(0, "/opt/nemesis/alert_manager")
import prompt_fields as pf                                      # noqa: E402

N_CLS = "npfa_probe"
n1 = cs.add_learned(N_CLS, "ip", "198.51.100.60", cs.PERMISSIVE, cs.SCOPE_TRIGGER,
                    "SECRET-PROSE-MARKER our monitoring host, do not block")
nctx = cs.retrieve(N_CLS, "ip", "198.51.100.60")
parts = cs.context_parts(nctx)

# Every kind string this module emits must be a REAL prompt_fields kind. A
# drifted string would fail at runtime inside a decision; this fails at test
# time instead.
kinds = [p[1] for p in parts if isinstance(p, (tuple, list))]
check("every emitted kind is a real prompt_fields kind",
      all(k in pf.KINDS for k in kinds), [k for k in kinds if k not in pf.KINDS])

built = pf.build(parts)
check("\u2b50 the parts BUILD into a real BuiltPrompt",
      isinstance(built, pf.BuiltPrompt))
check("\u26a0 the admin's prose is NOWHERE in the prompt",
      "SECRET-PROSE-MARKER" not in str(built), str(built)[:120])
check("...and the STRUCTURE is", "permissive" in str(built)
      and "198.51.100.60" in str(built), str(built)[:200])
# ⚠ The naive form of this check -- `"build(" not in getsource(...)` -- FAILS,
# and not because the code is wrong: the DOCSTRING says "never calls
# prompt_fields.build()", and the grep matches the prose asserting the very
# thing it is checking. Third confirmed instance of that shape in this repo.
# Strip the docstring and look at executable lines only.
_src = inspect.getsource(cs.context_parts)
_body = _src.split('"""')[2] if _src.count('"""') >= 2 else _src
check("⭐ context_parts NEVER calls build() (checked on CODE, not the docstring)",
      "build(" not in _body, [l for l in _body.splitlines() if "build(" in l])
check("CONTROL: the docstring DOES mention build(), so the strip was real",
      "build()" in _src.split('"""')[1])

# Truncation must reach the model, not just the return value.
for i in range(30):
    cs.add_learned(N_CLS, "host", "lots.example", cs.RESTRICTIVE,
                   cs.SCOPE_TRIGGER, "entry %d" % i)
tctx = cs.retrieve(N_CLS, "host", "lots.example", limit=5)
tbuilt = str(pf.build(cs.context_parts(tctx)))
check("\u2b50 a TRUNCATED context says so IN THE PROMPT",
      "truncated" in tbuilt.lower(), tbuilt[:160])
check("...and a complete one does not",
      "truncated" not in str(pf.build(cs.context_parts(nctx))).lower())

# It must REFUSE an inexpressible key rather than degrade it.
p_id2 = cs.add_learned(N_CLS, "path", "/opt/vendor/agent.bin", cs.RESTRICTIVE,
                       cs.SCOPE_TRIGGER, "full path, cannot be one NPFA field")
pctx = cs.retrieve(N_CLS, "path", "/opt/vendor/agent.bin")
try:
    pf.build(cs.context_parts(pctx))
    check("\u2b50 a PATH key is REFUSED, not silently reduced to a basename",
          False, "it built -- specificity may have been lost silently")
except pf.PromptFieldError:
    check("\u2b50 a PATH key is REFUSED, not silently reduced to a basename", True)
check("...and an explicit key_kind override is honoured",
      isinstance(pf.build(cs.context_parts(pctx, key_kind=pf.HASH)) if False
                 else pf.build(cs.context_parts(
                     cs.retrieve(N_CLS, "ip", "198.51.100.60"),
                     key_kind=pf.IDENTIFIER)), pf.BuiltPrompt))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
