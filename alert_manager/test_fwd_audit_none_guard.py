#!/usr/bin/env python3
"""The unattended dispatch must not audit a successful no-op -- and must audit everything else.

`vpn-dns-guard` calls `resolvconf_repair` every cycle as a consistency sweep. The
op is correct: it looks, finds nothing to do, and returns `action="none"`. The
DISPATCH was the defect -- it audited unconditionally, so a sweep that changed
nothing wrote an audit row anyway. Measured 2026-09-03: ~17K rows/day, 98% of
`audit_log`. That is not merely wasteful; an audit trail whose contents are 98%
no-ops is one nobody reads, which is the same outcome as not having one.

WHY THE GUARD IS NOT `action == "none"` ALONE -- the load-bearing detail.
Five sites return `action="none"`; FOUR are `ok=True`, and one (`nemesis_fwd.py:2645`)
is `ok=False` -- "could not determine preference or ownership -- failing closed".
That is a FAILURE, not a no-op. Suppressing it would delete the only record that
the guard could not read the system's state, which is precisely the event worth
keeping: the standing rule is that a surface with no logged failures is
indistinguishable from one nobody exercised. So the guard is
`action == "none" AND ok is True`, and the fail-closed case is asserted to still
audit, below.

The premise is checked too (§4): these tests assert a contract about the values
`op_resolvconf_repair` returns, so they call the REAL op and confirm it actually
produces those values. A guard tested only against hand-written dicts proves the
dispatch honours a contract, not that anything produces it.

Run: python3 alert_manager/test_fwd_audit_none_guard.py
"""
import os
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))

import nemesis_fwd as F                                             # noqa: E402

EXPECTED_CHECKS = 34

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


# ── harness ──────────────────────────────────────────────────────────────────
# Drives the real Helper.handle on the unattended path. Only two things are
# faked: the op (so each return shape can be forced) and audit() (so rows can be
# counted). Peer identity, policy lookup and the dispatch/audit sequence are the
# production code under test.

GUARD_UID = 4242


class _Cache:
    """Never consulted on the unattended path; present so handle() can run."""
    def check_and_refresh(self, *a, **k):
        raise AssertionError("credential cache must not be consulted unattended")

    def drop(self, *a, **k):
        raise AssertionError("not exercised")

    def remember(self, *a, **k):
        raise AssertionError("not exercised")


def dispatch(op, result, peer="vpn-dns-guard", uid=GUARD_UID):
    """Run one op through handle(); return (rows_audited, returned_result)."""
    rows = []
    real_audit, real_ops = F.audit, dict(F.OPS)
    F.audit = lambda action, actor, ip=None, detail=None: rows.append(
        {"action": action, "actor": actor, "ip": ip, "detail": detail})
    F.OPS[op] = lambda params: result
    try:
        helper = F.Helper({uid: peer}, _Cache())
        out = helper.handle({"op": op, "params": {}, "request_id": "test-req"},
                            (9999, uid, 9999))
        return rows, out
    finally:
        F.audit = real_audit
        F.OPS.clear()
        F.OPS.update(real_ops)


# ── 1. the four genuine no-ops are NOT audited ───────────────────────────────
print("\n1. successful no-ops are not audited")

NOOPS = [
    ("could not determine -> n/a (that one is ok=False, tested in §2)", None),
    ("owner is someone else's",
     {"ok": True, "action": "none", "reason": "not ours to touch"}),
    ("consistent: Tailscale owns DNS",
     {"ok": True, "action": "none", "reason": "consistent"}),
    ("consistent: resolved owns DNS",
     {"ok": True, "action": "none", "reason": "consistent"}),
    ("accept-dns on, resolved still owns (self-heals)",
     {"ok": True, "action": "none", "reason": "re-asserts in ~2s"}),
]
for label, res in NOOPS:
    if res is None:
        continue
    rows, _ = dispatch("resolvconf_repair", res)
    check("no audit row: %s" % label, rows == [], repr(rows))


# ── 2. failure and action-taken outcomes ARE audited ─────────────────────────
print("\n2. every non-no-op outcome still audits")

AUDITED = [
    ("FAIL-CLOSED (ok=False, action=none) -- the one that must NOT be suppressed",
     {"ok": False, "action": "none", "reason": "could not determine -- failing closed"}),
    ("refused (rate cap)", {"ok": False, "action": "refused", "reason": "rate cap"}),
    ("refused (precondition)", {"ok": False, "action": "refused", "reason": "why"}),
    ("failed", {"ok": False, "action": "failed", "reason": "link failed"}),
    ("repaired, DNS still broken",
     {"ok": False, "action": "repaired", "resolution_recovered": False}),
    ("repaired, DNS recovered",
     {"ok": True, "action": "repaired", "resolution_recovered": True}),
]
for label, res in AUDITED:
    rows, _ = dispatch("resolvconf_repair", res)
    check("audited: %s" % label, len(rows) == 1, repr(rows))
    check("  ...attributed to the guard, not a human",
          len(rows) == 1 and rows[0]["actor"] == "vpn-dns-guard",
          repr(rows))


# ── 3. no collateral suppression of other ops ────────────────────────────────
print("\n3. other ops on the same dispatch path are unaffected")

# The sibling op granted to this same peer.
rows, _ = dispatch("magicdns_switch", {"ok": True, "changed": True})
check("magicdns_switch still audits", len(rows) == 1, repr(rows))

# An op that returns no dict at all -- the guard must not crash or suppress.
rows, _ = dispatch("magicdns_switch", None)
check("a non-dict result still audits (guard must not assume a dict)",
      len(rows) == 1, repr(rows))
rows, _ = dispatch("magicdns_switch", True)
check("a bare True result still audits", len(rows) == 1, repr(rows))

# A DIFFERENT unattended peer entirely.
rows, _ = dispatch("block_ip", {"ok": True}, peer="alert-watcher", uid=4243)
check("alert-watcher's block_ip still audits", len(rows) == 1, repr(rows))
check("  ...attributed to alert-watcher",
      len(rows) == 1 and rows[0]["actor"] == "alert-watcher", repr(rows))

# The adversarial case: another op that COINCIDENTALLY returns action="none".
# Suppression is deliberately keyed on the result shape, not the op name, so
# this SHOULD suppress -- asserted so the behaviour is a decision on record
# rather than a surprise the first time another op adopts the convention.
rows, _ = dispatch("magicdns_switch", {"ok": True, "action": "none"})
check("shape-keyed, not op-keyed: any ok+none suppresses (documented choice)",
      rows == [], repr(rows))


# ── 4. premise: the real op actually produces these shapes ───────────────────
print("\n4. premise check -- the real op returns the values the guard keys on")

src = open(os.path.join(ROOT, "alert_manager", "nemesis_fwd.py")).read()

# ⚠ Count RETURN STATEMENTS, not occurrences of the string. A plain
# src.count('action="none"') also matches the prose in audit_suppressed()'s own
# docstring explaining the convention -- it reported 9 for 5 real sites, and the
# EXPECTED_CHECKS mismatch is what surfaced it. A grep for a term matches the
# note ABOUT the term; count the code.
returns = [ln.strip() for ln in src.splitlines()
           if ln.strip().startswith("return dict(base,")]
none_returns = [ln for ln in returns if 'action="none"' in ln]
check("5 return sites carry action=\"none\"", len(none_returns) == 5,
      "%d: %r" % (len(none_returns), none_returns))
check("  ...4 of them ok=True",
      sum('ok=True' in ln for ln in none_returns) == 4,
      str(sum('ok=True' in ln for ln in none_returns)))
check("  ...1 of them ok=False (the fail-closed case)",
      sum('ok=False' in ln for ln in none_returns) == 1,
      str(sum('ok=False' in ln for ln in none_returns)))
check("non-none actions exist and are untouched by the guard",
      all(a in src for a in ('action="refused"', 'action="failed"',
                             'action="repaired"')))

# Drive the real op with a stubbed environment: no tailscale CLI -> the early
# return. Proves the real function is reachable and returns a dict, so the
# contract above is about a live code path.
real_bin = F._tailscale_bin
try:
    F._tailscale_bin = lambda: None
    out = F.op_resolvconf_repair({})
    check("real op returns a dict", isinstance(out, dict), repr(out))
    check("  ...and the CLI-missing case is NOT an ok+none no-op",
          not (out.get("action") == "none" and out.get("ok") is True), repr(out))
finally:
    F._tailscale_bin = real_bin


# ── 5. the guard predicate itself ────────────────────────────────────────────
print("\n5. the predicate, directly")

check("ok+none suppresses", F.audit_suppressed({"ok": True, "action": "none"}) is True)
check("fail+none does NOT suppress",
      F.audit_suppressed({"ok": False, "action": "none"}) is False)
check("ok+repaired does NOT suppress",
      F.audit_suppressed({"ok": True, "action": "repaired"}) is False)
check("missing action does NOT suppress", F.audit_suppressed({"ok": True}) is False)
check("non-dict does NOT suppress", F.audit_suppressed(None) is False)
check("truthy-but-not-True ok does NOT suppress (is True, not truthiness)",
      F.audit_suppressed({"ok": 1, "action": "none"}) is False)


print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d -- a check was added, "
          "removed, or skipped by a short-circuit" % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
