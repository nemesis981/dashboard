#!/usr/bin/env python3
"""The alert-explanation cache key must be bound to the address mapping.

Run: python3 alert_manager/test_alert_cache_key.py   (exit 0 = all pass)

THE BUG (PUNCHLIST "cache-hit token skew", carried from 2026-08-06; fixed 2026-09-05)
    `cache_key=f"alert_{rule_id}"` keyed on the rule id ALONE. On this path the
    reply is cached TOKENIZED -- ai_engine.analyze() resolves before caching, but
    its pass is a no-op here because the body arrives already pseudonymized, so
    what lands in `ai_cache` still says "host-A". Resolution happens back in the
    dashboard request, against a map rebuilt from TODAY's body.

    So the same rule firing later from a DIFFERENT source address hit the old
    entry, and `host-A` resolved to the NEW address while the cached text
    described the OLD one. An explanation about host A, silently attributed to
    host B, for up to 24 hours. Nothing errors; the reader just gets confident,
    incorrect attribution inside a security explanation.

WHY A FINGERPRINT OF THE MAP, NOT A HASH OF THE BODY
    Hashing the alert body would also fix it, and would destroy the cache: the
    body carries a timestamp, so every alert would be unique and every call would
    be paid. The mapping is the precise thing correctness depends on -- identical
    addresses mean the cached reply resolves identically -- so binding to it keeps
    the hit for a repeat alert between the same hosts and misses only when reuse
    would have been wrong.

EXTRACTED FROM dashboard.py VIA AST, not reimplemented: dashboard.py cannot be
imported as the operator account (it fails closed on /var/lib/nemesis/.flask_secret,
mode 0600 nemesis-dash). Same approach as test_tiered_explanations.py. A copy of
the logic here would drift from the shipped code and prove nothing about it.
"""
import ast
import hashlib
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXPECTED_CHECKS = 12
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 42:
        g, w = g[:39] + "...", w[:39] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def load_fn():
    src = open(os.path.join(REPO, "dashboard.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_alert_cache_key":
            ns = {"hashlib": hashlib}
            exec(compile(ast.Module([node], []), "<x>", "exec"), ns)
            return ns["_alert_cache_key"]
    sys.exit("FATAL: _alert_cache_key not found in dashboard.py -- "
             "this TEST is stale, or the fix was reverted")


key = load_fn()

# Two bodies for the SAME rule, differing only in which hosts were involved.
MAP_A = {"host-A": "203.0.113.10", "host-B": "203.0.113.20"}
MAP_B = {"host-A": "203.0.113.99", "host-B": "203.0.113.20"}   # src changed
MAP_A2 = {"host-B": "203.0.113.20", "host-A": "203.0.113.10"}  # same, reordered


def main():
    print("1. the defect: a changed address must NOT reuse the cached reply")
    check("different mapping -> different key",
          key("1000002", MAP_A) == key("1000002", MAP_B), False)
    check("  ...and the rule id alone is not what distinguishes them",
          key("1000002", MAP_A).startswith("alert_1000002_")
          and key("1000002", MAP_B).startswith("alert_1000002_"), True)

    print("\n2. CONTROL: the cache must still WORK when reuse is correct")
    # Without this the fix could be "never cache anything", which passes check 1
    # and silently makes every alert a paid call.
    check("identical mapping -> identical key",
          key("1000002", MAP_A) == key("1000002", MAP_A), True)
    check("dict ORDER does not change the key (sorted before hashing)",
          key("1000002", MAP_A) == key("1000002", MAP_A2), True)

    print("\n3. the rule id still participates")
    check("different rule, same mapping -> different key",
          key("1000001", MAP_A) == key("1000002", MAP_A), False)
    check("key is prefixed with the readable rule id",
          key("1000002", MAP_A).startswith("alert_1000002_"), True)

    print("\n4. shape and edge cases")
    check("empty mapping yields a stable key, not a crash",
          key("1000002", {}) == key("1000002", {}), True)
    check("  ...and an empty map differs from a populated one",
          key("1000002", {}) == key("1000002", MAP_A), False)
    check("key is a single token with no whitespace",
          " " in key("1000002", MAP_A), False)
    check("fingerprint is fixed-length hex",
          len(key("1000002", MAP_A).rsplit("_", 1)[1]), 16)

    print("\n5. it is the VALUE that matters, not just the token set")
    # The tokens are assigned positionally, so two different incidents produce
    # the SAME token names with different addresses behind them. A fingerprint
    # over tokens alone would collide and reintroduce the bug exactly.
    check("same tokens, different addresses -> different key",
          key("1000002", {"host-A": "203.0.113.1"})
          == key("1000002", {"host-A": "203.0.113.2"}), False)
    check("  ...same tokens, same addresses -> same key",
          key("1000002", {"host-A": "203.0.113.1"})
          == key("1000002", {"host-A": "203.0.113.1"}), True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
