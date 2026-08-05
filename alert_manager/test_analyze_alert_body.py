#!/usr/bin/env python3
"""`analyze_alert`'s prompt body — never send an empty alert to a billed model.

Run: python3 alert_manager/test_analyze_alert_body.py

WHAT WENT WRONG (measured live 2026-08-05, rule 1000002)
--------------------------------------------------------
`/api/analyze/<rule_id>` built its prompt as `Alert: {raw_alert}`, where
`raw_alert` came from the `?raw=` query string. The deep-link entry point
(`/?alert=<rule_id>` → `viewAlert(deepLink, "")`) has always passed an EMPTY
string, so the request was literally `GET /api/analyze/1000002?raw=`.

That was invisible for as long as the gate above it was broken and the AI was
never called. The moment the gate was fixed, the first deep-linked analysis
asked the model to analyse nothing. It answered, correctly, "No alert data was
provided for analysis" — and that non-answer was:

  * BILLED,
  * cached under `alert_1000002` for 24h,
  * written back to `alerts.explanation`, where the now-correct gate
    early-returns on it PERMANENTLY, and
  * accompanied by `risk_level` being overwritten CRITICAL → LOW on a rule seen
    108 times.

So the failure was not "a wasted call". It was a wasted call that poisoned the
row it existed to fill, and looked like success at every layer except the
content of the answer.

WHAT THIS SUITE PINS
--------------------
Two properties, and the second is the one that matters:

  1. When `raw` is empty, the body is rebuilt from the stored row — so the
     deep-link path produces a real analysis.
  2. When there is NO body from either source, the AI is NOT called at all.

A suite that only proved (1) would pass an implementation that still called the
model with an empty string whenever the row was missing. So the refusal is
tested with a control proving the same code path DOES proceed when a body
exists — otherwise "it refused" is indistinguishable from "it never runs".
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

EXPECTED_CHECKS = 29

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def load_named(name):
    """Import ONE named helper, by AST-extracting it from dashboard.py.

    Importing dashboard.py wholesale runs its module-level init against the live
    database and loads every module — far too much for a pure-function test, and
    it would make this suite depend on the machine's state. Extracting the one
    function keeps the test hermetic while still testing the REAL source, not a
    reimplementation of it (which would drift and prove nothing).

    Module-level names the extracted function closes over (json, re, and any
    compiled pattern) are supplied explicitly, so a helper that grows a new
    dependency fails loudly here rather than silently testing a stub.
    """
    import ast, json as _json, re as _re
    src = open(os.path.join(REPO, "dashboard.py")).read()
    tree = ast.parse(src)
    ns = {"json": _json, "re": _re}
    # Pull in module-level constants the helpers reference (e.g. _JSON_FENCE_RE).
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id.startswith("_JSON_")
                for t in node.targets):
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         "dashboard.py", "exec"), ns)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         "dashboard.py", "exec"), ns)
            return ns[name]
    raise AssertionError("%s not found in dashboard.py — the fix is ABSENT, "
                         "not merely failing" % name)


def load_body_builder():
    return load_named("_alert_body_from_row")


# Row shape mirrors analyze_alert's documented SELECT * mapping:
#   0 id 1 rule_id 2 rule_name 3 classification 4 priority 5 explanation
#   6 risk_level 7 action 8 times_seen 9 first_seen 10 last_seen
#   11 src_ip 12 dst_ip 13 protocol
def row(rule_name="", classification="", priority="", src="", dst="",
        proto="", seen=""):
    return (1, "1000002", rule_name, classification, priority, "", "CRITICAL",
            "pending", seen, "", "", src, dst, proto)


def main():
    build = load_body_builder()

    # ── the row rebuilds into something an AI can actually analyse ────────────
    print("\na stored row rebuilds into a usable alert body")
    full = row("NEMESIS Host-defence: TCP SYN sweep", "Attempted Recon", 1,
               "203.0.113.9", "198.51.100.22", "TCP", 108)
    body = build(full)
    check("signature is carried", "NEMESIS Host-defence" in body, True)
    check("classification is carried", "Attempted Recon" in body, True)
    check("priority is carried", "Priority: 1" in body, True)
    check("protocol is carried", "Protocol: TCP" in body, True)
    check("source ip is carried", "203.0.113.9" in body, True)
    check("destination ip is carried", "198.51.100.22" in body, True)
    check("times-seen is carried", "Times seen: 108" in body, True)

    # ── the empty cases, which are the whole point ───────────────────────────
    print("\nan empty or unusable row yields an EXPLICIT empty string")
    # CONTROL first: without this, "empty row -> empty body" would also pass an
    # implementation that returned "" for everything, including the row above.
    check("CONTROL a populated row does NOT yield empty", build(full) == "", False)
    check("a wholly empty row yields empty", build(row()), "")
    check("a row of Nones yields empty", build((1, "x") + (None,) * 12), "")
    check("whitespace-only fields yield empty",
          build(row(rule_name="   ", classification="  ")), "")
    # A short row must not raise — analyze_alert already guards len()>11 elsewhere,
    # so short rows are a shape this code genuinely sees.
    check("a short row does not raise", build((1, "x", "SigName")), "Signature: SigName")

    # ── no stub content: an empty row must not become plausible-looking text ──
    print("\nan empty row must not be dressed up as content")
    # This is the trap: returning "Alert 1000002" for an empty row would satisfy
    # a truthiness guard and get SENT to the billed model, reproducing the exact
    # bug from a different direction.
    empty_body = build(row())
    check("empty row produces nothing truthy", bool(empty_body), False)

    # ── the guard exists in the real source, and refuses before spending ──────
    print("\nthe route refuses to call the AI without a body")
    import ast
    src = open(os.path.join(REPO, "dashboard.py")).read()
    tree = ast.parse(src)
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "analyze_alert":
            fn = node
    # The refusal must come BEFORE the ai_analyze call in source order, or it
    # refuses after paying — which is the bug, not the fix.
    guard_line = ai_call_line = None
    for node in ast.walk(fn) if fn else []:
        if isinstance(node, ast.Return) and guard_line is None:
            # the 422 refusal carries the literal status code
            seg = ast.get_source_segment(src, node) or ""
            if "422" in seg:
                guard_line = node.lineno
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id == "ai_analyze":
                ai_call_line = node.lineno
    check("a 422 refusal exists in analyze_alert", guard_line is not None, True)
    check("the refusal precedes the billed AI call",
          bool(guard_line and ai_call_line and guard_line < ai_call_line), True)

    # The two checks above pass even if the PROMPT still interpolates the raw
    # query-string value — which is the actual bug. Pin the interpolation too,
    # or reverting one identifier silently restores the defect with a green suite.
    fn_src = ast.get_source_segment(src, fn) or ""
    check("the prompt interpolates the rebuilt body", "Alert: {alert_body}" in fn_src, True)
    check("CONTROL the prompt no longer interpolates raw directly",
          "Alert: {raw_alert}" in fn_src, False)

    # ── fence-tolerant JSON parse ────────────────────────────────────────────
    # Found live 2026-08-05: the model wrapped its (correct) answer in ```json
    # despite the prompt saying "JSON only, no markdown". json.loads() died on
    # the first backtick, the except branch stored the whole fenced blob as the
    # "plain English explanation", and hardcoded risk_level="UNKNOWN" straight
    # over a stored CRITICAL. The analysis was right; only the storage was wrong.
    print("\na fenced JSON reply is parsed, not treated as unparseable")
    parse = load_named("_parse_ai_json")
    good = '{"explanation": "x", "risk_level": "MEDIUM"}'
    check("CONTROL bare JSON still parses", (parse(good) or {}).get("risk_level"), "MEDIUM")
    check("```json fenced JSON parses",
          (parse("```json\n" + good + "\n```") or {}).get("risk_level"), "MEDIUM")
    check("bare ``` fenced JSON parses",
          (parse("```\n" + good + "\n```") or {}).get("risk_level"), "MEDIUM")
    check("fence with trailing whitespace parses",
          (parse("  ```json\n" + good + "\n```  \n") or {}).get("risk_level"), "MEDIUM")
    # None is the explicit failure sentinel — it must NOT be an empty dict, or the
    # caller cannot tell "unparseable" from "parsed something empty".
    check("genuinely non-JSON returns the None sentinel", parse("hello there"), None)
    check("empty text returns None", parse(""), None)
    # A bare string/list is valid JSON but cannot be an analysis; letting one
    # through would put a plausible wrong shape into the row.
    check("a JSON string (not object) is rejected", parse('"just a string"'), None)
    check("a JSON list (not object) is rejected", parse('[1,2,3]'), None)

    # ── a parse failure must not rewrite severity ────────────────────────────
    print("\na parse failure does not overwrite a stored risk_level")
    fn_src2 = ast.get_source_segment(src, fn) or ""
    check("the fallback no longer hardcodes UNKNOWN",
          '"risk_level": "UNKNOWN"' in fn_src2, False)
    check("the fallback carries the prior stored risk forward",
          "prior_risk" in fn_src2, True)
    check("the UPDATE coalesces rather than clobbering",
          "COALESCE(?, risk_level)" in fn_src2, True)
    # CONTROL: the INSERT path has no prior value, so UNKNOWN is correct there —
    # proving the two paths are deliberately different, not accidentally the same.
    check("CONTROL the INSERT path still defaults to UNKNOWN",
          'or "UNKNOWN"' in fn_src2, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
