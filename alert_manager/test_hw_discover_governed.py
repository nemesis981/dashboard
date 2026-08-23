#!/usr/bin/env python3
"""hw_discover: the AI call is GOVERNED, and --auto never prompts.

Covers the two defects fixed 2026-08-23:
  1. a second, ungoverned AI path straight to the vendor API (no rate limit, no
     spend accounting, no cap, no breaker, no pseudonymization, no cache);
  2. `--auto` accepted by the caller and silently ignored here, so a
     non-interactive invocation reached input() and hung until a timeout kill.

Every assertion that matters carries a MUTATION CONTROL -- a deliberately wrong
input proving the check can actually fail. A test that only ever sees the good
case is the instrument this codebase keeps finding broken.
"""
import io
import json
import os
import sys
import contextlib

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import hw_discover as hd

_pass = _fail = 0


def check(label, got, want=True):
    global _pass, _fail
    if got == want:
        _pass += 1
        print(f"  [PASS] {label}")
    else:
        _fail += 1
        print(f"  [FAIL] {label}   (got={got!r} want={want!r})")


def _quiet(fn, *a, **k):
    """Run fn with stdout/stderr swallowed; return (result, exit_code_or_None)."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            return fn(*a, **k), None
    except SystemExit as e:
        return None, e.code


# ═══════════════════════════════════════════════════════════════════════════
print("\n== 1. the ungoverned transport is GONE from the source ==")

_src = open(os.path.join(_HERE, "hw_discover.py"), encoding="utf-8").read()
for banned in ("urllib", "x-api-key", "api.anthropic.com", "ANTHROPIC_API_KEY"):
    check(f"no {banned!r} anywhere in the file", banned not in _src)

# MUTATION CONTROL: the check above must be capable of failing.
check("CONTROL: the same test on a string that DOES contain it fails",
      "urllib" not in "import urllib.request", False)

check("the only outbound call is via an injected analyze()",
      _src.count("def _governed_ask(") == 1)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== 2. --auto is actually parsed (it used to be silently ignored) ==")

check("--auto parses to True", hd._parse_args(["--auto"]).auto, True)
check("absent --auto parses to False", hd._parse_args([]).auto, False)
# MUTATION CONTROL: an unknown flag must be rejected, proving argv is really read
_, code = _quiet(hd._parse_args, ["--not-a-real-flag"])
check("CONTROL: an unknown flag exits non-zero (argv genuinely parsed)", code == 2)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== 3. under --auto nothing calls input() ==")

def _explode(*a, **k):
    raise AssertionError("input() was called under --auto")

_real_input = getattr(hd, "input", None)
hd.input = _explode          # module-level shadow; ask() resolves it at call time
_saved_auto = hd.AUTO
hd.AUTO = True
try:
    pick = ("nct6798", "temp1_input", "Package id 0")
    idx = {1: pick}

    got, _ = _quiet(hd.ask, "CPU", idx, True, "skip", pick)
    check("required + auto_pick -> returns the pick, no prompt", got, pick)

    got, _ = _quiet(hd.ask, "NVMe", idx, False, "not present", None)
    check("optional + no pick -> None, no prompt", got, None)

    got, code = _quiet(hd.ask, "CPU", idx, True, "skip", None)
    check("required + NO pick -> exits non-zero rather than guessing", code, 2)
    check("  ...and returns no value at all", got, None)

    # fans: no live view, no prompt, only spinning fans
    fans = [("nct", "fan1_input", "CPU fan", 900),
            ("nct", "fan2_input", "phantom header", 0)]
    got, _ = _quiet(hd._select_fans_manual, fans, {})
    check("auto fan pick takes only the spinning one", len(got), 1)
    check("  ...and it is the right one", got[0]["unique_key"], "fan1_input")

    # MUTATION CONTROL: with AUTO off, the IDENTICAL call really does reach
    # input(). This is what proves the three checks above measured --auto rather
    # than measuring a function that never prompts under any setting.
    hd.AUTO = False
    _reached = False
    try:
        _quiet(hd.ask, "CPU", idx, True, "skip", pick)
    except AssertionError as e:
        _reached = "input() was called" in str(e)
    check("CONTROL: with AUTO off the same call DOES reach input()", _reached)
finally:
    hd.AUTO = _saved_auto
    if _real_input is None:
        del hd.input
    else:
        hd.input = _real_input


# ═══════════════════════════════════════════════════════════════════════════
print("\n== 4. _governed_ask routes through analyze() with the right controls ==")

_seen = {}

def _fake_analyze(prompt, **kw):
    _seen.clear()
    _seen.update(kw)
    _seen["prompt"] = prompt
    return {"ok": True, "text": json.dumps(
        {"cpu_temp": {"adapter": "nct", "unique_key": "temp1_input"},
         "ambient_temp": None, "nvme_temp": None, "fans": []})}

got, _ = _quiet(hd._governed_ask, _fake_analyze, "Temperature sensors:\n  1. x")
check("returns a parsed proposal", isinstance(got[0], dict))
check("no error reason on success", got[1], None)
check("the real model is passed (not the engine default)",
      _seen.get("model"), hd.CLAUDE_MODEL)
check("the call is attributable in ai_usage", _seen.get("surface"), "hw_discover")
check("a cache key is supplied", str(_seen.get("cache_key", "")).startswith("hw_discover:"))

# the engine's OWN decline reason must survive, not be flattened
def _capped(prompt, **kw):
    return {"ok": False, "reason": "monthly spend cap reached"}

got, _ = _quiet(hd._governed_ask, _capped, "x")
check("a declined call returns no proposal", got[0], None)
check("the engine's reason reaches the caller verbatim",
      got[1], "monthly spend cap reached")

# MUTATION CONTROL: a different reason must produce a different result
def _breaker(prompt, **kw):
    return {"ok": False, "reason": "circuit breaker open"}

got2, _ = _quiet(hd._governed_ask, _breaker, "x")
check("CONTROL: a different decline reason is NOT the same string",
      got2[1] != "monthly spend cap reached")

# unparseable model output is an explicit reason, never a silent None
def _garbage(prompt, **kw):
    return {"ok": True, "text": "not json at all"}

got, _ = _quiet(hd._governed_ask, _garbage, "x")
check("unparseable JSON -> explicit reason, not a bare None",
      got[0] is None and "unparseable" in (got[1] or ""))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== 5. _load_engine explains itself instead of returning a bare None ==")

_saved_db = os.environ.get("NEMESIS_DB_PATH")
os.environ["NEMESIS_DB_PATH"] = "/nonexistent/definitely/not/here/alerts.db"
try:
    fn, why = hd._load_engine()
    check("no analyze callable when the DB is absent", fn, None)
    check("a REASON is returned, not a bare None", bool(why))
    check("  ...and it names the actual cause", "does not exist" in (why or ""))
finally:
    if _saved_db is None:
        os.environ.pop("NEMESIS_DB_PATH", None)
    else:
        os.environ["NEMESIS_DB_PATH"] = _saved_db

print(f"\n{_pass} passed, {_fail} failed")
sys.exit(1 if _fail else 0)
