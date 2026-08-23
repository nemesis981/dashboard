"""
Response-block parsing for ai_engine — the ThinkingBlock regression guard.

Standalone (no pytest). Stubs the `anthropic` package so `messages.create()`
returns a synthetic response, then drives the REAL `_analyze_inner` parsing path.
No network calls.

WHY THIS EXISTS
---------------
`_analyze_inner` read the model's answer as `msg.content[0].text`. That is correct
only while the first content block happens to be the text block. On
`claude-opus-5` thinking is ON BY DEFAULT — omitting the `thinking` parameter runs
adaptive thinking, unlike opus-4-8/4-7 where omitting it meant no thinking — so
content[0] became a ThinkingBlock, which carries `.thinking` and has no `.text`.

Every AI surface in the product broke on the same AttributeError (chat, Layer C
verdicts, anomaly analysis) **while the API call itself returned HTTP 200**. The
failure was invisible to anything watching request status; only the response
parse failed.

The load-bearing case is therefore case 1: a response whose FIRST block is a
ThinkingBlock. A test that only feeds a text-first response passes against the
broken code and proves nothing.
"""

import os
import sys
import tempfile
import types

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
# Must look configured or _analyze_inner returns "no key" before reaching the
# parsing path this harness exists to prove. Never used: the client is stubbed.
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test-not-a-real-key"

import modules                                                  # noqa: E402
modules.set_shared_db_path(_db)
import sys as _s_npfa
_s_npfa.path.insert(0, '/opt/nemesis/alert_manager')
import prompt_fields as _pf                    # noqa: E402  (NPFA/1)
import modules_loader                                           # noqa: E402
modules_loader._db_path = _db

import sqlite3 as _sqlite3                                      # noqa: E402
_c = _sqlite3.connect(_db)
_c.execute("CREATE TABLE IF NOT EXISTS modules_enabled "
           "(module_name TEXT PRIMARY KEY, enabled INTEGER, actor TEXT)")
_c.execute("INSERT OR REPLACE INTO modules_enabled VALUES ('ai_engine',1,NULL)")
_c.commit()
_c.close()

from modules.ai_engine import module as ai                      # noqa: E402

EXPECTED_CHECKS = 10
_state = {"ran": 0, "failed": 0}


def check(label, got, want):
    _state["ran"] += 1
    ok = got == want
    if not ok:
        _state["failed"] += 1
    print("  %-56s %s  (got=%r want=%r)"
          % (label, "PASS" if ok else "FAIL", got, want))


class _Block:
    """A content block shaped like the SDK's — typed, with only its own field.

    ThinkingBlock deliberately has NO `.text` attribute: that absence is the
    bug's mechanism, so a stub that carried both fields would let the broken
    code pass.
    """

    def __init__(self, type_, **fields):
        self.type = type_
        for k, v in fields.items():
            setattr(self, k, v)


class _Usage:
    input_tokens = 100
    output_tokens = 50


class _Resp:
    def __init__(self, content, stop_reason="end_turn", stop_details=None):
        self.content = content
        self.usage = _Usage()
        self.stop_reason = stop_reason
        self.stop_details = stop_details


def install_stub(resp):
    """Replace the `anthropic` package so the real code path gets `resp`."""
    mod = types.ModuleType("anthropic")

    class _Messages:
        def create(self, **kwargs):
            return resp

    class _Client:
        def __init__(self, **kwargs):
            self.messages = _Messages()

    mod.Anthropic = _Client
    sys.modules["anthropic"] = mod


def call():
    """Drive the real path. cache_key=None so nothing short-circuits."""
    # NPFA/1 (ADR 0025): this suite exercises response-block parsing, not the
    # allowlist. The prompt is wrapped in the proof type so the boundary
    # passes and the guard under test is the one actually measured.
    return ai._analyze_inner(
        prompt=_pf.BuiltPrompt("test data 2026-08-04 — response block parsing"),
        system_prompt=None, max_tokens=64,
        cache_key=None, cache_hours=0, force=True)


def main():
    print("-- case 1: THINKING BLOCK FIRST (the regression) --")
    install_stub(_Resp([
        _Block("thinking", thinking="internal reasoning, no .text attribute"),
        _Block("text", text="  the real answer  "),
    ]))
    r = call()
    check("call succeeds despite leading ThinkingBlock", r.get("ok"), True)
    check("extracts the TEXT block, not content[0]", r.get("text"), "the real answer")
    check("no AttributeError surfaced as a reason", r.get("reason"), None)

    print("\n-- case 2: text-only (older-model shape) still works --")
    install_stub(_Resp([_Block("text", text="plain answer")]))
    r = call()
    check("text-only response still parses", r.get("ok"), True)
    check("text is correct", r.get("text"), "plain answer")

    print("\n-- case 3: thinking-only — must FAIL, not return empty success --")
    install_stub(_Resp([_Block("thinking", thinking="reasoned but never answered")]))
    r = call()
    check("no text block -> not ok", r.get("ok"), False)
    check("reason names the block types it did see",
          "thinking" in (r.get("reason") or ""), True)

    print("\n-- case 4: refusal (HTTP 200, stop_reason='refusal') --")
    install_stub(_Resp([], stop_reason="refusal",
                       stop_details=_Block("refusal", category="cyber")))
    r = call()
    check("refusal -> not ok", r.get("ok"), False)
    check("refusal is stated, not an empty answer",
          "declined" in (r.get("reason") or ""), True)
    check("refusal category surfaced", "cyber" in (r.get("reason") or ""), True)

    print("\n%d/%d checks (ran=%d failed=%d)"
          % (_state["ran"] - _state["failed"], EXPECTED_CHECKS,
             _state["ran"], _state["failed"]))
    if _state["ran"] != EXPECTED_CHECKS:
        print("!! declared %d but ran %d — count guard failed"
              % (EXPECTED_CHECKS, _state["ran"]))
        return 1
    return 1 if _state["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
