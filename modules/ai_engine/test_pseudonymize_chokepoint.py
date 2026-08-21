#!/usr/bin/env python3
"""No billed AI call may carry a real network address off this box.

Run:  python3 modules/ai_engine/test_pseudonymize_chokepoint.py   (exit 0 = pass)

WHAT THIS GUARDS. Until 2026-08-21 pseudonymization lived in exactly ONE caller
(dashboard's alert path) while three others -- anomaly, community queue, malware
Layer C -- called `analyze()` directly. Anomaly was sending real device names and
real LAN IPs to the vendor on every automatic incident analysis. The scrub now
lives at the choke point, so it applies to every present and future caller.

The property under test is therefore about the WIRE, not about a helper: what
does `_analyze_inner` actually hand to the SDK? So this harness stubs the
`anthropic` package, captures the exact kwargs the client is called with, and
asserts on those bytes. A test that only exercised `nemesis_pseudonymize`
directly would have passed happily throughout the entire period the leak existed
-- the helper was never broken; nothing called it.

⚠ SCOPE, STATED HONESTLY. `nemesis_pseudonymize` replaces ADDRESSES (IPv4/IPv6
and MACs). It does NOT replace hostnames or device names. The name leak is still
open, and `test_names_are_NOT_covered` below pins that as a known gap so nobody
reads this suite as proving more than it does.

CONTROLS. Every "the address is gone" assertion is paired with proof the
detector can see an address when one is present, and with an address-free
control showing the scrubber does not mangle ordinary text. The fail-closed case
asserts not merely that an error was returned but that NO CALL WAS MADE.

NO NETWORK. The SDK is stubbed; nothing here contacts Anthropic or spends money.
"""
import os
import sys
import tempfile
import types

sys.path.insert(0, "/opt/nemesis")
# Deliberately NOT adding alert_manager/ to sys.path: the module under test must
# resolve `nemesis_pseudonymize` on its own. That import path is load-bearing
# for availability (the scrub fails closed), so it is part of what is tested.

_db = os.path.join(tempfile.mkdtemp(prefix="ai-pseudo-"), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")

import modules                                          # noqa: E402
modules.set_shared_db_path(_db)

from modules.ai_engine import module as ai               # noqa: E402

passed = failed = 0
SENT = []            # every kwargs dict the stub client was called with


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + detail) if detail else ""))


# ── stub the SDK: capture what would have gone over the wire ────────────────
class _Block:
    type = "text"

    def __init__(self, text):
        self.text = text


class _Usage:
    input_tokens = 100
    output_tokens = 50


class _Msg:
    stop_reason = "end_turn"

    def __init__(self, text):
        self.content = [_Block(text)]
        self.usage = _Usage()


REPLY = ["ok"]          # mutable so a case can choose the model's answer


class _Messages:
    def create(self, **kwargs):
        SENT.append(kwargs)
        return _Msg(REPLY[0])


class _Client:
    def __init__(self, **_kw):
        self.messages = _Messages()


_fake = types.ModuleType("anthropic")
_fake.Anthropic = _Client
sys.modules["anthropic"] = _fake

# Isolate the path under test from rate limiting / usage accounting / cache.
# Signatures matter: `_check_rate_limit(conn)` returns the TUPLE (limited, reason).
# A stub with the wrong shape raises inside the caller's try/except, which
# swallows it and carries on — the suite would still pass, for the wrong reason,
# while logging a TypeError on every call. Matched deliberately.
ai._check_rate_limit = lambda conn: (False, None)
ai._increment_usage = lambda conn, tokens_in, tokens_out: None
ai._record_call_success = lambda: None


def run(prompt, system=None):
    SENT.clear()
    return ai._analyze_inner(prompt, system, 500, None, 0, False)


REAL_IP, REAL_IP2 = "192.0.2.5", "198.51.100.77"
REAL_MAC = "aa:bb:cc:dd:ee:ff"


def main():
    print("\n-- PREMISE: the harness really does capture the wire payload --")
    r = run("nothing sensitive here")
    check("a call reaches the stubbed SDK", len(SENT) == 1)
    check("the call succeeded", r.get("ok") is True, repr(r)[:200])
    check("address-free text is passed through UNCHANGED",
          SENT[0]["messages"][0]["content"] == "nothing sensitive here",
          repr(SENT[0]["messages"][0]["content"]))

    print("\n-- CONTROL: the detector can see a real address when one is present --")
    probe = "host %s did something" % REAL_IP
    check("the raw prompt genuinely contains the address", REAL_IP in probe)

    print("\n-- the wire must not carry real addresses --")
    run(probe)
    wire = SENT[0]["messages"][0]["content"]
    check("IPv4 does NOT reach the wire", REAL_IP not in wire, "wire=%r" % wire)
    check("a token replaced it", "host-" in wire, "wire=%r" % wire)

    run("MAC %s seen on the LAN" % REAL_MAC)
    check("MAC does NOT reach the wire", REAL_MAC not in SENT[0]["messages"][0]["content"],
          "wire=%r" % SENT[0]["messages"][0]["content"])

    print("\n-- the SYSTEM prompt is scrubbed too --")
    run("benign body", "You are analysing traffic from %s" % REAL_IP2)
    check("IPv4 does NOT reach the wire via `system`",
          REAL_IP2 not in SENT[0].get("system", ""), "system=%r" % SENT[0].get("system"))
    check("the system field is still populated", bool(SENT[0].get("system")))

    print("\n-- ONE mapping across both fields (no colliding host-A) --")
    run("the body mentions %s" % REAL_IP, "the system mentions %s" % REAL_IP)
    sys_txt, usr_txt = SENT[0]["system"], SENT[0]["messages"][0]["content"]
    sys_tok = sys_txt.split("mentions ")[1].strip()
    usr_tok = usr_txt.split("mentions ")[1].strip()
    check("the SAME address gets the SAME token in both fields",
          sys_tok == usr_tok, "system=%r user=%r" % (sys_tok, usr_tok))

    run("body has %s" % REAL_IP, "system has %s" % REAL_IP2)
    sys_tok = SENT[0]["system"].split("has ")[1].strip()
    usr_tok = SENT[0]["messages"][0]["content"].split("has ")[1].strip()
    check("DIFFERENT addresses get DIFFERENT tokens across the two fields",
          sys_tok != usr_tok, "system=%r user=%r" % (sys_tok, usr_tok))

    print("\n-- the reply is un-pseudonymized before the caller sees it --")
    REPLY[0] = "host-A is the source"
    out = run("investigate %s" % REAL_IP)
    check("the caller gets the REAL address back", REAL_IP in out.get("text", ""),
          "text=%r" % out.get("text"))
    check("the token is gone from the returned text", "host-A" not in out.get("text", ""))

    print("\n-- an invented token is left standing, not silently deleted --")
    REPLY[0] = "host-Q did it"
    out = run("investigate %s" % REAL_IP)
    check("an unmapped token survives so the operator can see it",
          "host-Q" in out.get("text", ""), "text=%r" % out.get("text"))
    REPLY[0] = "ok"

    print("\n-- COMPOSITION: an already-scrubbed caller is not double-mangled --")
    out = run("host-A talked to host-B")     # dashboard's alert path shape
    check("pre-tokenized text passes through unchanged",
          SENT[0]["messages"][0]["content"] == "host-A talked to host-B",
          repr(SENT[0]["messages"][0]["content"]))
    check("and its reply is returned unchanged for the caller to resolve",
          out.get("text") == "ok")

    print("\n-- FAIL CLOSED: a broken scrubber must BLOCK, not pass raw text --")
    import nemesis_pseudonymize as _p
    _orig = _p.pseudonymize
    _p.pseudonymize = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        SENT.clear()
        blocked = ai._analyze_inner("leak %s" % REAL_IP, None, 500, None, 0, False)
        check("the call is refused", blocked.get("ok") is False, repr(blocked)[:200])
        check("the reason names pseudonymization",
              "pseudonym" in (blocked.get("reason") or "").lower(),
              repr(blocked.get("reason")))
        check("NO REQUEST WAS MADE (the decisive assertion)", len(SENT) == 0,
              "sent=%r" % SENT)
    finally:
        _p.pseudonymize = _orig

    print("\n-- recovery control: normal calls work again afterwards --")
    r = run("plain text")
    check("a later call succeeds", r.get("ok") is True)

    print("\n-- the import that makes fail-closed safe actually resolves --")
    check("nemesis_pseudonymize resolved WITHOUT the test adding it to sys.path",
          "nemesis_pseudonymize" in sys.modules)

    print("\n-- KNOWN GAP, pinned deliberately: names are NOT addresses --")
    run("device Reception-Laptop contacted %s" % REAL_IP)
    wire = SENT[0]["messages"][0]["content"]
    check("device NAMES still reach the wire (documented, still open)",
          "Reception-Laptop" in wire,
          "If this now FAILS, name coverage was added — update the audit and this test.")

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
