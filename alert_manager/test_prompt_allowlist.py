#!/usr/bin/env python3
"""NPFA/1 — the structured-prompt allowlist and its ENFORCEMENT BOUNDARY.

Two different things are tested here and the distinction matters:

  * the FIELD VALIDATORS -- does each kind reject what it promises to reject;
  * the BOUNDARY -- can an unstructured prompt reach `analyze()` at all.

The second is the one that actually closes the gap. A perfect set of validators
is worth nothing if a caller can hand `analyze()` a hand-built f-string, so the
boundary gets mutation coverage in its own right: a plain str, a tampered
BuiltPrompt, and a BuiltPrompt downgraded by ordinary string operations.

NO NETWORK, NO LIVE DB: the SDK is stubbed and the DB is a throwaway temp file.
"""
import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

_db = os.path.join(tempfile.mkdtemp(prefix="npfa-"), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")

import types
SENT = []


class _Block:
    type = "text"

    def __init__(self, text):
        self.text = text


class _Resp:
    def __init__(self):
        self.content = [_Block('{"ok": 1}')]
        self.usage = type("U", (), {"input_tokens": 1, "output_tokens": 1})()


class _Messages:
    def create(self, **kw):
        SENT.append(kw)
        return _Resp()


class _Client:
    def __init__(self, **k):
        self.messages = _Messages()


_fake = types.ModuleType("anthropic")
_fake.Anthropic = _Client
sys.modules["anthropic"] = _fake

import modules                                            # noqa: E402
modules.set_shared_db_path(_db)
import prompt_fields as pf                                # noqa: E402
from modules.ai_engine import module as ai                # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def raises(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except pf.PromptFieldError:
        return True


# ═══════════════════════════════════════════════════════════════════════
print("\n== 1. field kinds reject what they promise to reject ==")

# Each rejection is PAIRED with a control proving the same kind accepts a
# legitimate value -- otherwise a validator that rejected everything would look
# identical to one that works.
cases = [
    (pf.ADDRESS,     "not-an-ip",              "192.0.2.5"),
    (pf.ADDRESS,     "999.999.999.999",        "aa:bb:cc:dd:ee:ff"),
    (pf.BASENAME,    "/home/someone/thing.exe", "thing.exe"),
    (pf.BASENAME,    "C:\\Users\\x\\a.exe",     "a.exe"),
    (pf.HASH,        "not a hash",             "deadbeefcafe1234"),
    (pf.IDENTIFIER,  "has spaces and stuff",   "rule:2054140"),
    (pf.DOMAIN,      "not a domain!!",         "example.com"),
    (pf.NUMBER,      "12",                     12),
    (pf.DEVICE_NAME, "line one\nline two",     "Reception-Laptop"),
    (pf.LABEL,       "multi\nline",            "Package id 0"),
    (pf.TIMESTAMP,   "x" * 200,                1724400000),
]
for kind, bad, good in cases:
    check("%-12s rejects %-26r" % (kind, bad), raises(pf.render_field, kind, bad))
    check("  CONTROL: %-12s accepts %r" % (kind, good),
          pf.render_field(kind, good) is not None)

check("ENUM rejects a non-member",
      raises(pf.render_field, pf.ENUM, "purple", allowed={"red", "blue"}))
check("  CONTROL: ENUM accepts a member",
      pf.render_field(pf.ENUM, "red", allowed={"red", "blue"}) == "red")
check("ENUM with NO declared set is refused (not silently allowed)",
      raises(pf.render_field, pf.ENUM, "anything"))
check("an unknown kind is refused", raises(pf.render_field, "free_text", "whatever"))
check("an over-long field is refused",
      raises(pf.render_field, pf.LABEL, "x" * (pf.MAX_FIELD_CHARS + 1)))

# The kind that would be the escape hatch if it were sloppy.
check("DEVICE_NAME refuses multi-line input (free text under a name's label)",
      raises(pf.render_field, pf.DEVICE_NAME, "Reception-Laptop\nplus a whole log"))


# ═══════════════════════════════════════════════════════════════════════
print("\n== 2. build() produces a BuiltPrompt, and only from declared parts ==")

p = pf.build(["Header text", ("Domain", pf.DOMAIN, "example.com")])
check("build() returns a BuiltPrompt", isinstance(p, pf.BuiltPrompt))
check("it is also a str (existing consumers keep working)", isinstance(p, str))
check("the rendered text is right", "Domain: example.com" in p)
check("a malformed part is refused", raises(pf.build, [("x", )]))
check("a bare runtime value with no kind is refused",
      raises(pf.build, [("Label", "made_up_kind", "value")]))


# ═══════════════════════════════════════════════════════════════════════
print("\n== 3. THE BOUNDARY: what analyze() will and will not accept ==")


def _call(prompt, **kw):
    SENT.clear()
    return ai._analyze_inner(prompt, None, 200, None, 0, True, **kw)

# (a) the good path
r = _call(pf.build(["hello", ("Domain", pf.DOMAIN, "example.com")]))
check("a BuiltPrompt is accepted", r.get("ok") is True, repr(r)[:120])
check("  ...and it really did reach the wire", len(SENT) == 1)

# (b) a hand-built string -- the whole thing this closes
r = _call("Reception-Laptop did something at 192.0.2.5")
check("a plain str prompt is REFUSED", r.get("ok") is False)
check("  ...and NOTHING reached the wire", len(SENT) == 0)
check("  ...and the reason names the spec", "NPFA/1" in (r.get("reason") or ""))

# (c) TAMPERING DOWNGRADES THE TYPE. This is the property that makes the type a
#     real proof rather than a label: any str operation returns a plain str.
built = pf.build(["safe", ("Domain", pf.DOMAIN, "example.com")])
for label, mutated in (
    ("concatenation",     built + "\nand Reception-Laptop leaked"),
    ("prefix concat",     "Reception-Laptop\n" + built),
    ("slicing",           built[:-1]),
    ("join",              "".join([built, " extra"])),
    ("format",            "%s extra" % built),
    ("replace",           built.replace("safe", "Reception-Laptop")),
    ("upper",             built.upper()),
):
    check("tampering by %-16s downgrades to plain str" % label,
          not isinstance(mutated, pf.BuiltPrompt))
    r = _call(mutated)
    check("  ...and analyze() refuses it", r.get("ok") is False and len(SENT) == 0)

# (d) the ONE exemption
r = _call("whatever the operator typed", free_text_reason="operator-authored test")
check("free_text_reason admits a plain str", r.get("ok") is True, repr(r)[:120])
check("  ...and it reached the wire", len(SENT) == 1)

# CONTROL: the exemption must be the REASON, not incidental -- the identical
# call without it is refused. Without this pairing the check above would pass
# even if analyze() accepted plain strings unconditionally.
r = _call("whatever the operator typed")
check("CONTROL: the SAME prompt without a reason is refused",
      r.get("ok") is False and len(SENT) == 0)
check("CONTROL: an empty reason does not count as one",
      _call("x", free_text_reason="").get("ok") is False)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 4. CONFORMANCE: the exemption is one marked path, not a hatch ==")

import subprocess
hits = subprocess.run(
    ["grep", "-rn", "free_text_reason=", "--include=*.py", "/opt/nemesis"],
    capture_output=True, text=True).stdout.strip().split("\n")
callers = [h for h in hits if h and "/test_" not in h
           and "prompt_fields.py" not in h
           and "def analyze" not in h
           and "free_text_reason=free_text_reason" not in h
           and "free_text_reason: str" not in h]
check("exactly ONE production caller passes free_text_reason", len(callers) == 1,
      "found: %s" % [c.split(":")[0] for c in callers])
check("  ...and it is the chat surface in ai_engine",
      bool(callers) and "ai_engine/module.py" in callers[0], str(callers[:1]))

# No machine-generated builder may still hand analyze() an f-string.
#
# ⚠ THIS LIST IS THE CLOSED SET OF BUILDERS. `prompt_fields.build()`'s own
# docstring says the caller set is closed and that this conformance list is what
# keeps it that way — so a new builder is added HERE, deliberately, or the set
# is closed in name only and grows silently.
#
# ADDED 2026-08-27: `modules/ai_engine/failsafe_decision.py`, the engine side of
# ADR 0019 Amendment 03 §10.3. It is the SIXTH builder and the first one that
# lives inside ai_engine itself — worth noting, because it makes ai_engine both
# a builder and the enforcer of the rule. That is acceptable only because
# `analyze()` checks the TYPE it receives and does not care who built it: the
# guarantee is carried by BuiltPrompt, not by the caller's identity.
for mod in ("modules/anomaly_detection/module.py",
            "modules/community_queue/module.py",
            "modules/malware_detection/module.py",
            "modules/ai_engine/failsafe_decision.py",
            "dashboard.py",
            "alert_manager/hw_discover.py"):
    src = open(os.path.join("/opt/nemesis", mod), encoding="utf-8").read()
    check("%s builds prompts via the allowlist" % mod.split("/")[-1],
          "_pf.build(" in src or "prompt_fields" in src)

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
