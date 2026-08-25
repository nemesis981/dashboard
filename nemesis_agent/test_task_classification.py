#!/usr/bin/env python3
"""Default-deny task-action dispatch (agent-side) — conformance + mutation suite.

WHAT THIS PROVES
----------------
Before this change, `agent.py`'s task loop ended in a bare `else:` forwarding any
action to `_CommandHandler._dispatch`. Adding an action to that handler silently
made it remotely executable. Now an unclassified action is REFUSED.

Two failure directions, and both are tested, because each is invisible on its own:

  * TOO STRICT -- an action that used to run is now refused. That is a live
    regression, so the exempt set is checked against the dispatcher's ACTUAL
    action list, parsed out of `agent.py` rather than retyped here. A hand-copied
    list would agree with itself forever while drifting from the code.
  * TOO LOOSE -- the classifier admits everything, restoring the default-allow
    behaviour this replaced. Nothing about that looks wrong from outside: tasks
    keep running, which is what they did before. Only a mutation test catches it,
    so `classification_self_test` is re-run against deliberately broken
    classifiers and each mutant must be confirmed to die.

Run: python3 nemesis_agent/test_task_classification.py
"""
import os
import re
import sys

# Overridable so this suite can be run against a DIFFERENT checkout (a clean
# origin/main worktree, say) and actually test THAT tree. Hardcoding /opt/nemesis
# would make a run inside another worktree silently parse the production files and
# report a pass about a tree it never looked at -- the wrong-source read this
# suite exists to catch, committed by the suite itself.
ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "nemesis_agent"))
print("  [root] parsing and importing from %s" % ROOT)

import tasks                                                       # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== NO REGRESSION: every action the dispatcher handles stays runnable ==")

AGENT_SRC = os.path.join(ROOT, "nemesis_agent", "agent.py")
with open(AGENT_SRC, "r", encoding="utf-8") as fh:
    _src = fh.read()

# Isolate `_dispatch` so `action == "..."` comparisons elsewhere in the file cannot
# inflate the list. Bounded at the next top-level `    def `, matching the file's
# own indentation.
_m = re.search(r"\n    def _dispatch\(self, action, body\):\n(.*?)\n    def ",
               _src, re.S)
DISPATCH_BODY = _m.group(1) if _m else ""
check("located `_dispatch` in agent.py to parse", bool(DISPATCH_BODY),
      "regex found nothing -- this test cannot verify anything without it")

DISPATCH_ACTIONS = sorted(set(re.findall(r'action == "([a-z_]+)"', DISPATCH_BODY)))
print("  dispatcher handles %d actions: %s" % (len(DISPATCH_ACTIONS), DISPATCH_ACTIONS))

# Shape check, not just a value check: if the parse silently matched nothing, an
# empty list would make the loop below vacuously pass.
check("parsed a PLAUSIBLE number of dispatcher actions (>=8)",
      len(DISPATCH_ACTIONS) >= 8, "got %d" % len(DISPATCH_ACTIONS))

# Every dispatcher action must be CLASSIFIED -- but "classified" is not the same
# as "exempt". An action may be deliberately loopback-only, and that is a decision
# rather than a gap. What must never happen is UNCLASSIFIED: that is the state
# where nobody decided, and where the action works locally while being silently
# refused from the server.
_VALID_DISPOSITIONS = (tasks.DISP_EXEMPT,
                       tasks.DISP_LOOPBACK_ONLY,
                       tasks.DISP_APPROVAL_REQUIRED)
for act in DISPATCH_ACTIONS:
    check("dispatcher action %-14s is CLASSIFIED (not left undecided)" % act,
          tasks.disposition(act) in _VALID_DISPOSITIONS,
          "got %s" % tasks.disposition(act))

# Pin the two classified on 2026-08-25 to the direction each was actually decided
# in, so a later "make the suite green" edit cannot quietly flip one. Asserting
# only "is classified" would accept either answer for either action.
check("`findings` is EXEMPT (read-only; server already holds the data)",
      tasks.disposition("findings") == tasks.DISP_EXEMPT,
      "got %s" % tasks.disposition("findings"))
check("`report_error` is LOOPBACK-ONLY (a write only the local GUI can mean)",
      tasks.disposition("report_error") == tasks.DISP_LOOPBACK_ONLY,
      "got %s" % tasks.disposition("report_error"))

# EXERCISE the refusal branch, do not merely assert the classification value.
# A test that reads the disposition proves the table; it does not prove that
# `assert_dispatchable` acts on it, which is the thing that actually stops a
# signed task from running the action.
try:
    tasks.assert_dispatchable("report_error")
except tasks.LoopbackOnlyAction as _e:
    check("assert_dispatchable RAISES LoopbackOnlyAction for `report_error`", True)
    check("...and its reason is distinct from an unclassified one",
          _e.reason == "action_is_loopback_only" and
          _e.reason != tasks.UnclassifiedAction.reason,
          "got reason=%r" % _e.reason)
except Exception as _e:                                        # noqa: BLE001
    check("assert_dispatchable RAISES LoopbackOnlyAction for `report_error`", False,
          "raised %r instead" % (_e,))
else:
    check("assert_dispatchable RAISES LoopbackOnlyAction for `report_error`", False,
          "it RETURNED -- a signed server task would be allowed to run it")

# CONTROL: the same call must still SUCCEED for an exempt action, or the check
# above would pass just as well against a classifier that refuses everything.
try:
    tasks.assert_dispatchable("findings")
    check("CONTROL: assert_dispatchable ADMITS `findings`", True)
except Exception as _e:                                        # noqa: BLE001
    check("CONTROL: assert_dispatchable ADMITS `findings`", False,
          "raised %r -- the refusal test above proves nothing" % (_e,))

# The production self-test must itself exercise the new tier.
try:
    tasks.classification_self_test()
    check("classification_self_test() passes with the loopback tier wired", True)
except Exception as _e:                                        # noqa: BLE001
    check("classification_self_test() passes with the loopback tier wired", False,
          "raised %r" % (_e,))

# The two special-cased task actions never reach `_dispatch`, so the parse above
# cannot see them -- they are checked by name.
for act in (tasks.ROTATE_ACTION, tasks.ATTEST_ACTION):
    check("special-cased action %-18s is classified EXEMPT" % act,
          tasks.disposition(act) == tasks.DISP_EXEMPT)

# And the reverse direction: nothing was added to the exempt set that the
# dispatcher cannot actually service. An exempt action with no handler would be a
# name that passes the gate and then fails at execution -- a phantom.
_known = set(DISPATCH_ACTIONS) | {tasks.ROTATE_ACTION, tasks.ATTEST_ACTION}
_phantoms = sorted(set(tasks.BASE_EXEMPT_ACTIONS) - _known)
check("no PHANTOM exempt actions (exempt but unhandled)", not _phantoms,
      "phantoms: %s" % _phantoms)

# Same reverse check for the loopback-only set: an entry naming a handler that
# does not exist would be a decision recorded about nothing, and would go on
# looking like a live control long after the action it names was deleted.
_lb_phantoms = sorted(set(tasks.BASE_LOOPBACK_ONLY_ACTIONS) - _known)
check("no PHANTOM loopback-only actions (classified but unhandled)",
      not _lb_phantoms, "phantoms: %s" % _lb_phantoms)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== CROSS-SIDE: every action the SERVER can emit is classified ==")
#
# The section above proves the agent still runs what its own dispatcher handles.
# That is not the same question as whether it still runs what the APPLIANCE
# actually sends -- the two lists are maintained in different repositories' worth
# of code and only overlap by convention. `attest_challenge` is the proof: the
# server defines it as a plain string that exists even when the private Tier 2
# module is absent, so it is emitted from a site that names no agent-side symbol
# at all. A drift here is a live outage (tasks silently refused fleet-wide), and
# it is invisible to every agent-only test.

SERVER_SRCS = [
    os.path.join(ROOT, "core_module", "hw_monitor", "hw_monitor.py"),
    os.path.join(ROOT, "dashboard.py"),
]

#: Server-side constants that resolve to an action name. Kept explicit so an
#: unresolvable site is REPORTED rather than quietly dropped from the count.
_CONST_VALUES = {
    "server_keys.ROTATE_ACTION": tasks.ROTATE_ACTION,
    "_att.TIER2_CHALLENGE_ACTION": "attest_challenge",
}

emitted, unresolved, sites = {}, [], 0
for path in SERVER_SRCS:
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    # `(?<!def )` excludes the DEFINITION of enqueue_task, whose signature is
    # literally `(device_id, action, ...)` and therefore matches a call-site
    # pattern perfectly. Caught by this check's own unresolved-site reporting,
    # which is the argument for having it: the parse was over-counting by one and
    # the only visible symptom was a name it could not resolve.
    for m in re.finditer(r"(?<!def )enqueue_task\(\s*(?:\n\s*)?device_id,\s*"
                         r'(?:"([a-z_]+)"|([A-Za-z_][\w.]*))', src):
        sites += 1
        literal, symbol = m.group(1), m.group(2)
        if literal:
            emitted[literal] = os.path.basename(path)
        elif symbol in _CONST_VALUES:
            emitted[_CONST_VALUES[symbol]] = os.path.basename(path)
        else:
            unresolved.append("%s:%s" % (os.path.basename(path), symbol))

print("  found %d enqueue_task sites -> %d distinct actions: %s"
      % (sites, len(emitted), sorted(emitted)))

# Report truncation/failure explicitly. An unresolved site means this check covers
# LESS than it appears to, and a shrinking denominator that nobody prints is how a
# coverage check quietly stops covering anything.
check("every enqueue_task site resolved to an action name", not unresolved,
      "unresolved: %s" % unresolved)
check("found a PLAUSIBLE number of emitting sites (>=5)", sites >= 5,
      "got %d -- the regex may have stopped matching" % sites)

for act, where in sorted(emitted.items()):
    if act == "attest_challenge":
        # Correctly UNCLASSIFIED on an agent without the private Tier 2 module:
        # it cannot service the action, so refusing it with a reported reason is
        # the honest outcome. Registration makes it EXEMPT where Tier 2 IS loaded,
        # which the runtime-registration section proves separately.
        tasks.register_exempt_action(act, "tier2 present (test simulation)")
        check("server-emitted %-18s classified once Tier 2 registers it (%s)"
              % (act, where), tasks.disposition(act) == tasks.DISP_EXEMPT)
        continue
    check("server-emitted %-18s is classified EXEMPT (%s)" % (act, where),
          tasks.disposition(act) == tasks.DISP_EXEMPT,
          "got %s -- the appliance would send a task this agent refuses"
          % tasks.disposition(act))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== DEFAULT-DENY: an unknown action is refused, not forwarded ==")

for bogus in ("push_and_run", "exec", "shell", "rm", "update_rules_v2",
              "PING", "ping ", "", "unknown action: ping"):
    check("refuses %-22r" % bogus,
          tasks.disposition(bogus) == tasks.DISP_UNCLASSIFIED,
          "got %s" % tasks.disposition(bogus))

# Hostile / wrong-typed input must produce a disposition, never a crash in the
# poll loop -- a TypeError here would take down task handling entirely.
for weird in (None, 42, b"ping", ["ping"], {"a": 1}, object()):
    try:
        d = tasks.disposition(weird)
        check("non-string %-14s -> UNCLASSIFIED (no crash)" % type(weird).__name__,
              d == tasks.DISP_UNCLASSIFIED, "got %s" % d)
    except Exception as exc:                                       # noqa: BLE001
        check("non-string %-14s -> UNCLASSIFIED (no crash)" % type(weird).__name__,
              False, "raised %r" % exc)

try:
    tasks.assert_dispatchable("definitely_not_an_action")
    check("assert_dispatchable RAISES on an unclassified action", False,
          "it returned instead")
except tasks.UnclassifiedAction as exc:
    check("assert_dispatchable RAISES on an unclassified action", True)
    check("  the refusal carries a typed machine-readable reason",
          exc.reason == "action_not_classified", exc.reason)
    check("  UnclassifiedAction is a TaskRejected (caught by existing handlers)",
          isinstance(exc, tasks.TaskRejected))

check("assert_dispatchable RETURNS the disposition for an exempt action",
      tasks.assert_dispatchable("ping") == tasks.DISP_EXEMPT)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== RUNTIME REGISTRATION (optional modules, e.g. Tier 2) ==")

_secret = "__private_module_action__"
check("an unregistered module action is refused first",
      tasks.disposition(_secret) == tasks.DISP_UNCLASSIFIED)

tasks.register_exempt_action(_secret, "test registration")
check("registering it makes it EXEMPT",
      tasks.disposition(_secret) == tasks.DISP_EXEMPT)
check("  registration does NOT mutate the frozen base set",
      _secret not in tasks.BASE_EXEMPT_ACTIONS)
check("  the base set is immutable (frozenset)",
      isinstance(tasks.BASE_EXEMPT_ACTIONS, frozenset))

for bad_args, why in ((("", "reason"), "empty action name"),
                      ((None, "reason"), "None action"),
                      (("act", ""), "missing reason"),
                      (("act", None), "None reason")):
    try:
        tasks.register_exempt_action(*bad_args)
        check("registration rejects %s" % why, False, "it was accepted")
    except ValueError:
        check("registration rejects %s" % why, True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== MUTATION: the self-test must DIE against a broken classifier ==")

# CONTROL FIRST. If the unmutated self-test does not pass, every "mutant caught"
# below could be dying of something unrelated and would prove nothing.
try:
    tasks.classification_self_test()
    check("CONTROL: unmutated classification_self_test PASSES", True)
except Exception as exc:                                           # noqa: BLE001
    check("CONTROL: unmutated classification_self_test PASSES", False, repr(exc))

_real_disposition = tasks.disposition
_real_assert = tasks.assert_dispatchable

MUTANTS = [
    ("always EXEMPT (restores default-allow)",
     lambda _a: tasks.DISP_EXEMPT, None),
    ("always UNCLASSIFIED (refuses every task)",
     lambda _a: tasks.DISP_UNCLASSIFIED, None),
    ("EXEMPT for anything non-empty (a plausible-looking bug)",
     lambda a: tasks.DISP_EXEMPT if a else tasks.DISP_UNCLASSIFIED, None),
    ("assert_dispatchable never raises",
     None, lambda _a: tasks.DISP_EXEMPT),
]

for label, mut_disp, mut_assert in MUTANTS:
    if mut_disp is not None:
        tasks.disposition = mut_disp
    if mut_assert is not None:
        tasks.assert_dispatchable = mut_assert
    try:
        tasks.classification_self_test()
        check("mutant CAUGHT: %s" % label, False, "the self-test passed anyway")
    except tasks.VerifierBroken:
        check("mutant CAUGHT: %s" % label, True)
    except Exception as exc:                                       # noqa: BLE001
        check("mutant CAUGHT: %s" % label, False,
              "died of an UNRELATED error, so nothing was proven: %r" % exc)
    finally:
        tasks.disposition = _real_disposition
        tasks.assert_dispatchable = _real_assert

check("CONTROL: the real functions were restored after mutation",
      tasks.disposition is _real_disposition
      and tasks.assert_dispatchable is _real_assert)
try:
    tasks.classification_self_test()
    check("CONTROL: self-test passes again post-mutation", True)
except Exception as exc:                                           # noqa: BLE001
    check("CONTROL: self-test passes again post-mutation", False, repr(exc))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== WIRING: the gate is reached, and reached BEFORE the claim ==")
#
# SOURCE-ORDER CHECK, and labelled as one. Running the real task loop needs a
# pinned anchor, config and a live poll cycle; what actually has to be true is a
# property of the call ORDER in the source, so that is what is asserted here
# rather than dressed up as a runtime observation.

_loop = _src[_src.find("def _handle_response_tasks"):]
_loop = _loop[:_loop.find("\ndef ", 1)] if "\ndef " in _loop[1:] else _loop

_i_assert = _loop.find("assert_dispatchable")
_i_claim = _loop.find("claim_task(")
_i_verify = _loop.find("verify_task(")

check("agent.py's task loop CALLS assert_dispatchable", _i_assert != -1)
check("agent.py's task loop still calls claim_task", _i_claim != -1)
check("assert_dispatchable is called AFTER verify_task (signature first)",
      _i_verify != -1 and _i_assert > _i_verify,
      "verify@%d assert@%d" % (_i_verify, _i_assert))
check("assert_dispatchable is called BEFORE claim_task (no wasted claim)",
      _i_assert != -1 and _i_claim != -1 and _i_assert < _i_claim,
      "assert@%d claim@%d" % (_i_assert, _i_claim))
check("the refusal path records E-AGENT-117", "E-AGENT-117" in _loop)

# The error code must actually exist in the registry, or recording it is a no-op
# that reports nothing -- a failed lookup surfacing as silence.
import agent_errors                                                # noqa: E402

# The registry is looked up by its real name and the LOOKUP ITSELF is checked
# first. An earlier version of this guessed `agent_errors.ERRORS`, did not exist,
# and reported "code missing" -- a wrong-source read wearing the costume of a real
# finding. Two separate assertions now, so "registry not found" can never again be
# reported as "code not registered".
_registry = getattr(agent_errors, "E_AGENT_CODES", None)
check("the agent error registry is reachable under its real name",
      isinstance(_registry, dict) and len(_registry) > 0,
      "E_AGENT_CODES missing or empty -- the check below would be meaningless")
if isinstance(_registry, dict):
    check("E-AGENT-117 is a REGISTERED error code (not a silent no-op)",
          "E-AGENT-117" in _registry,
          "registry holds %d codes, none of them E-AGENT-117" % len(_registry))
    check("  CONTROL: the registry does NOT contain a code that was never added",
          "E-AGENT-999" not in _registry)


print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
