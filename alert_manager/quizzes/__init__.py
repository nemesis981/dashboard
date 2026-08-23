"""Hand-authored capability quizzes: loading, validation, and grading.

WHY THESE ARE AUTHORED AND NOT GENERATED (ADR 0026 D4)
------------------------------------------------------
The roadmap ties the learning gate to the AI-tutorials plan. That plan is unbuilt
and contains no quiz concept at all -- read end to end it specifies tiered
walkthroughs, a `tutorial_index` table and natural-language search, with no
scoring and no unlock mechanic. Waiting for it would block this indefinitely on a
dependency that would not deliver the needed piece even when finished.

That dependency is only load-bearing if the quiz must be GENERATED. It does not
have to be, and generating it would be actively worse: a quiz about a dangerous
capability that hallucinates a wrong "correct" answer teaches a confident
misunderstanding, and the failure is invisible -- the learner passes, unlocks, and
is now wrong about something that can break the network. When the tutorials system
exists it becomes a CONTENT SOURCE feeding this format, not a prerequisite.

WHAT THE QUIZ IS AND IS NOT
---------------------------
It proves COMPETENCE, not AUTHORIZATION. A quiz stops an untrained delegate firing
a dangerous task by accident; it does not inconvenience an attacker for a moment.
It is one layer on top of real authorization (role + capability unlock + the
admin-approval signature), never a substitute for any of them. Nothing in this
module should ever be described as a security control.

100% TO PASS, UNLIMITED RETAKES
-------------------------------
Not an arbitrary bar. A partial threshold means someone can unlock a dangerous
capability while demonstrably not understanding one of its points, and nothing
records WHICH point. Since this teaches rather than examines, there is no reason
to allow permanent failure: retake until every point is understood, with the
reasoning shown after a wrong answer. Short sets (3-5 questions) keep that humane.

VERSIONING IS A CONTENT DIGEST, NOT A DECLARED NUMBER
-----------------------------------------------------
`effective_version()` is derived from the QUESTIONS THEMSELVES, so editing a quiz
necessarily changes it and silently invalidates every unlock earned against the
old wording. The declared `quiz_version` remains as a human-readable label of
intent ("2 -- rewritten after the firewall change") but is NOT what invalidation
keys on.

The alternative -- trusting an author to bump a number when they change content --
is the "forgot to update it" failure this codebase has now been bitten by four
times in one day via missing package exports. A digest cannot be forgotten.

THE TRADEOFF, STATED: fixing a typo also invalidates unlocks and forces a retake.
That is a real cost and it is accepted deliberately. The alternative failure is
stale training that the UI still asserts is current, which is the one that gets
someone hurt. Erring toward re-training matches every other fail-safe choice here.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os

log = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))

#: Every question must be answered correctly. See the module docstring.
PASS_MARK = 100


class QuizError(Exception):
    """Base for every refusal in this module."""


class QuizUnavailable(QuizError):
    """No usable quiz exists for this capability.

    RAISED, never resolved to an empty quiz. A zero-question quiz would be passed
    by answering nothing, which would unlock a dangerous capability while proving
    exactly nothing -- the worst possible failure for this module.
    """


class QuizMalformed(QuizError):
    """A quiz file exists but cannot be trusted. Refused at LOAD, not at grade."""


def _quiz_path(capability):
    # Capability names come from roles.CAPABILITY_ROUTES, not from callers, but
    # this is a filesystem path either way -- refuse anything that is not a plain
    # identifier rather than relying on that remaining true.
    if not capability or not str(capability).replace("_", "").isalnum():
        raise QuizMalformed("%r is not a usable capability name" % (capability,))
    return os.path.join(_HERE, "%s.json" % capability)


def _validate(capability, doc):
    """Refuse anything that could grade wrongly. Returns the question list."""
    if not isinstance(doc, dict):
        raise QuizMalformed("%s: top level is not an object" % capability)
    questions = doc.get("questions")
    if not isinstance(questions, list) or not questions:
        raise QuizMalformed("%s: no questions -- a quiz that can be passed by "
                            "answering nothing proves nothing" % capability)
    seen_ids = set()
    for i, q in enumerate(questions):
        where = "%s question %d" % (capability, i + 1)
        if not isinstance(q, dict):
            raise QuizMalformed("%s: not an object" % where)
        qid = q.get("id")
        if not qid or not isinstance(qid, str):
            raise QuizMalformed("%s: missing a string id" % where)
        if qid in seen_ids:
            raise QuizMalformed("%s: duplicate id %r -- grading would be "
                                "ambiguous" % (where, qid))
        seen_ids.add(qid)
        if not q.get("prompt"):
            raise QuizMalformed("%s: missing prompt" % where)
        options = q.get("options")
        if not isinstance(options, list) or len(options) < 2:
            raise QuizMalformed("%s: needs at least two options, or there is "
                                "nothing to choose" % where)
        correct = q.get("correct")
        if not isinstance(correct, int) or isinstance(correct, bool) \
                or not (0 <= correct < len(options)):
            # `isinstance(True, int)` is True in Python; a bool here would index
            # option 0 or 1 and grade silently wrongly.
            raise QuizMalformed("%s: 'correct' must be an index into options "
                                "(got %r)" % (where, correct))
        if not q.get("why"):
            raise QuizMalformed("%s: missing 'why' -- a wrong answer with no "
                                "explanation teaches nothing" % where)
    return questions


def load(capability):
    """The validated quiz document for `capability`. Raises; never returns empty."""
    path = _quiz_path(capability)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise QuizUnavailable("no quiz authored for %r yet" % (capability,)) from None
    except (OSError, ValueError) as exc:
        raise QuizMalformed("%s: could not be read (%s)" % (capability, exc)) from None
    _validate(capability, doc)
    return doc


def effective_version(capability, doc=None):
    """The version invalidation keys on: a digest of the QUESTIONS.

    Derived from content so that editing a quiz necessarily changes it. The
    declared `quiz_version` is included as a label but cannot, on its own, keep
    the value stable across a content edit.
    """
    doc = doc if doc is not None else load(capability)
    payload = json.dumps(
        [{"id": q["id"], "prompt": q["prompt"], "options": q["options"],
          "correct": q["correct"]} for q in doc["questions"]],
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:12]
    return "%s+%s" % (str(doc.get("quiz_version", "1")), digest)


def available():
    """Capabilities that have a LOADABLE quiz. A malformed one is not available.

    A malformed quiz is logged loudly and excluded rather than raising, so one bad
    file cannot take down the settings page that lists them -- but it is never
    silently treated as absent either.
    """
    out = []
    for fn in sorted(os.listdir(_HERE)):
        if not fn.endswith(".json"):
            continue
        cap = fn[:-len(".json")]
        try:
            load(cap)
            out.append(cap)
        except QuizError:
            log.exception("quizzes: %s is present but unusable; excluding it", cap)
    return out


def grade(capability, answers, doc=None):
    """Grade a submission. Returns a result dict; never raises on wrong answers.

    `answers` maps question id -> chosen option index. A missing or unparseable
    answer is WRONG, never skipped: skipping would let a submission that omitted
    every hard question score 100%.
    """
    doc = doc if doc is not None else load(capability)
    questions = doc["questions"]
    answers = answers if isinstance(answers, dict) else {}
    wrong = []
    for q in questions:
        given = answers.get(q["id"])
        if not isinstance(given, int) or isinstance(given, bool) \
                or given != q["correct"]:
            wrong.append({"id": q["id"], "why": q["why"],
                          "correct": q["correct"]})
    total = len(questions)
    score = int(round(100.0 * (total - len(wrong)) / total)) if total else 0
    # Passing is "nothing wrong", NOT "score >= PASS_MARK". With 3 questions a
    # rounded 2/3 is 67, but with 200 questions a single wrong answer rounds to
    # 100 -- and a rounding artefact must never unlock a dangerous capability.
    passed = not wrong
    return {"passed": passed, "score": score, "total": total,
            "wrong": wrong, "version": effective_version(capability, doc)}
