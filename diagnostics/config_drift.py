"""Check: config drift — does the documentation still describe the code?

THE BUG CLASS THIS EXISTS FOR
    Anything that RESTATES a constant becomes a second source of truth, and a
    second source of truth desyncs by default — the only question is when someone
    notices. This repo has the failure on record twice:

      * ARCHITECTURE.md documented the approval model as "Teaching Mode /
        Automated Mode" with a LOW/MEDIUM/HIGH vocabulary appearing nowhere in
        the tree, describing an execution path that did not exist, while the code
        shipped an entirely different design.
      * The Settings page hardcodes a model name in its own prose while the
        engine calls whatever `_ACTIVE_MODEL` says. One of the two is wrong at
        any moment and neither knows about the other.

    Neither breaks anything. Both make the product describe itself incorrectly to
    the person relying on the description, which for a security tool is its own
    kind of failure.

WHAT IT COMPARES
    * the action classes named in ARCHITECTURE.md  vs  ACTION_CLASS_CEILINGS
    * model names written into user-facing prose   vs  the engine's active model

WHY IT READS NAMED FILES RATHER THAN GREPPING THE TREE
    Two sibling diagnostics were caught matching their OWN fixtures: the DDL
    scanner found the example in its docstring, and the dependency scanner found
    the fake binary in its canary. Any check that greps the tree for a pattern it
    also has to WRITE will match itself.

    Here the action-class comparison reads two specific files, which cannot
    self-match. The model comparison does scan prose, so every fixture in this
    module is assembled at runtime and the module excludes its own source and the
    `diagnostics/` package from that scan — verified by a canary case, not
    assumed.

Read-only: parses files. Executes nothing.
"""

import os
import re
import sys

try:                                    # normal package import
    from . import canary as _canary_harness
except ImportError:                     # loaded by file path (tests, direct run)
    # The checks are documented as independently runnable, and the test suites
    # load them via spec_from_file_location -- neither has package context, so a
    # bare relative import fails. Falling back keeps all three entry points
    # working: `import diagnostics`, `python3 -m diagnostics.<id>`, and a direct
    # path load.
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import canary as _canary_harness

META = {
    "id": "config_drift",
    "name": "Documentation Drift",
    "icon": "📐",
    "descriptions": {
        "beginner": "Checks that what the documentation and settings pages SAY "
                    "about Nemesis still matches what the software actually does "
                    "— for example the AI model named on screen versus the one "
                    "really being used.",
        "intermediate": "Compares ARCHITECTURE.md's documented action classes "
                        "against ACTION_CLASS_CEILINGS, and model names written "
                        "into user-facing prose against the engine's active "
                        "model constant.",
        "pro": "Second-source-of-truth audit. Named-file comparison for the "
               "authority ladder; prose scan for stale model identifiers, "
               "excluding this package so the check cannot match its own "
               "fixtures.",
    },
}

_OK = "ok"
_DRIFT = "drift"
_PROBE_FAILED = "probe-failed"
_TAGS = {_OK: "OK", _DRIFT: "DRIFT", _PROBE_FAILED: "PROBE-FAILED"}


def _section(label, state, detail=""):
    """One labeled line. An unrecognised state raises rather than rendering OK."""
    return f"[{_TAGS[state]}] {label}" + (f": {detail}" if detail else "")


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── Action classes: doc vs code ──────────────────────────────────────────────

#: Keys of the ACTION_CLASS_CEILINGS literal in the engine.
_CEILINGS_BLOCK_RE = re.compile(r"ACTION_CLASS_CEILINGS\s*=\s*\{(.*?)\n\}", re.S)
_CEILING_KEY_RE = re.compile(r'"([a-z][a-z0-9_]*)"\s*:')

#: An action class mentioned in prose, written as `code` in markdown.
_DOC_CLASS_RE = re.compile(r"`([a-z][a-z0-9_]*)`")


def code_action_classes(source):
    """Class names declared in the code. Returns a set, or None if not found.

    None (not an empty set) because "the literal moved or was renamed" and "there
    are genuinely no action classes" are different facts, and an empty set would
    make a failed parse look like a real measurement — then the comparison would
    report every documented class as undocumented-in-code.
    """
    m = _CEILINGS_BLOCK_RE.search(source)
    if not m:
        return None
    keys = set(_CEILING_KEY_RE.findall(m.group(1)))
    return keys or None


def doc_action_classes(doc_text, known):
    """Which KNOWN class names the doc mentions.

    Intersected with the code's set on purpose. The doc is prose full of
    backticked identifiers — function names, table names, settings keys — and
    treating every one as a claimed action class would report dozens of phantom
    drifts. So this answers "which of the real classes does the doc discuss",
    which is the question that matters: a class the doc never mentions is
    undocumented.
    """
    mentioned = set(_DOC_CLASS_RE.findall(doc_text))
    return mentioned & set(known)


# ── Model identifiers: prose vs the engine ───────────────────────────────────

_ACTIVE_MODEL_RE = re.compile(r'_ACTIVE_MODEL\s*=\s*["\']([A-Za-z0-9._-]+)["\']')

#: A model identifier as written in USER-FACING prose. Deliberately matches the
#: human spelling (vendor name, family, dotted version) as well as the API id
#: form, because the Settings page uses the former and that is where the known
#: drift is.
#:
#: NOTE the example is DESCRIBED rather than spelled. Writing one out here makes
#: this file match its own regex, and then the check depends entirely on the
#: `diagnostics` directory exclusion below to avoid reporting itself — a single
#: point of failure that silently becomes a false positive the moment this file
#: moves or that exclusion is edited. Two sibling checks shipped exactly that
#: bug. Keep both defences independent: assembled fixtures AND the exclusion.
_MODEL_PROSE_RE = re.compile(
    r"Claude\s+(Opus|Sonnet|Haiku)\s+([0-9][0-9.]*)", re.IGNORECASE)


def active_model(source):
    """The model the engine actually calls, or None if the constant is not found."""
    m = _ACTIVE_MODEL_RE.search(source)
    return m.group(1) if m else None


def normalise_model(family, version):
    """('Sonnet', '4.6') -> 'claude-sonnet-4-6', matching the API id spelling."""
    return "claude-%s-%s" % (family.lower(), version.replace(".", "-"))


#: Paths excluded from the prose scan. This package is excluded so the check
#: cannot match its own fixtures — the trap that caught two sibling diagnostics.
_SCAN_SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv",
                   "diagnostics"}
_SCAN_EXT = (".py", ".md", ".html")

#: A model name appearing as a DICT KEY is a lookup table, not a claim.
#: `_DOC_NAME_TO_ID` and `_MODEL_RATES` legitimately enumerate every model the
#: engine knows how to price — reporting each as "the product names the wrong
#: model" is precisely wrong, and the first run produced four such findings
#: against one real one. A table that lists many models asserts nothing about
#: which one is active.
_TABLE_ENTRY_RE = re.compile(r'^\s*["\'][^"\']*["\']\s*:')

#: Test files quote the drift they exist to catch — `test_authority_doc.py`
#: names the stale model in its own docstring, describing the bug rather than
#: committing it. Scanning them turns every regression guard into a finding.
_TEST_PATH_HINTS = ("/test_", "test_", "/tests/")


def scan_model_prose(root, active, opener=None):
    """[(relpath, written_id, raw)] for prose naming a model other than `active`.

    Only DIFFERENCES are returned — prose naming the active model is correct and
    is not a finding.
    """
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SCAN_SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(_SCAN_EXT):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if any(h in "/" + rel for h in _TEST_PATH_HINTS):
                continue                     # tests quote the bug on purpose
            try:
                text = opener(path) if opener else open(
                    path, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if "laude" not in text:          # cheap prefilter, case-tolerant
                continue
            for line in text.splitlines():
                if _TABLE_ENTRY_RE.match(line):
                    continue                 # a lookup table, not a claim
                for m in _MODEL_PROSE_RE.finditer(line):
                    written = normalise_model(m.group(1), m.group(2))
                    if written != active:
                        out.append((rel, written, m.group(0)))
    return out


def compare_classes(code_set, doc_set):
    """Pure comparison. Returns {undocumented, phantom}."""
    return {"undocumented": sorted(code_set - doc_set),
            "phantom": sorted(doc_set - code_set)}


# ── Canary ───────────────────────────────────────────────────────────────────

def _fixture_model_prose(family, version):
    """Prose naming a model, ASSEMBLED so this file never contains the literal.

    `scan_model_prose` walks the tree; if this module wrote a model name plainly
    it would match itself and report a phantom drift on every production run.
    Two sibling diagnostics shipped exactly that bug before it was noticed here.
    """
    return "%s %s %s" % ("Cl" + "aude", family, version)


def _canary():
    """Returns (ok, detail). Never raises. Runs on EVERY invocation."""
    try:
        # --- action classes -------------------------------------------------
        src_ok = 'ACTION_CLASS_CEILINGS = {\n    "alpha": 1,\n    "beta": 2,\n}'
        got = code_action_classes(src_ok)
        if got != {"alpha", "beta"}:
            return False, "class keys were not parsed from the code literal (%r)" % got
        # A missing literal must yield None, never an empty set.
        if code_action_classes("nothing here") is not None:
            return False, ("a missing ACTION_CLASS_CEILINGS parsed as a real "
                           "(empty) answer -- every documented class would then "
                           "report as phantom")
        # ...and so must a literal that is PRESENT but yields no keys. This is a
        # distinct path from the one above (that one short-circuits on the block
        # regex; this one reaches the key parse and finds nothing), and it is the
        # one that fires if the key regex stops matching after a formatting
        # change. Added because a mutation test proved the canary never exercised
        # it -- the earlier guard was absorbing both cases in the test but only
        # one of them in production.
        for empty in ("ACTION_CLASS_CEILINGS = {\n}",
                      "ACTION_CLASS_CEILINGS = {\n    # only a comment\n}"):
            if code_action_classes(empty) is not None:
                return False, ("an ACTION_CLASS_CEILINGS literal with no parseable "
                               "keys returned an empty set instead of None -- a "
                               "failed parse would present as 'there are no action "
                               "classes' and report every documented one as phantom")

        known = {"alpha", "beta"}
        if doc_action_classes("mentions `alpha` only", known) != {"alpha"}:
            return False, "doc mention parsing failed"
        # Backticked identifiers that are NOT action classes must be ignored, or
        # the doc's ordinary prose becomes dozens of phantom findings.
        if doc_action_classes("`some_function` and `alpha`", known) != {"alpha"}:
            return False, "an unrelated backticked identifier was treated as a class"

        cmp_clean = compare_classes({"alpha"}, {"alpha"})
        if cmp_clean["undocumented"] or cmp_clean["phantom"]:
            return False, "a matching doc/code pair reported drift"
        if compare_classes({"alpha", "beta"}, {"alpha"})["undocumented"] != ["beta"]:
            return False, "a class missing from the doc was not reported"
        if compare_classes({"alpha"}, {"alpha", "ghost"})["phantom"] != ["ghost"]:
            return False, "a class the doc invents was not reported"

        # --- model prose ----------------------------------------------------
        if active_model('_ACTIVE_MODEL = "claude-x-9"') != "claude-x-9":
            return False, "the active-model constant was not parsed"
        if active_model("no constant here") is not None:
            return False, ("a missing _ACTIVE_MODEL parsed as a real answer -- "
                           "every model mention would then look like drift")
        if normalise_model("Sonnet", "4.6") != "claude-sonnet-4-6":
            return False, "model normalisation is wrong"

        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "page.py"), "w") as fh:
                fh.write('label = "%s"\n' % _fixture_model_prose("Sonnet", "4.6"))
            with open(os.path.join(d, "ok.py"), "w") as fh:
                fh.write('label = "%s"\n' % _fixture_model_prose("Sonnet", "5"))
            hits = scan_model_prose(d, "claude-sonnet-5")
            written = {h[1] for h in hits}
            if "claude-sonnet-4-6" not in written:
                return False, "a stale model name in prose was not detected"
            if "claude-sonnet-5" in written:
                return False, ("prose naming the ACTIVE model was reported as "
                               "drift -- correct documentation would be a finding")

            # SELF-REFERENCE: this package must be excluded from the prose scan.
            os.makedirs(os.path.join(d, "diagnostics"), exist_ok=True)
            with open(os.path.join(d, "diagnostics", "self.py"), "w") as fh:
                fh.write('label = "%s"\n' % _fixture_model_prose("Opus", "1.0"))
            hits2 = scan_model_prose(d, "claude-sonnet-5")
            if any("diagnostics" in h[0] for h in hits2):
                return False, ("the diagnostics package was scanned -- this check "
                               "would match its own fixtures, the trap that hit "
                               "two sibling checks")

            # A LOOKUP TABLE enumerating models is not a claim about the active
            # one. The first run reported four entries of `_DOC_NAME_TO_ID` as
            # drift against a single real finding.
            with open(os.path.join(d, "table.py"), "w") as fh:
                fh.write('RATES = {\n    "%s": 1,\n    "%s": 2,\n}\n'
                         % (_fixture_model_prose("Opus", "4.8").lower(),
                            _fixture_model_prose("Haiku", "4.5").lower()))
            hits3 = scan_model_prose(d, "claude-sonnet-5")
            if any(h[0] == "table.py" for h in hits3):
                return False, ("a model lookup table was reported as drift -- a "
                               "table that lists many models asserts nothing "
                               "about which is active")
            # ...and a TEST file quoting a stale name is describing the bug.
            with open(os.path.join(d, "test_quotes.py"), "w") as fh:
                fh.write('DOC = "%s"\n' % _fixture_model_prose("Sonnet", "4.6"))
            hits4 = scan_model_prose(d, "claude-sonnet-5")
            if any("test_quotes" in h[0] for h in hits4):
                return False, ("a test file was scanned -- every regression guard "
                               "that names the bug becomes a finding")
            # CONTROL: the real finding must still survive all that filtering.
            if not any(h[0] == "page.py" for h in hits4):
                return False, ("the genuine stale-model finding was filtered away "
                               "along with the false positives")
        return True, "known-good and 10 known-bad cases behaved correctly"
    except Exception as e:                                   # noqa: BLE001
        return False, "canary itself failed: %s: %s" % (type(e).__name__, e)


# ── Run ──────────────────────────────────────────────────────────────────────

_DOC_REL = "ARCHITECTURE.md"
_ENGINE_REL = os.path.join("modules", "ai_engine", "module.py")


def run() -> dict:
    """Entry point. The harness runs the canary and suppresses the
    verdict entirely if it fails -- see diagnostics/canary.py."""
    return _canary_harness.guard(META, _canary, _produce,
                                 subject="documentation")


def _produce(detail):
    sections = [_section("canary self-test", _OK, detail)]
    root = _repo_root()
    status = _OK
    findings = 0

    try:
        with open(os.path.join(root, _ENGINE_REL), encoding="utf-8",
                  errors="replace") as fh:
            engine_src = fh.read()
        with open(os.path.join(root, _DOC_REL), encoding="utf-8",
                  errors="replace") as fh:
            doc_text = fh.read()
    except OSError as e:
        return {
            "id": META["id"], "name": META["name"], "icon": META["icon"],
            "status": "error",
            "summary": "Could not read the files being compared",
            "output": "\n".join(sections + [
                _section("source read", _PROBE_FAILED,
                         "%s: %s" % (type(e).__name__, os.path.basename(
                             getattr(e, "filename", "") or "?")))]),
        }

    code_set = code_action_classes(engine_src)
    if code_set is None:
        # A failed parse must not present as "the doc invents everything".
        sections.append(_section(
            "action classes", _PROBE_FAILED,
            "ACTION_CLASS_CEILINGS could not be parsed from the engine — the "
            "authority comparison did NOT run (this is not a clean result)"))
        status = _DRIFT
        findings += 1
    else:
        doc_set = doc_action_classes(doc_text, code_set)
        cmp_ = compare_classes(code_set, doc_set)
        sections.append(_section(
            "action classes in the code", _OK,
            "%d declared, %d described in %s" % (len(code_set), len(doc_set), _DOC_REL)))
        if cmp_["undocumented"]:
            status = _DRIFT
            findings += len(cmp_["undocumented"])
            sections.append(_section(
                "action classes the documentation never mentions", _DRIFT,
                "%d: %s" % (len(cmp_["undocumented"]),
                            ", ".join(cmp_["undocumented"]))))
        else:
            sections.append(_section("every action class is documented", _OK))

    active = active_model(engine_src)
    if active is None:
        sections.append(_section(
            "active model", _PROBE_FAILED,
            "_ACTIVE_MODEL could not be parsed — the model comparison did NOT run"))
        status = _DRIFT
        findings += 1
    else:
        stale = scan_model_prose(root, active)
        sections.append(_section("model the engine calls", _OK, active))
        if stale:
            status = _DRIFT
            findings += len(stale)
            lines = ["%s: says %s" % (rel, raw) for rel, _w, raw in stale]
            sections.append(_section(
                "user-facing text naming a different model", _DRIFT,
                "%d — the product describes itself incorrectly:\n    %s"
                % (len(lines), "\n    ".join(lines))))
        else:
            sections.append(_section("no stale model names in prose", _OK))

    return {
        "id": META["id"], "name": META["name"], "icon": META["icon"],
        "status": "warn" if status == _DRIFT else "ok",
        "summary": ("%d documentation drift(s) found" % findings) if findings
                   else "Documentation matches the code",
        "output": "\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
