#!/usr/bin/env python3
"""Attachment facts reach `fast_check.signals()` -- as FACTS, never as a verdict.

⛔ WHY THIS EXISTS. `mime_parse` computed `executable_extension` and
`type_extension_mismatch` per attachment correctly, and NOTHING CONSUMED THEM.
`signals()` returned three keys and never looked at `parsed.attachments`, so the
facts were computed and dropped at the scorer boundary. Measured 2026-09-05
against the live DB: across 169 recorded verdicts, ZERO mention attachments.

⛔ AND THEY STAY FACTS. `verdict`/`confidence`/`reason` remain NULL. fast_check
deliberately returns no verdict (supervisor.py's comment: combining signals is a
separate decision with its own D9 measurement requirement), and this change does
not touch that. A test below pins it.

⛔ SUBSTRATE IS THE POINT, NOT A FORMALITY. D9 classified `risky_attachment`
INERT -- "never fired on any population; recorded as untested, not clean" -- as
distinct from the many signals it REJECTED for firing on legitimate mail. It was
never exercised, not disproven. So "no attachment" must report substrate=False
(not tested), never fired=False with substrate=True (tested and clean). Those two
look identical in a results table, which is the whole reason the field exists.

Run:  python3 modules/email_security/test_attachment_signals.py
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import fast_check                                              # noqa: E402
import mime_parse                                              # noqa: E402
from fast_check import signals, SIGNAL_PROVENANCE              # noqa: E402

EXPECTED_CHECKS = 22
_results = []


def check(label, got, want=True):
    _results.append((got == want, label, got, want))


class _P:
    """A ParsedMessage stand-in. Deliberately mirrors the shape signals() reads."""
    def __init__(self, attachments=None, with_attr=True):
        self.headers = {"subject": "", "authentication_results": [], "from": ""}
        self.body_html = ""
        self.urls = []
        self.problems = []
        self.truncated = False
        if with_attr:
            self.attachments = attachments or []


def att(ext, declared, mismatch, tested):
    """One attachment dict, shaped as mime_parse emits it."""
    return {"name_hash": "deadbeef", "extension": ext, "declared_type": declared,
            "sha256": "x" * 64, "size": 100,
            "executable_extension": ext in mime_parse.EXECUTABLE_EXTENSIONS,
            "type_extension_mismatch": mismatch,
            "type_mismatch_tested": tested}


def main():
    EXE = "executable_attachment"
    MIS = "attachment_type_mismatch"

    # ── no attachments AT ALL: not tested, never "clean" ─────────────────────
    none_ = signals(_P([]))
    check("no attachments: %s present" % EXE, EXE in none_)
    check("no attachments: %s does not fire" % EXE, none_[EXE]["fired"], False)
    check("no attachments: %s substrate is False (NOT TESTED)" % EXE,
          none_[EXE]["substrate"], False)
    check("no attachments: %s does not fire" % MIS, none_[MIS]["fired"], False)
    check("no attachments: %s substrate is False (NOT TESTED)" % MIS,
          none_[MIS]["substrate"], False)

    # A message object with NO `attachments` ATTRIBUTE must not raise: the
    # import-time selftest builds exactly such an object.
    try:
        noattr = signals(_P(with_attr=False))
        check("a parsed object with no .attachments does not raise",
              noattr[EXE]["substrate"], False)
    except Exception as exc:                                    # noqa: BLE001
        check("a parsed object with no .attachments does not raise",
              "raised %s" % type(exc).__name__, False)

    # ── a benign pdf: TESTED, and clean ─────────────────────────────────────
    pdf = signals(_P([att("pdf", "application/pdf", False, True)]))
    check("benign pdf: %s does not fire" % EXE, pdf[EXE]["fired"], False)
    check("benign pdf: %s substrate is True (TESTED)" % EXE,
          pdf[EXE]["substrate"], True)
    check("benign pdf: %s does not fire" % MIS, pdf[MIS]["fired"], False)

    # ── an executable extension ─────────────────────────────────────────────
    exe = signals(_P([att("exe", "application/x-msdownload", False, True)]))
    check("exe attachment: %s fires" % EXE, exe[EXE]["fired"], True)
    check("exe attachment: %s substrate is True" % EXE, exe[EXE]["substrate"], True)

    # ── a declared-type / extension contradiction ───────────────────────────
    mis = signals(_P([att("exe", "application/pdf", True, True)]))
    check("mismatch attachment: %s fires" % MIS, mis[MIS]["fired"], True)
    check("mismatch attachment: %s substrate is True" % MIS,
          mis[MIS]["substrate"], True)

    # ── a NON-TESTABLE mismatch: generic declared type ──────────────────────
    # octet-stream is the absence of a claim. The mismatch signal was not
    # tested; the executable-extension signal still was.
    gen = signals(_P([att("dat", "application/octet-stream", False, False)]))
    check("octet-stream: %s substrate is False (no claim to contradict)" % MIS,
          gen[MIS]["substrate"], False)
    check("octet-stream: %s substrate is still True" % EXE,
          gen[EXE]["substrate"], True)

    # ── CONTROLS: the instrument produces different answers ─────────────────
    check("CONTROL: fired differs between an exe and a pdf",
          exe[EXE]["fired"] != pdf[EXE]["fired"], True)
    check("CONTROL: substrate differs between no-attachment and a pdf",
          none_[EXE]["substrate"] != pdf[EXE]["substrate"], True)

    # ── SHAPE: the import-time selftest iterates values and reads ["fired"] ──
    for name, sig in exe.items():
        if "fired" not in sig:
            check("every signal value carries 'fired' (selftest contract)",
                  "missing on %s" % name, True)
            break
    else:
        check("every signal value carries 'fired' (selftest contract)", True)
    check("new entries carry exactly fired+substrate, both bool",
          all(set(exe[k]) == {"fired", "substrate"}
              and isinstance(exe[k]["fired"], bool)
              and isinstance(exe[k]["substrate"], bool) for k in (EXE, MIS)))

    # ── REGRESSION: the three existing signals are untouched ────────────────
    check("the three D9-cleared signals still present and unchanged",
          all(k in pdf for k in ("has_form", "urgent_subject", "url_shortener"))
          and pdf["has_form"] == {"fired": False, "substrate": False})

    # ── the import-time canary still passes ─────────────────────────────────
    ok, detail = fast_check.selftest()
    check("fast_check.selftest() passes: %s" % detail, ok, True)

    # ── provenance: traceable, and honestly marked as NOT D9-cleared ────────
    check("provenance recorded for both new signals",
          EXE in SIGNAL_PROVENANCE and MIS in SIGNAL_PROVENANCE)
    check("...and both are marked not-D9-cleared, not given a fake FP rate",
          SIGNAL_PROVENANCE[EXE].get("status") in ("inert", "unmeasured")
          and SIGNAL_PROVENANCE[MIS].get("status") in ("inert", "unmeasured"))

    # ── mime_parse records whether the mismatch check was testable ──────────
    parsed = mime_parse.parse(
        b"From: a@example.com\r\nTo: b@example.org\r\nSubject: s\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="x.pdf"\r\n\r\nJVBERi0K\r\n'
        b"--B--\r\n")
    check("mime_parse emits type_mismatch_tested on each attachment",
          bool(parsed.attachments) and "type_mismatch_tested" in parsed.attachments[0])

    # ── verdict stays None: this change records facts, it does not judge ────
    src = open(os.path.join(_HERE, "supervisor.py")).read()
    check("supervisor still records verdict=None (no verdict was invented)",
          "verdict=None" in src)

    print("=" * 72)
    for ok_, label, got, want in _results:
        print("  %s  %s" % ("PASS" if ok_ else "FAIL", label))
        if not ok_:
            print("        got=%r want=%r" % (got, want))
    passed = sum(1 for r in _results if r[0])
    print("-" * 72)
    print("  %d/%d passed (expected %d checks)" % (passed, len(_results), EXPECTED_CHECKS))
    print("=" * 72)
    if len(_results) != EXPECTED_CHECKS:
        print("  ⛔ CHECK COUNT DRIFT: ran %d, expected %d" % (len(_results), EXPECTED_CHECKS))
        return 2
    return 0 if passed == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
