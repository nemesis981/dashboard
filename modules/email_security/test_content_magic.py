#!/usr/bin/env python3
"""Magic-byte content verification: does an attachment's CONTENT match its CLAIM?

⛔ WHAT THIS ADDS THAT THE EXISTING CHECK CANNOT DO. `_type_ext_mismatch`
compares the declared Content-Type against the filename extension. Both are
attacker-controlled CLAIMS, so the canonical attack passes it cleanly:
`invoice.pdf`, `Content-Type: application/pdf`, contents beginning `MZ`. Two
claims agreeing is not evidence about the bytes. This reads the bytes.

⛔ AND IT IS NOT A COMPLETE ANSWER -- the tests below pin the limits as
deliberately as the capabilities:
  * a POLYGLOT satisfies any single-signature test by construction
  * EMBEDDED content in a structurally valid host file is invisible
  * PK\\x03\\x04 cannot separate .docx from .jar from a plain archive
  * scripts (.js, .vbs, .bat, .ps1) have NO magic at all -- unverifiable
  * it detects CONTRADICTION, not malice

⛔ THE FALSE-POSITIVE TRAPS ARE THE POINT. A naive table calls `.msi` a PE (it
is OLE2), `.jar`/`.apk`/`.docx` non-archives (they are ZIP), and flags every
office document. Those cases are tested explicitly, because a check that cries
wolf on ordinary mail is worse than no check -- which is what D9 measured
repeatedly and what `_GENERIC_TYPES` already exists to prevent.

Run:  python3 modules/email_security/test_content_magic.py
"""
import base64
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import mime_parse                                              # noqa: E402
from fast_check import signals                                 # noqa: E402

EXPECTED_CHECKS = 38
_results = []


def check(label, got, want=True):
    _results.append((got == want, label, got, want))


# Minimal real headers for each family.
PE    = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 50
ELF   = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50
MACHO = b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 50
PDF   = b"%PDF-1.7\n1 0 obj\n" + b"x" * 40
ZIP   = b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 50
OLE2  = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 50
PNG   = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 40
JPEG  = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 40
GIF   = b"GIF89a\x01\x00\x01\x00" + b"\x00" * 40
RTF   = b"{\\rtf1\\ansi\\deff0" + b" " * 40
GZIP  = b"\x1f\x8b\x08\x00" + b"\x00" * 50
TEXT  = b"var x = 1;\nalert('hi');\n" + b"// padding\n" * 5


def att(raw, filename, ctype):
    """One attachment through the REAL parser -- never a hand-built dict."""
    msg = (b"From: a@example.com\r\nTo: b@example.org\r\nSubject: s\r\n"
           b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
           b"--B\r\nContent-Type: " + ctype.encode() + b"\r\n"
           b'Content-Disposition: attachment; filename="' + filename.encode() + b'"\r\n'
           b"Content-Transfer-Encoding: base64\r\n\r\n"
           + base64.b64encode(raw) + b"\r\n--B--\r\n")
    p = mime_parse.parse(msg)
    return (p.attachments[0] if p.attachments else {}), p


def main():
    # ── the detector itself ────────────────────────────────────────────────
    for raw, want, label in ((PE, "executable", "PE/MZ"), (ELF, "executable", "ELF"),
                             (MACHO, "executable", "Mach-O"), (PDF, "pdf", "PDF"),
                             (ZIP, "zip", "ZIP"), (OLE2, "ole2", "OLE2"),
                             (PNG, "png", "PNG"), (JPEG, "jpeg", "JPEG"),
                             (GIF, "gif", "GIF"), (RTF, "rtf", "RTF"),
                             (GZIP, "gzip", "GZIP")):
        check("_content_magic detects %s" % label, mime_parse._content_magic(raw), want)

    check("_content_magic returns None on script text (no magic exists)",
          mime_parse._content_magic(TEXT), None)
    check("_content_magic returns None on empty input",
          mime_parse._content_magic(b""), None)
    check("_content_magic does not crash on a 1-byte payload",
          mime_parse._content_magic(b"M"), None)

    # ── THE HEADLINE CASE: an executable wearing a .pdf name AND type ───────
    a, _ = att(PE, "invoice.pdf", "application/pdf")
    check("PE named .pdf: detected_type is executable", a.get("detected_type"), "executable")
    check("PE named .pdf: content_type_mismatch FIRES", a.get("content_type_mismatch"), True)
    check("PE named .pdf: the OLD extension check is blind to it "
          "(both claims agree)", a.get("type_extension_mismatch"), False)

    # ── agreement must NOT fire ─────────────────────────────────────────────
    for raw, fn, ct, label in ((PE, "setup.exe", "application/x-msdownload", "PE/.exe"),
                               (PDF, "report.pdf", "application/pdf", "PDF/.pdf"),
                               (PNG, "logo.png", "image/png", "PNG/.png"),
                               (JPEG, "photo.jpg", "image/jpeg", "JPEG/.jpg")):
        a, _ = att(raw, fn, ct)
        check("%s agrees -> no content mismatch" % label,
              a.get("content_type_mismatch"), False)

    # ── FALSE-POSITIVE TRAPS: correct answers that a naive table gets wrong ─
    a, _ = att(ZIP, "report.docx",
               "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    check("TRAP: .docx IS a zip -- no mismatch", a.get("content_type_mismatch"), False)
    a, _ = att(ZIP, "app.jar", "application/java-archive")
    check("TRAP: .jar IS a zip -- no mismatch", a.get("content_type_mismatch"), False)
    a, _ = att(OLE2, "book.xls", "application/vnd.ms-excel")
    check("TRAP: legacy .xls IS ole2 -- no mismatch", a.get("content_type_mismatch"), False)
    a, _ = att(OLE2, "installer.msi", "application/x-msi")
    check("TRAP: .msi is OLE2, NOT a PE -- no mismatch",
          a.get("content_type_mismatch"), False)

    # ── NOT TESTABLE cases must report substrate honestly ──────────────────
    a, _ = att(TEXT, "payload.js", "application/javascript")
    check("a script has no magic -> not testable", a.get("content_mismatch_tested"), False)
    check("...and therefore does not fire", a.get("content_type_mismatch"), False)
    a, _ = att(PE, "thing.xyz", "application/pdf")
    check("an unknown extension -> not testable", a.get("content_mismatch_tested"), False)

    # ── LIMITATION, pinned as a test so it is not mistaken for coverage ────
    # A ZIP-headed file named .pdf IS caught; a true polyglot (valid as both)
    # is not, by construction. This records which half we actually have.
    a, _ = att(ZIP, "statement.pdf", "application/pdf")
    check("LIMITATION: a zip-headed .pdf is caught (single-signature only)",
          a.get("content_type_mismatch"), True)

    # ── end-to-end into signals() ──────────────────────────────────────────
    _, parsed = att(PE, "invoice.pdf", "application/pdf")
    sig = signals(parsed)
    check("signals() emits attachment_content_mismatch",
          "attachment_content_mismatch" in sig)
    check("...and it FIRES on the PE-as-pdf message",
          sig["attachment_content_mismatch"]["fired"], True)
    check("...with substrate True", sig["attachment_content_mismatch"]["substrate"], True)
    _, clean_p = att(PDF, "report.pdf", "application/pdf")
    check("...and does NOT fire on a genuine pdf",
          signals(clean_p)["attachment_content_mismatch"]["fired"], False)
    _, script_p = att(TEXT, "x.js", "application/javascript")
    check("...and reports substrate False when nothing was verifiable",
          signals(script_p)["attachment_content_mismatch"]["substrate"], False)

    # ── STRUCTURAL invariants of the table itself ──────────────────────────
    # Longest-first ordering is currently UNOBSERVABLE -- no signature is a
    # prefix of another, so no result can change with sort order. It is
    # future-proofing, and a structural assertion is the only thing that can
    # protect it, because no behavioural test can (verified by mutation: the
    # ordering mutant is equivalent today).
    lens = [len(sig) for sig, _ in mime_parse._MAGIC_BY_LENGTH]
    check("signatures are matched longest-first", lens == sorted(lens, reverse=True))
    # ...and the invariant that makes the above merely defensive rather than
    # load-bearing. If someone adds a signature that IS a prefix of another, this
    # fails loudly instead of silently making match order significant.
    sigs = [sig for sig, _ in mime_parse._MAGIC_SIGNATURES]
    check("no signature is a prefix of another",
          [(a, b) for a in sigs for b in sigs if a != b and b.startswith(a)], [])

    # ── CONTROL ────────────────────────────────────────────────────────────
    check("CONTROL: the detector gives different answers for different inputs",
          mime_parse._content_magic(PE) != mime_parse._content_magic(PDF), True)

    # ── the docstring claim is no longer stale ─────────────────────────────
    src = open(os.path.join(_HERE, "mime_parse.py")).read()
    check("the module docstring's magic-byte claim is now backed by code",
          "def _content_magic" in src)

    print("=" * 72)
    for ok, label, got, want in _results:
        print("  %s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            print("        got=%r want=%r" % (got, want))
    passed = sum(1 for r in _results if r[0])
    print("-" * 72)
    print("  %d/%d passed (expected %d)" % (passed, len(_results), EXPECTED_CHECKS))
    print("=" * 72)
    if len(_results) != EXPECTED_CHECKS:
        print("  ⛔ CHECK COUNT DRIFT: ran %d, expected %d" % (len(_results), EXPECTED_CHECKS))
        return 2
    return 0 if passed == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
