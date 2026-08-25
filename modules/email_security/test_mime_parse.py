#!/usr/bin/env python3
"""Tests + fuzzer for the MIME parser. ADR 0028, build spec Stage 2.3.

Run: python3 test_mime_parse.py     (exit 0 = all pass)

THE BUILD SPEC REQUIRES FUZZING HERE, IN THOSE WORDS
    "Treat parser-differential attacks as a real threat class, not a footnote:
     fuzz against malformed/nested/oversized MIME before trusting it against a
     real corpus."

    Section 4 is that fuzzer. Its single invariant is that `parse()` NEVER
    RAISES -- because a parser that raises on hostile input hands an attacker a
    denial of service: one malformed message stops the pipeline for every
    message queued behind it. Every fuzz case asserts a ParsedMessage came
    back, whatever state it is in.

    Section 5 then does what the spec says comes after: runs the parser against
    REAL mail from the D9 corpus, since a fuzzer proves robustness against
    invented malformation and real mail is malformed in ways nobody invents.

NO NETWORK. Fuzz inputs are generated locally; the real-mail sample is read
from a local export and NOTHING from it is printed.
"""

import os
import random
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import mime_parse                                            # noqa: E402
from mime_parse import parse, ParsedMessage                  # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


print("-- 1. The canary --")
ok, detail = mime_parse.selftest()
check("selftest passes", ok, detail)

print("\n-- 2. Extraction on well-formed mail --")
m = parse(b"From: a@example.com\r\nSubject: s\r\n\r\nhi http://a.example/1 "
          b"and http://b.example/2\r\n")
check("From extracted", m.headers["from"] == "a@example.com", m.headers["from"])
check("two URLs extracted", len(m.urls) == 2, m.urls)
check("parsed_cleanly is True on clean input", m.parsed_cleanly, m.problems)
check("absent header is None, not empty string",
      m.headers["reply_to"] is None,
      "absent and empty are different facts")

print("\n-- 3. Failure is REPORTED, never silent --")
for label, raw, expect in [
    ("empty input", b"", "empty_input"),
    ("non-bytes input", "a str", "input_not_bytes"),
    ("headerless prose", b"just prose, no headers at all", "no_headers"),
]:
    r = parse(raw)
    check("%s -> problem recorded" % label,
          any(expect in p for p in r.problems), r.problems)
    check("...and parsed_cleanly is False", not r.parsed_cleanly)

print("\n-- 4. FUZZ: parse() must NEVER raise (build-spec requirement) --")

random.seed(20260825)          # deterministic: a fuzz failure must reproduce


def fuzz_cases():
    """Malformed, nested and oversized MIME, per the spec's three categories."""
    yield "deep nesting", _nested(60)
    yield "part explosion", _many_parts(400)
    yield "unterminated boundary", (
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\n'
        b"Content-Type: text/plain\r\n\r\nno terminator")
    yield "boundary that never appears", (
        b'Content-Type: multipart/mixed; boundary="NOPE"\r\n\r\nbody')
    yield "empty boundary", (
        b'Content-Type: multipart/mixed; boundary=""\r\n\r\n--\r\nx')
    yield "null bytes in body", b"From: a@b.c\r\n\r\n" + b"\x00" * 500
    yield "null bytes in header", b"From: a\x00b@c.d\r\nSubject: x\r\n\r\nbody"
    yield "header with no colon", b"NotAHeaderAtAll\r\nFrom: a@b.c\r\n\r\nbody"
    yield "enormous single header", b"X-Big: " + b"A" * 200000 + b"\r\n\r\nbody"
    yield "enormous header count", b"".join(
        b"X-H%d: v\r\n" % i for i in range(5000)) + b"\r\nbody"
    yield "truncated mid-header", b"From: a@b.c\r\nSubject: unfinis"
    yield "bare CR only", b"From: a@b.c\rSubject: s\r\rbody"
    yield "bare LF only", b"From: a@b.c\nSubject: s\n\nbody"
    yield "invalid base64 payload", (
        b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        b"!!!!not base64!!!!")
    yield "invalid charset", (
        b'Content-Type: text/plain; charset="not-a-real-charset"\r\n\r\nbody')
    yield "invalid utf-8 bytes", b"From: a@b.c\r\n\r\n" + bytes([0xC3, 0x28] * 200)
    yield "attachment, no filename", (
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment\r\n\r\nDATA")
    yield "filename with traversal", (
        b"Content-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="../../../etc/passwd"\r\n\r\nX')
    yield "filename with null", (
        b"Content-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="a\x00.pdf"\r\n\r\nX')
    yield "URL flood", b"From: a@b.c\r\n\r\n" + b"http://x.example/a " * 2000
    yield "oversized message", b"From: a@b.c\r\n\r\n" + b"A" * (
        mime_parse.MAX_MESSAGE_BYTES + 5000)
    # Purely random bytes: the case nobody designs for.
    for i in range(40):
        yield ("random bytes #%d" % i,
               bytes(random.getrandbits(8) for _ in range(random.randint(1, 3000))))


def _nested(depth):
    body = b"innermost"
    for d in range(depth):
        b_ = b"B%d" % d
        body = (b'Content-Type: multipart/mixed; boundary="' + b_ + b'"\r\n\r\n'
                b"--" + b_ + b"\r\n" + body + b"\r\n--" + b_ + b"--\r\n")
    return b"From: a@b.c\r\n" + body


def _many_parts(n):
    parts = b"".join(b"--B\r\nContent-Type: text/plain\r\n\r\npart%d\r\n" % i
                     for i in range(n))
    return (b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
            + parts + b"--B--\r\n")


raised = []
returned_wrong = []
n_fuzz = 0
for label, raw in fuzz_cases():
    n_fuzz += 1
    try:
        r = parse(raw)
        if not isinstance(r, ParsedMessage):
            returned_wrong.append(label)
    except Exception as exc:                                   # noqa: BLE001
        raised.append((label, type(exc).__name__))

check("parse() never raised across %d fuzz cases" % n_fuzz, not raised, raised)
check("...and always returned a ParsedMessage", not returned_wrong, returned_wrong)

print("\n-- 4b. Limits are ENFORCED and RECORDED (not silently truncated) --")
r = parse(_many_parts(400))
check("part limit enforced", len(r.parts) <= mime_parse.MAX_PARTS, len(r.parts))
check("...and recorded as a problem",
      any("part_limit" in p for p in r.problems), r.problems)
check("...and truncated flag set", r.truncated)
check("...so parsed_cleanly is False", not r.parsed_cleanly,
      "a truncated parse reported as clean understates structure in exactly "
      "the direction an attacker wants")

r = parse(b"From: a@b.c\r\n\r\n" + b"http://x.example/a " * 2000)
check("URL limit enforced", len(r.urls) <= mime_parse.MAX_URLS, len(r.urls))
check("...and recorded", any("url_limit" in p for p in r.problems), r.problems)

r = parse(b"From: a@b.c\r\n\r\n" + b"A" * (mime_parse.MAX_MESSAGE_BYTES + 5000))
check("size limit enforced and recorded",
      r.truncated and any("size_limit" in p for p in r.problems), r.problems)

print("\n-- 5. REAL MAIL (the spec's 'then a real corpus') --")
MBOX = os.path.expanduser(
    "~/gmailexport/Takeout/Mail/All mail Including Spam and Trash.mbox")
if not os.path.exists(MBOX):
    print("  [SKIP] real-mail corpus not present at the expected path")
else:
    import mailbox
    box = mailbox.mbox(MBOX, create=False)
    keys = list(box.keys())
    sample = keys[:400] + keys[len(keys) // 2:len(keys) // 2 + 400] + keys[-400:]
    crashed, n, clean, with_problems, with_attachments, with_urls = [], 0, 0, 0, 0, 0
    for k in sample:
        try:
            raw = box.get_bytes(k)
        except Exception:                                      # noqa: BLE001
            continue
        n += 1
        try:
            r = parse(raw)
        except Exception as exc:                               # noqa: BLE001
            crashed.append(type(exc).__name__)
            continue
        clean += bool(r.parsed_cleanly)
        with_problems += bool(r.problems)
        with_attachments += bool(r.attachments)
        with_urls += bool(r.urls)

    check("parse() never crashed on %d REAL messages" % n, not crashed, crashed)
    check("...and extracted URLs from a real share of them",
          with_urls > n * 0.5,
          "%d/%d had URLs — if this were ~0 the extractor would be inert "
          "while looking clean" % (with_urls, n))
    check("...and found attachments in some", with_attachments > 0,
          "%d/%d" % (with_attachments, n))
    print("      (real-mail sample: %d parsed, %d clean, %d with recorded "
          "problems, %d with attachments)" % (n, clean, with_problems,
                                              with_attachments))

print("\n-- 6. Attachment facts, not verdicts --")
m = parse(b"Content-Type: application/pdf\r\n"
          b'Content-Disposition: attachment; filename="invoice.exe"\r\n\r\nX')
a = m.attachments[0]
check("extension kept in the clear", a["extension"] == "exe", a)
check("filename HASHED, never stored in the clear",
      "invoice" not in str(a), a)
check("executable extension flagged as a FACT", a["executable_extension"])
check("declared-type vs extension mismatch detected",
      a["type_extension_mismatch"],
      "application/pdf declared, .exe extension — the parser-differential shape")

m = parse(b"Content-Type: application/octet-stream\r\n"
          b'Content-Disposition: attachment; filename="a.zip"\r\n\r\nX')
check("generic octet-stream is NOT a mismatch (absence of a claim)",
      not m.attachments[0]["type_extension_mismatch"],
      "flagging this would fire on a large share of ordinary mail")

# The executable branch, which the first implementation was blind to. Pinned
# across an extension NOT in _EXT_TYPE_HINTS, so coverage cannot silently
# depend on someone remembering to add a hints entry.
for ctype, fname, want, why in [
    (b"application/pdf", b"invoice.exe", True, "pdf declared on an .exe"),
    (b"image/png", b"photo.scr", True, ".scr is executable, png is not"),
    (b"text/plain", b"notes.js", True, ".js declared as text/plain"),
    (b"application/x-msdownload", b"setup.exe", False,
     "a genuine executable type on an .exe is NOT a contradiction"),
    (b"application/octet-stream", b"tool.exe", False,
     "generic type makes no claim to contradict"),
    (b"application/java-archive", b"app.jar", False, "correct type for .jar"),
]:
    r = parse(b"Content-Type: " + ctype + b"\r\n"
              b'Content-Disposition: attachment; filename="' + fname + b'"\r\n\r\nX')
    got = r.attachments[0]["type_extension_mismatch"]
    check("exec-mismatch: %s -> %s" % (why, want), got is want,
          "got %s for %s / %s" % (got, ctype, fname))

print("\n-- 7. MUTATION: prove the checks above can go red --")
_real = mime_parse._URL_RE
try:
    import re as _re
    mime_parse._URL_RE = _re.compile(rb"(?!x)x")     # matches nothing
    r = parse(b"From: a@b.c\r\n\r\nhttp://example.com/x")
    check("MUTANT (URL regex matches nothing): extraction goes silent",
          len(r.urls) == 0,
          "section 2 and section 5's URL-share check are what catch this")
finally:
    mime_parse._URL_RE = _real
check("CONTROL: real regex restored, URL found again",
      len(parse(b"From: a@b.c\r\n\r\nhttp://example.com/x").urls) == 1)

_real_max = mime_parse.MAX_PARTS
try:
    mime_parse.MAX_PARTS = 10 ** 9        # limit effectively removed
    r = parse(_many_parts(400))
    check("MUTANT (part limit removed): truncation no longer recorded",
          not any("part_limit" in p for p in r.problems),
          "section 4b is what catches this")
finally:
    mime_parse.MAX_PARTS = _real_max

print("\n-- 8. Scope boundary --")
import ast as _ast                                            # noqa: E402


def _code_only(path):
    tree = _ast.parse(open(path).read())
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.Module, _ast.ClassDef, _ast.FunctionDef)):
            if (node.body and isinstance(node.body[0], _ast.Expr)
                    and isinstance(node.body[0].value, _ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    return _ast.unparse(tree)


code = _code_only(os.path.join(_HERE, "mime_parse.py"))
check("no network access in CODE",
      not any(t in code for t in ("requests", "urllib", "httpx", "socket",
                                  "urlopen")),
      "URLs are extracted as text; visiting them is a separate sandboxed stage")
check("nothing writes to disk",
      "open(" not in code.replace("open(path)", ""),
      "attachments are hashed and measured, never written out")
check("nothing executes",
      not any(t in code for t in ("subprocess", "os.system", "eval(", "exec(")))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
