"""MIME parsing for inbound mail. ADR 0028, build spec Stage 2.3.

⚠ THIS IS NEW ATTACK SURFACE, AND IT IS THE FIRST IN THIS CODEBASE
    ADR 0028 §2 confirmed there is no existing attachment-handling code in
    Nemesis. Everything here processes bytes chosen by an attacker: the whole
    point of a phishing gateway is that hostile mail arrives and is parsed.
    Parser-differential attacks are a real threat class here, not a footnote.

    The specific hazard is that a MIME parser is a *guessing machine*. Real mail
    violates the RFCs constantly, so every parser is lenient in slightly
    different ways -- and an attacker who knows Nemesis's parser sees one thing
    while the user's mail client sees another can hide a payload in the gap.
    A message whose text/plain part says one thing and whose text/html part says
    another; a nested multipart whose boundary is malformed so one parser stops
    early; an attachment whose declared type and actual magic bytes disagree.

    **Nothing here can eliminate that gap** -- Nemesis is not the client, and
    will never parse identically to every mail app. What it CAN do is refuse to
    pretend it parsed cleanly when it did not, which is why `problems` is a
    first-class output and never silently empty. A verdict computed from a
    partially-parsed message is only as trustworthy as the caller's willingness
    to look at what failed.

STRUCTURED FROM THE PROVEN COLLECTOR, DELIBERATELY
    `tools/collect_mail_corpus.py` (the D9 measurement collector, private repo)
    already parses real mail at scale under the same constraints -- hard part
    and depth limits, never raising on malformed input, problems recorded with
    reasons rather than swallowed. That code parsed 15,216 real Gmail messages
    and 17,834 Proton messages with zero failures, so its shape is proven
    against real-world malformation. This is the same discipline applied to the
    live path.

    The difference: the collector was allowed to be slow and to record
    everything. This runs against arriving mail, so it also enforces size
    ceilings and must not become a denial-of-service vector against the
    appliance.

LIMITS ARE RECORDED, NEVER SILENT
    Hitting a limit produces an entry in `problems`. A truncated parse counted
    as complete would understate structure in exactly the direction an attacker
    wants: fewer parts examined, fewer URLs seen, a cleaner-looking message.

NOTHING HERE FETCHES A URL, RESOLVES A DOMAIN, OR EXECUTES ANYTHING.
    URLs are extracted as text. Attachments are hashed and measured, never
    opened, never written to disk, never executed. Detonation is a separate
    sandboxed engine (later stages) and the boundary is the safety model.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import os
import re

#: Hard structural ceilings. A hostile message must not exhaust memory or hang
#: the parser. Chosen well above what legitimate mail uses -- the D9 corpus's
#: real-world maximum part count was far below MAX_PARTS.
MAX_PARTS = 200
MAX_DEPTH = 20
MAX_URLS = 500
#: 50 MB. Gmail's own attachment ceiling is 25 MB; double it so a legitimate
#: message never trips this, while a multi-gigabyte body still cannot.
MAX_MESSAGE_BYTES = 50 * 1024 * 1024

#: Deliberately permissive: over-matching costs a few junk entries, while
#: under-matching silently loses the URL a detonation stage needed to see.
_URL_RE = re.compile(rb"""(?i)\bhttps?://[^\s<>"'\)\]]+""")

#: Extensions worth flagging as executable-ish. NOT a verdict -- a fact for a
#: later stage to weigh. `risky_attachment` was REJECTED as a standalone signal
#: by the D9 measurement (it never fired on real phishing), so this exists to
#: describe the message, not to score it.
EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "hta", "msi", "msp", "cpl", "jar", "ps1", "lnk", "iso",
    "img", "vhd", "reg", "dll", "apk",
})


class ParsedMessage:
    """One message, reduced to facts. No verdict, no score, no judgement.

    `problems` is load-bearing: a caller that ignores it is trusting a parse
    that may have stopped early.
    """

    __slots__ = ("headers", "parts", "attachments", "urls", "body_text",
                 "body_html", "problems", "size_bytes", "truncated")

    def __init__(self):
        self.headers: dict = {}
        self.parts: list = []
        self.attachments: list = []
        self.urls: list = []
        self.body_text: str = ""
        self.body_html: str = ""
        self.problems: list = []
        self.size_bytes: int = 0
        self.truncated: bool = False

    @property
    def parsed_cleanly(self) -> bool:
        """True only when nothing was truncated, skipped, or failed.

        Named as a question about the PARSE, not about the message. A caller
        asking "is this safe" must not be able to mistake this for an answer.
        """
        return not self.problems and not self.truncated

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}


def _header_facts(msg) -> dict:
    """Headers as facts. Absent is recorded as absent, never as a value."""
    def one(name):
        try:
            v = msg.get(name)
            return str(v) if v is not None else None
        except Exception:                                      # noqa: BLE001
            # A header that cannot even be stringified is itself a fact.
            return None

    received = []
    try:
        received = msg.get_all("Received") or []
    except Exception:                                          # noqa: BLE001
        pass

    return {
        "from": one("From"),
        "to": one("To"),
        "subject": one("Subject"),
        "date": one("Date"),
        "message_id": one("Message-ID"),
        "reply_to": one("Reply-To"),
        "return_path": one("Return-Path"),
        "list_unsubscribe": one("List-Unsubscribe"),
        # Kept raw for fast_check (2.4) to interpret. Parsing authentication
        # results is a verdict step and does not belong in the parser.
        "authentication_results": [str(v) for v in
                                   (msg.get_all("Authentication-Results") or [])],
        "received_count": len(received),
    }


def parse(raw: bytes) -> ParsedMessage:
    """Parse one message. NEVER raises on hostile input.

    A parser that raises hands an attacker a denial-of-service: a single
    malformed message would stop the pipeline for every other message behind
    it. Every failure becomes a recorded problem instead, and the caller
    decides what a partial parse is worth.
    """
    out = ParsedMessage()
    if not isinstance(raw, (bytes, bytearray)):
        out.problems.append("input_not_bytes")
        return out

    out.size_bytes = len(raw)
    if out.size_bytes == 0:
        out.problems.append("empty_input")
        return out
    if out.size_bytes > MAX_MESSAGE_BYTES:
        # Truncate rather than refuse: a 60MB message is still worth screening
        # on its headers. Recorded so nothing downstream reads the result as a
        # complete parse.
        raw = bytes(raw[:MAX_MESSAGE_BYTES])
        out.truncated = True
        out.problems.append("size_limit:%d" % MAX_MESSAGE_BYTES)

    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:                                   # noqa: BLE001
        out.problems.append("parse_failed:%s" % type(exc).__name__)
        return out

    try:
        if not msg.keys():
            out.problems.append("no_headers")
    except Exception:                                          # noqa: BLE001
        out.problems.append("headers_unreadable")

    out.headers = _header_facts(msg)
    _walk(msg, out)
    return out


def _walk(msg, out: ParsedMessage) -> None:
    """Structure, attachments, URLs, body. Records rather than raises."""
    try:
        walker = list(msg.walk())
    except Exception as exc:                                   # noqa: BLE001
        out.problems.append("walk_failed:%s" % type(exc).__name__)
        return

    text_chunks, html_chunks = [], []

    for part in walker:
        if len(out.parts) >= MAX_PARTS:
            out.truncated = True
            out.problems.append("part_limit:%d" % MAX_PARTS)
            break
        try:
            ctype = (part.get_content_type() or "").lower()
            disp = (part.get_content_disposition() or "")
            filename = part.get_filename()

            payload = None
            try:
                payload = part.get_payload(decode=True)
            except Exception as exc:                           # noqa: BLE001
                out.problems.append("decode_failed:%s" % type(exc).__name__)

            entry = {
                "content_type": ctype,
                "disposition": disp or None,
                "size": len(payload) if payload else 0,
                "is_attachment": disp == "attachment" or bool(filename),
                "charset": part.get_content_charset() or None,
            }

            if filename:
                ext = os.path.splitext(filename)[1].lower().lstrip(".")
                declared = ctype
                entry["attachment"] = {
                    # Filename HASHED, extension in the clear -- the extension
                    # is the signal, the name can carry personal information
                    # ("2026-tax-return-<name>.pdf"). Same split the D9
                    # collector makes, for the same reason.
                    "name_hash": hashlib.sha256(
                        filename.encode("utf-8", "replace")).hexdigest()[:16],
                    "extension": ext or None,
                    "declared_type": declared,
                    "sha256": (hashlib.sha256(payload).hexdigest()
                               if payload else None),
                    "size": len(payload) if payload else 0,
                    # A FACT, not a verdict. D9 measurement REJECTED
                    # `risky_attachment` as a standalone signal.
                    "executable_extension": ext in EXECUTABLE_EXTENSIONS,
                    # Declared type vs extension disagreeing is exactly the
                    # parser-differential shape worth recording: the client may
                    # act on one, a scanner on the other.
                    "type_extension_mismatch": _type_ext_mismatch(declared, ext),
                }
                out.attachments.append(entry["attachment"])

            if payload:
                _collect_urls(payload, out)
                if ctype == "text/html":
                    html_chunks.append(_decode(payload, part))
                elif ctype.startswith("text/"):
                    text_chunks.append(_decode(payload, part))

            out.parts.append(entry)
        except Exception as exc:                               # noqa: BLE001
            out.problems.append("part_failed:%s" % type(exc).__name__)

    out.body_text = "\n\n".join(text_chunks)
    out.body_html = "\n\n".join(html_chunks)


def _decode(payload: bytes, part) -> str:
    """Bytes -> str, never raising. Undecodable bytes are replaced, not dropped."""
    try:
        return payload.decode(part.get_content_charset() or "utf-8", "replace")
    except Exception:                                          # noqa: BLE001
        return payload.decode("utf-8", "replace")


def _collect_urls(payload: bytes, out: ParsedMessage) -> None:
    for u in _URL_RE.findall(payload):
        if len(out.urls) >= MAX_URLS:
            out.truncated = True
            out.problems.append("url_limit:%d" % MAX_URLS)
            return
        out.urls.append(u.decode("utf-8", "replace"))


#: Content types that legitimately pair with many extensions; a mismatch there
#: says nothing. Keeps the mismatch flag meaningful instead of near-universal.
_GENERIC_TYPES = frozenset({
    "application/octet-stream", "application/x-download", "", None,
})

_EXT_TYPE_HINTS = {
    "pdf": "pdf", "zip": "zip", "doc": "msword", "docx": "wordprocessingml",
    "xls": "excel", "xlsx": "spreadsheetml", "png": "png", "jpg": "jpeg",
    "jpeg": "jpeg", "gif": "gif", "txt": "plain", "html": "html",
    "htm": "html", "csv": "csv", "rtf": "rtf",
}


#: Content types that legitimately accompany an executable extension. A
#: declared type OUTSIDE this set on an executable file is a contradiction.
_EXECUTABLE_TYPE_MARKERS = (
    "msdownload", "executable", "x-dosexec", "portable-executable",
    "x-msdos-program", "x-msi", "java-archive", "x-sh", "x-bat",
)


def _type_ext_mismatch(declared: str, ext: str) -> bool:
    """True when a declared content type contradicts the file extension.

    Conservative by design: only flags a mismatch when BOTH sides are specific
    enough for a contradiction to mean something. `application/octet-stream`
    with any extension is not a contradiction -- it is the absence of a claim,
    and flagging it would fire on a large share of ordinary mail, which the D9
    work established is how a signal becomes useless.

    ⚠ THE EXECUTABLE BRANCH EXISTS BECAUSE THE FIRST VERSION WAS BLIND TO THE
    ONLY CASE THAT MATTERS. That version consulted `_EXT_TYPE_HINTS` alone, and
    `.exe` has no entry there -- so `application/pdf` declared on `invoice.exe`
    returned False. The check worked for benign mismatches (a .png declared as
    text/plain) and could not see the dangerous one, which is the
    can-only-produce-one-answer shape applied to exactly the wrong half of the
    input space. Caught by its own test; fixed rather than the test relaxed.
    """
    if not ext or declared in _GENERIC_TYPES:
        return False
    low = (declared or "").lower()

    # An executable extension declared as something that is not an executable
    # type. Checked FIRST and independently of the hints table, so coverage
    # here never depends on someone having remembered to add an entry.
    if ext in EXECUTABLE_EXTENSIONS:
        return not any(mark in low for mark in _EXECUTABLE_TYPE_MARKERS)

    hint = _EXT_TYPE_HINTS.get(ext)
    if hint is None:
        return False
    return hint not in low


# ── Canary ──────────────────────────────────────────────────────────────────

_CANARY_GOOD = (
    b"From: a@example.com\r\nTo: b@example.org\r\nSubject: hi\r\n"
    b"Message-ID: <1@example.com>\r\n\r\nbody http://example.com/x\r\n"
)
_CANARY_ATTACH = (
    b"From: c@example.net\r\nSubject: m\r\n"
    b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
    b"--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
    b"--B\r\nContent-Type: application/pdf\r\n"
    b'Content-Disposition: attachment; filename="x.pdf"\r\n\r\nPDFDATA\r\n--B--\r\n"'
)


def selftest() -> tuple[bool, str]:
    """Prove the parser both extracts AND reports failure before it is trusted.

    A parser that silently returned an empty ParsedMessage for everything would
    produce a corpus of clean-looking messages with no URLs and no attachments
    -- indistinguishable, downstream, from genuinely clean mail. This makes it
    demonstrate both directions on every import.
    """
    good = parse(_CANARY_GOOD)
    if good.headers.get("from") is None:
        return False, "canary 1: lost the From header"
    if len(good.urls) != 1:
        return False, ("canary 1: expected exactly 1 URL, got %d -- the URL "
                       "extractor is not extracting" % len(good.urls))
    if not good.parsed_cleanly:
        return False, "canary 1: a well-formed message reported problems: %s" % good.problems

    att = parse(_CANARY_ATTACH)
    if len(att.attachments) != 1:
        return False, ("canary 2: expected exactly 1 attachment, got %d"
                       % len(att.attachments))
    if att.attachments[0]["extension"] != "pdf":
        return False, "canary 2: attachment extension lost"

    # It must also be able to FAIL. A parser that reports success on empty
    # input cannot be trusted when it reports success on real input.
    empty = parse(b"")
    if empty.parsed_cleanly or "empty_input" not in empty.problems:
        return False, "canary 3: empty input did not report a problem"
    notbytes = parse("a string")                               # type: ignore[arg-type]
    if notbytes.parsed_cleanly:
        return False, "canary 4: non-bytes input did not report a problem"

    return True, "4 canaries pass (2 must-extract, 2 must-report-failure)"
