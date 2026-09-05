"""Fast synchronous checks: authentication + the D9-cleared signals.
ADR 0028 D9, build spec Stage 2.4.

WHAT "FAST" MEANS HERE
    Everything in this module completes without detonating anything and without
    fetching any URL. One DNS lookup (the DMARC policy record) is the only
    network access, and it is cached. Attachment and link detonation are later,
    slower, sandboxed stages.

────────────────────────────────────────────────────────────────────────────
⚠ WHAT CAN AND CANNOT BE VERIFIED FROM AN IMAP MAILBOX -- read this before
   changing anything in the auth section
────────────────────────────────────────────────────────────────────────────

    **SPF cannot be independently verified from IMAP. Not "is not yet" --
    cannot.** SPF evaluates the connecting SMTP client's IP against the
    sending domain's policy. By the time a message is read over IMAP it has
    already been delivered; that TCP connection is long gone and its IP is not
    recoverable from the message. Any code claiming to "check SPF" on a
    mailbox-read message is either parsing someone else's finding or guessing
    from `Received` headers, which are attacker-influenced.

    **DKIM in principle could be** -- the signature covers the message and is
    self-contained -- but it needs a verifying library (`dkimpy`), which is NOT
    installed here (verified, not assumed). Adding it is a real option for a
    later stage; pretending to verify without it is not.

    **DMARC policy IS independently checkable**, because it is a DNS TXT record
    at `_dmarc.<domain>`. That is what dnspython is for here, and it is the one
    authentication fact this module establishes on its own authority.

    **So: this module TRUSTS the receiving provider's `Authentication-Results`
    for SPF and DKIM, and says so in its output.** `AuthResult.verified_by_us`
    distinguishes what we established from what we accepted on trust. A caller
    that treats those as the same thing is making a claim this module refuses
    to make for it.

⚠ AND THE HEADER IS ONLY TRUSTWORTHY IF YOU CHECK WHO WROTE IT
    `Authentication-Results` is an ordinary header. **Anyone can add one.** An
    attacker forging `Authentication-Results: mx.google.com; spf=pass` into
    their own message is trivial, and a scanner that reads "the first one it
    finds" or "any one that says pass" is trivially defeated.

    Only the receiving server's own header counts, it is prepended at delivery,
    and it must carry that server's authserv-id. This module therefore takes
    the TOPMOST header AND requires its authserv-id to match an expected value
    (`mx.google.com` for the Gmail path). Anything below the top is
    attacker-supplied until proven otherwise and is ignored.

────────────────────────────────────────────────────────────────────────────
THE D9 SIGNALS ARE PORTED VERBATIM, AND THAT IS DELIBERATE
────────────────────────────────────────────────────────────────────────────
    `has_form`, `urgent_subject` and `url_shortener` cleared the D9 measurement
    gate with measured false-positive rates on 14,785 real benign messages
    (0.14%, 1.72%, 0.01%). **Those rates describe the exact signal definitions
    that were measured and nothing else.** A reimplementation that "does the
    same thing" more cleanly invalidates the measurement, and the FP rate would
    have to be re-established from scratch against a fresh corpus.

    So the word lists, the shortener set, and the HTML extractor below are
    copied from `tools/measure_link_html_signals.py` and
    `tools/measure_naive_heuristics.py` unchanged. **If you improve one, you
    must re-measure it.** `SIGNAL_PROVENANCE` records which corpus each rate
    came from so the claim can always be traced.

    Signals REJECTED by D9 are not implemented here at all -- not implemented
    and disabled, not implemented behind a flag. `hidden_styled_elements`
    (80.13% FP) and `many_external_images` (55.88% FP) fire on most legitimate
    modern mail; shipping them switched off would leave a loaded gun for
    someone who assumes an unused signal is merely untested.

NOTHING HERE FETCHES A URL. Hosts are compared as strings.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

__all__ = ["AuthResult", "FastCheckResult", "check", "SIGNAL_PROVENANCE"]

# ── D9-cleared signal definitions — PORTED VERBATIM, DO NOT "IMPROVE" ────────

#: From tools/measure_naive_heuristics.py. Measured FP 1.72% corpus-wide,
#: 2.46% on transactional mail (Gmail, n=14,785).
URGENT_WORDS = [
    "urgent", "verify", "suspend", "act now", "immediately", "confirm your",
    "expire", "expiring", "locked", "unusual activity", "final notice",
    "action required", "validate", "unauthorized", "click here",
]

#: From tools/measure_link_html_signals.py. Measured FP 0.01%.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "lnkd.in", "t.ly", "shorte.st",
}

#: Where each rate came from. A signal's FP rate is meaningless without the
#: corpus it was measured on, and this is what lets a future reader tell
#: "measured" from "assumed".
SIGNAL_PROVENANCE = {
    "has_form": {
        "fp_rate": 0.0014, "corpus": "gmail-2026-08-25 benign inbox",
        "n": 14785, "note": "56x worst-year phishing enrichment (Nazario 2015-25)",
    },
    "urgent_subject": {
        "fp_rate": 0.0172, "corpus": "gmail-2026-08-25 benign inbox",
        "n": 14785, "note": "2.46% on transactional mail; weak contributor, "
                            "never fires alone (operator decision 2026-08-25)",
    },
    "url_shortener": {
        "fp_rate": 0.0001, "corpus": "gmail-2026-08-25 benign inbox",
        "n": 14785, "note": "first era-compatible measurement; Enron predates "
                            "shorteners entirely",
    },
    # ── NOT D9-CLEARED. Recorded so the claim is traceable, and carrying an
    # explicit `status` so the ABSENCE of a validated rate is visible rather
    # than implied by a number sitting in the same column as three measured
    # ones. These are facts about a message; they are never a verdict.
    "executable_attachment": {
        "fp_rate": 0.0001, "corpus": "gmail-2026-08-25 benign inbox",
        "n": 14785, "status": "inert",
        "note": "D9 measured `risky_attachment` at 1 occurrence (0.01% benign, "
                "0.00% phish) and classified it INERT -- never exercised on any "
                "population, which is NOT the same as disproved. Distinct from "
                "the signals D9 REJECTED for firing on legitimate mail.",
    },
    "attachment_content_mismatch": {
        "fp_rate": None, "corpus": None, "n": None, "status": "unmeasured",
        "note": "magic-byte content verification, added 2026-09-05. No corpus "
                "measurement exists. Known blind spots are structural, not gaps "
                "to be tuned away: polyglots satisfy any single-signature test, "
                "embedded content in a valid host file is invisible, and scripts "
                "have no signature at all. Detects contradiction, not malice.",
    },
    "attachment_type_mismatch": {
        "fp_rate": None, "corpus": None, "n": None, "status": "unmeasured",
        "note": "no corpus measurement exists for declared-type/extension "
                "contradiction. Left as None rather than borrowing "
                "`risky_attachment`'s rate, which measured a different thing.",
    },
}


def _host(url: str) -> str:
    """Host of a URL. Ported verbatim from the measurement tooling."""
    u = re.sub(r"^[a-z]+://", "", (url or "").strip(), flags=re.I)
    u = u.split("/")[0].split("?")[0]
    if "@" in u:
        u = u.rsplit("@", 1)[1]
    return u.split(":")[0].lower()


class _Extract(HTMLParser):
    """HTML feature extractor. Ported verbatim from the D9 measurement.

    Only the fields the CLEARED signals need are retained. The rejected
    signals' counters are deliberately absent -- see the module docstring.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = 0
        self.anchors: list = []
        self._in_a = None
        self._buf: list = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a":
            self._in_a = d.get("href") or ""
            self._buf = []
        elif tag == "form":
            self.forms += 1

    def handle_endtag(self, tag):
        if tag == "a" and self._in_a is not None:
            self.anchors.append((self._in_a, "".join(self._buf).strip()))
            self._in_a, self._buf = None, []

    def handle_data(self, data):
        if self._in_a is not None:
            self._buf.append(data)


# ── Authentication ──────────────────────────────────────────────────────────

#: The authserv-id the Gmail path expects. A header claiming any other
#: identity is not the receiving server's and carries no weight.
GMAIL_AUTHSERV_ID = "mx.google.com"

_AR_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)


class AuthResult:
    """Authentication facts, with provenance attached to each one."""

    __slots__ = ("spf", "dkim", "dmarc", "dmarc_policy", "authserv_id",
                 "header_present", "header_trusted", "verified_by_us",
                 "problems")

    def __init__(self):
        self.spf = None                 # None = not stated, never "pass"
        self.dkim = None
        self.dmarc = None
        self.dmarc_policy = None        # from OUR OWN DNS lookup
        self.authserv_id = None
        self.header_present = False
        self.header_trusted = False
        #: What THIS module established on its own authority. Everything else
        #: was accepted from the receiving provider.
        self.verified_by_us: list = []
        self.problems: list = []

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}


def parse_authentication_results(headers_list, expect_authserv_id: str
                                 = GMAIL_AUTHSERV_ID) -> AuthResult:
    """Read the receiving server's own auth findings. Never trusts blindly.

    `headers_list` must be in RECEIVED ORDER, topmost first — the order
    `Message.get_all()` returns. Only the topmost is considered, and only if
    its authserv-id matches, because everything below it can be attacker
    supplied.
    """
    out = AuthResult()
    if not headers_list:
        # Absent is recorded as absent. NOT as fail, and emphatically not as
        # pass -- a message that arrived without the header is a different
        # fact from one that failed, and defaulting either way invents data.
        out.problems.append("no_authentication_results_header")
        return out

    out.header_present = True
    top = str(headers_list[0]).strip()

    # authserv-id is the first token, before the first ';'
    authserv = top.split(";")[0].strip().split()[0] if top else ""
    out.authserv_id = authserv or None

    if expect_authserv_id and authserv.lower() != expect_authserv_id.lower():
        out.problems.append(
            "authserv_id_mismatch:%s" % (authserv or "<empty>"))
        # Deliberately returns WITHOUT parsing the verdicts. A header from an
        # unexpected identity is attacker-supplied until proven otherwise, and
        # reading its verdicts "just for information" is how a forged pass ends
        # up in a result object that something downstream trusts.
        return out

    out.header_trusted = True
    for method, verdict in _AR_METHOD_RE.findall(top):
        setattr(out, method.lower(), verdict.lower())
    return out


def lookup_dmarc_policy(domain: str, resolver=None) -> tuple:
    """The domain's published DMARC policy, via DNS. Returns (policy, problem).

    This is the one authentication fact this module establishes itself, which
    is why it is separated from the header-trusting path above.

    A lookup FAILURE returns (None, reason) -- never a policy value. "No DMARC
    record published" and "DNS was unreachable" are different facts and only
    one of them says anything about the sender.
    """
    if not domain:
        return None, "no_domain"
    try:
        import dns.resolver                                    # noqa: PLC0415
    except ImportError:
        return None, "dnspython_missing"

    r = resolver or dns.resolver.Resolver()
    try:
        answers = r.resolve("_dmarc.%s" % domain, "TXT", lifetime=5.0)
    except Exception as exc:                                   # noqa: BLE001
        return None, "dns_%s" % type(exc).__name__

    for rdata in answers:
        txt = b"".join(getattr(rdata, "strings", []) or []).decode(
            "utf-8", "replace")
        if not txt:
            txt = str(rdata).strip('"')
        if "v=DMARC1" in txt:
            m = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", txt, re.I)
            if m:
                return m.group(1).lower(), None
            return None, "dmarc_record_without_policy"
    return None, "no_dmarc_record"


# ── The fast check ──────────────────────────────────────────────────────────

class FastCheckResult:
    """Signals and auth facts. NOT a verdict.

    Deliberately carries no score and no boolean 'suspicious'. Combining
    signals into a verdict is a separate decision with its own measurement
    requirement, and D9's finding was that `urgent_subject` must never fire
    alone. A result object with a `.suspicious` field would invite exactly that.
    """

    __slots__ = ("signals", "auth", "problems")

    def __init__(self):
        self.signals: dict = {}
        self.auth: AuthResult | None = None
        self.problems: list = []

    def to_dict(self) -> dict:
        return {"signals": dict(self.signals),
                "auth": self.auth.to_dict() if self.auth else None,
                "problems": list(self.problems)}


def signals(parsed) -> dict:
    """The signals for one ParsedMessage: three D9-cleared, two attachment facts.

    The three cleared signals (`has_form`, `urgent_subject`, `url_shortener`)
    carry measured false-positive rates. The two attachment entries do NOT --
    see SIGNAL_PROVENANCE, where they are marked `inert`/`unmeasured` rather
    than given a borrowed rate. All five share one shape so a consumer cannot
    tell them apart by accident; provenance is where the difference lives.

    Each returns a bool. `substrate` records whether the signal COULD have
    fired -- a signal with no substrate did not "pass", it was not tested, and
    the D9 work exists precisely because those two look identical in a results
    table.
    """
    html = getattr(parsed, "body_html", "") or ""
    subject = (getattr(parsed, "headers", {}) or {}).get("subject") or ""
    urls = getattr(parsed, "urls", []) or []
    # getattr with a default: the import-time selftest builds a message object
    # that has no `attachments` attribute at all, and a parse that failed early
    # may not have one either. Absent must degrade to "no substrate", not raise.
    attachments = getattr(parsed, "attachments", []) or []

    forms = 0
    anchors: list = []
    #: Set to the exception type name when the HTML could not be parsed. NOT a
    #: bool: the type is what tells a reader whether this was a malformed body,
    #: a MemoryError on a huge one, or a defect in _Extract.
    html_failed = None
    if html:
        try:
            p = _Extract()
            p.feed(html)
            forms, anchors = p.forms, p.anchors
        except Exception as exc:                               # noqa: BLE001
            # ⛔ A FAILED PARSE MUST NOT LOOK LIKE A CLEAN ONE.
            #
            # This used to `pass`, with a comment claiming the caller recorded
            # it via `problems`. It did not -- `signals()` has no problems
            # channel and its caller only records something when signals()
            # RAISES, which this handler prevented. So the failure was recorded
            # nowhere and `has_form` returned {fired: False, substrate: True}:
            # byte-identical to "we parsed the body and there was no form".
            # A phishing form in a body the parser choked on scored clean, and
            # `substrate` -- the field whose entire purpose is to separate "did
            # not fire" from "was not tested" -- asserted the opposite of the
            # truth. Confirmed by reproduction 2026-08-31 before this fix.
            html_failed = type(exc).__name__

    shortener = any(_host(h) in SHORTENERS for h, _ in anchors) or \
        any(_host(u) in SHORTENERS for u in urls)

    out = {
        # substrate is False when the parse failed: the body existed but the
        # signal was NOT tested against it.
        "has_form": {"fired": forms > 0,
                     "substrate": bool(html) and html_failed is None},
        "urgent_subject": {
            "fired": any(w in subject.lower() for w in URGENT_WORDS),
            "substrate": bool(subject),
        },
        # `urls` come from mime_parse, not from this parser, so a failed HTML
        # parse leaves the url half genuinely tested and the anchor half not.
        # substrate stays honest on its own (anchors is empty), but `fired` can
        # be a FALSE NEGATIVE -- a shortener present only in an <a href> was
        # never looked at -- so the problem is attached here too.
        "url_shortener": {"fired": shortener,
                          "substrate": bool(urls or anchors)},
        # ── attachment FACTS ────────────────────────────────────────────────
        # mime_parse computed these correctly and nothing consumed them: before
        # 2026-09-05 `signals()` never read `parsed.attachments`, so across 169
        # live recorded verdicts ZERO carried any attachment data.
        #
        # substrate is load-bearing here. "No attachment" must read as NOT
        # TESTED, never as fired=False with substrate=True -- D9 classified
        # `risky_attachment` INERT precisely because it was never exercised, and
        # an untested signal reporting a 0.00% FP rate looks like the best
        # signal in the table. That misreading is what the whole D9 campaign
        # exists to prevent.
        "executable_attachment": {
            "fired": any(a.get("executable_extension") for a in attachments),
            "substrate": bool(attachments),
        },
        # Its substrate is NARROWER than "has attachments": a generic declared
        # type is the absence of a claim, so there was nothing to contradict and
        # the signal was not tested. mime_parse decides that (type_mismatch_tested)
        # because it owns the sets involved.
        "attachment_type_mismatch": {
            "fired": any(a.get("type_extension_mismatch") for a in attachments),
            "substrate": any(a.get("type_mismatch_tested") for a in attachments),
        },
        # CONTENT vs claim -- the only one of the three that reads actual bytes.
        # Kept ALONGSIDE attachment_type_mismatch rather than replacing it: they
        # catch different lies. The extension check sees a sender who mislabelled
        # the type; this sees a sender whose name and type agree with each other
        # and disagree with the file. A message can trip either, both, or neither.
        "attachment_content_mismatch": {
            "fired": any(a.get("content_type_mismatch") for a in attachments),
            "substrate": any(a.get("content_mismatch_tested") for a in attachments),
        },
    }
    if html_failed:
        # Attached INSIDE the affected signals rather than as a new top-level
        # key: `_canary()` iterates this dict's values and reads v["fired"] on
        # each, so a value of a different shape would break the self-test that
        # runs on every import.
        out["has_form"]["problem"] = "html_parse_failed:%s" % html_failed
        out["url_shortener"]["problem"] = "html_parse_failed:%s" % html_failed
    return out


def check(parsed, resolver=None,
          expect_authserv_id: str = GMAIL_AUTHSERV_ID) -> FastCheckResult:
    """Full fast check for one parsed message. Never raises."""
    out = FastCheckResult()

    # A parse that reported problems produces signals computed over partial
    # content. Carried forward so a caller cannot mistake a truncated scan for
    # a complete one.
    for p in (getattr(parsed, "problems", []) or []):
        out.problems.append("parse:%s" % p)
    if getattr(parsed, "truncated", False):
        out.problems.append("parse:truncated")

    try:
        out.signals = signals(parsed)
        # A signal that could not be TESTED reports its reason inside itself
        # (see signals()). Lift those onto the result's problems list, which is
        # what the rest of the pipeline actually reads -- without this the
        # degradation is visible only to someone inspecting signals_json by eye.
        for _name, _sig in (out.signals or {}).items():
            _problem = isinstance(_sig, dict) and _sig.get("problem")
            if _problem:
                out.problems.append("signal:%s:%s" % (_name, _problem))
    except Exception as exc:                                   # noqa: BLE001
        out.problems.append("signals_failed:%s" % type(exc).__name__)
        out.signals = {}

    headers = getattr(parsed, "headers", {}) or {}
    auth = parse_authentication_results(
        headers.get("authentication_results") or [],
        expect_authserv_id=expect_authserv_id)

    from_hdr = headers.get("from") or ""
    m = re.search(r"@([A-Za-z0-9.\-]+)", from_hdr)
    if m:
        policy, problem = lookup_dmarc_policy(m.group(1).lower(), resolver)
        auth.dmarc_policy = policy
        if problem:
            auth.problems.append(problem)
        elif policy:
            auth.verified_by_us.append("dmarc_policy")

    out.auth = auth
    return out


# ── Canary ──────────────────────────────────────────────────────────────────

def selftest() -> tuple[bool, str]:
    """Prove each signal can fire AND not fire before any of them is trusted.

    A signal stuck at False reports a 0.00% false-positive rate and looks like
    the best signal in the table -- which is the exact misreading the entire D9
    measurement campaign was built to prevent. Runs on import rather than only
    in the suite.
    """
    class _P:
        headers = {"subject": "", "authentication_results": [], "from": ""}
        body_html = ""
        urls: list = []
        problems: list = []
        truncated = False
        attachments: list = []

    neg = signals(_P())
    if any(v["fired"] for v in neg.values()):
        return False, "canary: a signal fired on an empty message"

    pos = _P()
    pos.headers = {"subject": "URGENT: action required",
                   "authentication_results": [], "from": ""}
    pos.body_html = '<html><form action="x"><input name="p"></form></html>'
    pos.urls = ["http://bit.ly/abc"]
    # One attachment that trips BOTH attachment signals: an executable extension
    # (executable_attachment) declared as a PDF (attachment_type_mismatch), with
    # the mismatch marked answerable so its substrate is real rather than assumed.
    pos.attachments = [{"extension": "exe", "declared_type": "application/pdf",
                        "executable_extension": True,
                        "type_extension_mismatch": True,
                        "type_mismatch_tested": True,
                        "detected_type": "executable",
                        "content_type_mismatch": True,
                        "content_mismatch_tested": True}]
    p = signals(pos)
    for name in ("has_form", "urgent_subject", "url_shortener",
                 "executable_attachment", "attachment_type_mismatch",
                 "attachment_content_mismatch"):
        if not p[name]["fired"]:
            return False, "canary: %s did not fire on a message that should trip it" % name

    # A FAILED HTML PARSE MUST NOT BE INDISTINGUISHABLE FROM A CLEAN ONE.
    # This is the canary for the bug fixed 2026-08-31: the swallow used to
    # leave substrate=True, so a phishing form in an unparseable body reported
    # exactly like a body with no form in it. Checked here, on every import,
    # rather than only in the suite -- the same reasoning as the rest of these.
    class _Boom(_Extract):
        def feed(self, data):
            raise ValueError("canary: forced parse failure")

    _saved, globals()["_Extract"] = _Extract, _Boom
    try:
        broke = signals(pos)
    finally:
        globals()["_Extract"] = _saved
    if broke["has_form"]["substrate"]:
        return False, ("canary: a FAILED html parse still reported "
                       "has_form.substrate=True -- untested reads as tested")
    if not broke["has_form"].get("problem"):
        return False, ("canary: a failed html parse recorded no problem, so "
                       "the degradation is invisible to the caller")
    # ...and the control for that control: a HEALTHY parse must still report
    # substrate True and carry no problem, or the two checks above would pass
    # for the trivial reason that nothing ever has substrate.
    if not p["has_form"]["substrate"] or p["has_form"].get("problem"):
        return False, ("canary: a healthy parse did not report substrate=True "
                       "without a problem -- the parse-failure canary is vacuous")

    # A forged Authentication-Results must NOT be trusted.
    forged = parse_authentication_results(
        ["evil.example; spf=pass dkim=pass dmarc=pass"])
    if forged.header_trusted or forged.spf == "pass":
        return False, ("canary: a header from an unexpected authserv-id was "
                       "trusted -- forging one is trivial")
    good = parse_authentication_results(["mx.google.com; spf=pass dkim=fail"])
    if not good.header_trusted or good.spf != "pass" or good.dkim != "fail":
        return False, "canary: a legitimate Authentication-Results was misread"

    # ...and an ABSENT attachment must read as NOT TESTED, not as clean. Without
    # this the two new signals could report substrate=True on every message and
    # nothing here would notice -- the same shape as the has_form parse-failure
    # bug above, which is why it is checked on import rather than only in a suite.
    for _n in ("executable_attachment", "attachment_type_mismatch",
               "attachment_content_mismatch"):
        if neg[_n]["substrate"]:
            return False, ("canary: %s reported substrate=True on a message with "
                           "no attachments -- untested reads as tested" % _n)
        if not p[_n]["substrate"]:
            return False, ("canary: %s reported substrate=False on a message that "
                           "HAS a qualifying attachment -- the check above is "
                           "vacuous if substrate can never be True" % _n)

    return True, ("17 canaries pass (6 must-fire, 6 must-not-fire, "
                  "parse-failure not mistaken for clean +2 and its control, "
                  "forged-header rejected, genuine header read)")
