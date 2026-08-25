"""Characterise the links in a mail corpus WITHOUT EVER FETCHING ONE.

Build spec stage 4, step 2 (the zero-risk population analysis), and the
groundwork half of 4.4 (`link_extract.py`) — which has to do the extraction
anyway.

═══════════════════════════════════════════════════════════════════════════════
THIS MODULE MAKES NO NETWORK REQUESTS. THAT IS ITS ENTIRE SAFETY PROPERTY.
═══════════════════════════════════════════════════════════════════════════════
It imports no HTTP client, opens no socket, resolves no name. It parses strings.
`test_link_classify.py` asserts this structurally — it walks this file's AST for
any networking import and fails if one appears — because the property is easy to
break by accident later (one `requests` import inside one helper) and impossible
to notice from the output, which would look identical.

WHY THIS EXISTS
    Detonating a link means fetching it, and the links in a real mailbox are live
    URLs in genuine correspondence: tracking pixels that report a read, one-time
    tokens that burn on first use, unsubscribe endpoints that really unsubscribe,
    magic-links that can be consumed. The consequences land on the mailbox
    owner's own accounts.

    So the real mailbox cannot be a detonation target. It CAN, safely, tell us
    what its link population LOOKS like — and that is the question every
    synthetic corpus depends on but cannot answer about itself: is this set
    structurally representative? D9 Findings 1.4 is the precedent: benign and
    adversarial corpora were only comparable because someone measured their
    structural comparability (HTML rate, received hops) instead of asserting it.

⚠ THE RISK CLASSIFICATION BELOW IS DESCRIPTIVE, NOT A FETCH-SAFETY FILTER
    `side_effect_risk()` exists to characterise a population — "what fraction of
    real inbound links carry opaque tokens" — NOT to decide what is safe to
    fetch. Do not repurpose it as a gate.

    Two reasons, both load-bearing:

    1. HTTP METHOD IS NOT A SAFETY SIGNAL. GET is specified as safe and
       idempotent, but tracking pixels are GETs with side effects BY DESIGN and
       one-click unsubscribe is frequently a GET. Any filter reasoning from
       method semantics fires exactly the endpoints it meant to avoid.
    2. Shape-based classification is an UNVALIDATED HEURISTIC whose failure mode
       is consuming a real magic-link. That is a poor blast radius for a guess,
       and the build spec's standing prohibition is unconditional: never point
       link detonation at a live personal mailbox.

    A "low" score here means "nothing in the URL's shape suggests state" — never
    "safe to fire."
"""
from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlsplit, parse_qsl

#: Query parameter names that commonly carry single-use or identifying state.
#: Descriptive only -- see the module header.
_STATEFUL_PARAMS = frozenset({
    "token", "t", "auth", "key", "code", "confirm", "confirmation", "verify",
    "validation", "session", "sid", "sess", "otp", "magic", "login", "invite",
    "reset", "activate", "activation", "unsub", "unsubscribe", "u", "uid",
    "user", "email", "e", "recipient", "subscriber", "id",
})

#: Path segments that suggest an action endpoint rather than a document.
_ACTION_PATHS = frozenset({
    "unsubscribe", "unsub", "optout", "opt-out", "confirm", "verify", "activate",
    "reset", "login", "signin", "auth", "magic", "invite", "accept", "decline",
    "click", "track", "open", "pixel", "beacon", "redirect", "r", "c",
})

#: Extensions that indicate a static document rather than an endpoint.
_STATIC_EXTS = frozenset({
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "pdf",
    "woff", "woff2", "ttf", "mp4", "webm",
})

#: A path segment that looks like an opaque identifier: long, and mixing cases
#: or digits in a way human-readable slugs generally do not.
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_\-]{16,}$")


def _looks_opaque(segment: str) -> bool:
    """True for a long token-shaped path segment.

    Requires BOTH length and character-class mixing: `documentation-index` is
    long but all-lowercase-with-hyphens and is not a token, while
    `aG9sZDEyMzQ1Njc4` is. Length alone would classify most slugs as opaque and
    make the whole distribution meaningless.
    """
    if not _OPAQUE_RE.match(segment):
        return False
    has_digit = any(c.isdigit() for c in segment)
    has_upper = any(c.isupper() for c in segment)
    has_lower = any(c.islower() for c in segment)
    return (has_digit and (has_upper or has_lower)) or (has_upper and has_lower)


def classify_url(url: str) -> dict:
    """Structural facts about ONE url. No network. Facts, not verdicts.

    Every field is something readable from the string itself. `parse_failed`
    is an explicit state rather than a default-shaped empty result -- an
    unparseable URL is not a URL with no parameters.
    """
    out = {
        "url_len": len(url), "scheme": None, "host": None, "tld": None,
        "path_depth": 0, "n_query_params": 0, "stateful_params": [],
        "action_path": None, "static_ext": None, "opaque_segments": 0,
        "has_userinfo": False, "has_port": False, "is_ip_host": False,
        "parse_failed": False,
    }
    try:
        parts = urlsplit(url)
    except Exception:                                           # noqa: BLE001
        out["parse_failed"] = True
        return out

    out["scheme"] = (parts.scheme or "").lower() or None
    try:
        host = (parts.hostname or "").lower() or None
    except Exception:                                           # noqa: BLE001
        # A malformed authority (bad IPv6 literal, bad percent-encoding) raises
        # here rather than returning None. Recorded as a parse failure, not
        # silently treated as "no host".
        out["parse_failed"] = True
        return out
    out["host"] = host
    # A string with no scheme or no host is NOT a usable URL, and urlsplit does
    # not object to one: urlsplit("not a url at all") succeeds, yielding empty
    # scheme/host and a path of "not a url at all". Left unmarked, that falls
    # through the risk ladder to 'low' -- the most permissive label handed to the
    # least understood input, which is the "default that means something" shape
    # this module's own header warns about. Found by test, 2026-08-25.
    # A relative URL is unusable here for the same practical reason: it cannot be
    # fetched without a base, so it cannot be characterised as a target either.
    if not out["scheme"] or not host:
        out["parse_failed"] = True
        return out
    if host:
        out["is_ip_host"] = bool(re.match(r"^[0-9.]+$", host)) or ":" in host
        if not out["is_ip_host"] and "." in host:
            out["tld"] = host.rsplit(".", 1)[-1]
    out["has_userinfo"] = "@" in (parts.netloc or "")
    out["has_port"] = bool(parts.port) if parts.netloc else False

    segs = [s for s in (parts.path or "").split("/") if s]
    out["path_depth"] = len(segs)
    out["opaque_segments"] = sum(1 for s in segs if _looks_opaque(s))
    for s in segs:
        if s.lower() in _ACTION_PATHS:
            out["action_path"] = s.lower()
            break
    if segs and "." in segs[-1]:
        ext = segs[-1].rsplit(".", 1)[-1].lower()
        if ext in _STATIC_EXTS:
            out["static_ext"] = ext

    try:
        q = parse_qsl(parts.query or "", keep_blank_values=True)
    except Exception:                                           # noqa: BLE001
        q = []
    out["n_query_params"] = len(q)
    out["stateful_params"] = sorted({k.lower() for k, _ in q
                                     if k.lower() in _STATEFUL_PARAMS})
    return out


def side_effect_risk(facts: dict) -> str:
    """'low' | 'medium' | 'high' -- DESCRIPTIVE ONLY. Never a fetch gate.

    Read the module header before using this for anything. 'low' means "nothing
    in this URL's shape suggests server-side state", NOT "safe to fetch": a
    1x1 tracking pixel scores 'low' on shape alone and still reports a read.
    """
    if facts.get("parse_failed"):
        # NOT 'low'. An unparseable URL is unknown, and unknown must not inherit
        # the most permissive label -- that is the "default that means
        # something" shape this repo checks for.
        return "high"
    if facts["action_path"] or facts["stateful_params"]:
        return "high"
    if facts["opaque_segments"] or facts["has_userinfo"] or facts["is_ip_host"]:
        return "medium"
    if facts["static_ext"] and not facts["n_query_params"]:
        return "low"
    return "medium" if facts["n_query_params"] else "low"


def profile(urls) -> dict:
    """Aggregate a corpus's link population. Counts and distributions only.

    Returns explicit zeroed structure for an empty input rather than {} -- a
    caller must be able to tell "no links" from "never ran".
    """
    urls = list(urls)
    facts = [classify_url(u) for u in urls]
    risks = Counter(side_effect_risk(f) for f in facts)
    return {
        "n_urls": len(urls),
        "n_parse_failed": sum(1 for f in facts if f["parse_failed"]),
        "schemes": dict(Counter(f["scheme"] for f in facts if f["scheme"])),
        "tlds": dict(Counter(f["tld"] for f in facts if f["tld"]).most_common(25)),
        "hosts_unique": len({f["host"] for f in facts if f["host"]}),
        "risk": {k: risks.get(k, 0) for k in ("low", "medium", "high")},
        "with_stateful_param": sum(1 for f in facts if f["stateful_params"]),
        "with_action_path": sum(1 for f in facts if f["action_path"]),
        "with_opaque_segment": sum(1 for f in facts if f["opaque_segments"]),
        "static_assets": sum(1 for f in facts if f["static_ext"]),
        "ip_hosts": sum(1 for f in facts if f["is_ip_host"]),
        "userinfo_hosts": sum(1 for f in facts if f["has_userinfo"]),
        "stateful_param_names": dict(
            Counter(p for f in facts for p in f["stateful_params"]).most_common(20)),
        "median_path_depth": (sorted(f["path_depth"] for f in facts)[len(facts) // 2]
                              if facts else 0),
    }
