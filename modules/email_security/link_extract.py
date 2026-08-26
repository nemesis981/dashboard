"""Feed candidate URLs from one message to the link-detonation engine. Stage 4.4.

═══════════════════════════════════════════════════════════════════════════════
DETONATING A LINK MEANS FETCHING IT. THIS MODULE CAUSES REAL NETWORK REQUESTS.
═══════════════════════════════════════════════════════════════════════════════
Unlike attachment detonation -- where the sample is inert until executed inside
the VM -- a link's side effects land the moment it is fetched, and they land on
the MAILBOX OWNER'S OWN ACCOUNTS: tracking pixels report a read, one-time tokens
burn, unsubscribe endpoints unsubscribe, magic-links get consumed.

**NEVER point this at a live personal mailbox.** The build spec's prohibition is
unconditional, and Findings 1.7 quantified the exposure: 26.4% of 45,311 real
inbound URLs carry a high-risk shape. Detonation corpora must be expendable --
see the Stage 4 validation strategy.

WHY A FETCHER INTERFACE RATHER THAN A DIRECT CALL (same pattern as D3)
    `LinkSandbox` today exposes `verify_egress_constrained()` and NOTHING ELSE --
    the actual clone/fetch/observe engine is not built. Verified, not assumed.
    So this driver takes a `fetcher` and calls it; when the real engine lands it
    implements the same one-method contract and nothing here changes. That also
    keeps the tests meaningful rather than turning them into tests of a stub.

EGRESS IS VERIFIED BEFORE EVERY SINGLE FETCH, NOT ONCE PER BATCH
    D1 requires the canary run in the production path on every detonation, not at
    startup. The state it checks is host/VM state that can change between fetches,
    and a batch-level check would vouch for a configuration that has since moved.
    It is cheap relative to a fetch; do not "optimise" it to once per message.

⚠ side_effect_risk() IS RECORDED AS A FACT, NEVER USED AS A GATE
    `link_classify.side_effect_risk()` documents itself as descriptive-only, and
    this module honours that. A 'low' score means "nothing in the URL's shape
    suggests state" -- NOT "safe to fire": a 1x1 tracking pixel scores 'low' and
    still reports a read. Filtering on it would produce exactly the false
    assurance it warns against. It rides along in the result for analysis.

TRUNCATION IS NEVER SILENT
    A capped candidate list is reported as capped, with the totals, because a
    short list and a complete short list look identical -- and a conclusion drawn
    from a silently-truncated set is the failure this repo's standing checks name.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import urlsplit

from . import link_classify as lc

#: Must match the data_manager NAMESPACES key.
MODULE_NAME = "email_security"


def _now() -> str:
    """Local ISO to seconds -- ADR 0004, matching the sibling modules."""
    return datetime.now().isoformat(timespec="seconds")


#: Only these are fetchable. Anything else is recorded as skipped, never dropped
#: silently.
#:
#: ⚠ NOTE WHICH BUCKET THINGS LAND IN -- it is not what you would guess.
#: `mailto:`/`tel:`/`javascript:` are HOSTLESS, so `classify_url` marks them
#: `parse_failed` and they are recorded as `skipped_unparseable`; they never
#: reach this filter. This filter fires only for a scheme that HAS a host, e.g.
#: `ftp://example.com/x`. Both outcomes are correct and both are reported --
#: the distinction is documented because a reader debugging "why is my mailto
#: not in skipped_scheme" would otherwise assume a bug.
#:
#: DEFENSIVE: `mime_parse`'s URL regex already yields only http(s) (verified
#: 2026-08-26), so this cannot fire through the normal path today. Kept because
#: it is nearly free and becomes load-bearing the moment that regex widens --
#: and exercised DIRECTLY by test §6b rather than left as a branch nothing walks.
FETCHABLE_SCHEMES = ("http", "https")

#: Per-message cap. A single marketing message can carry 45k-corpus-scale link
#: counts; detonating every one is neither affordable nor informative. Exceeding
#: it is REPORTED, never silently trimmed.
MAX_LINKS_PER_MESSAGE = 25

#: Every value `outcome` may take.
OUTCOMES = ("completed", "egress_unverified", "skipped_scheme",
            "skipped_unparseable", "error")


class LinkDetonationHalted(RuntimeError):
    """The batch stopped deliberately. Carries WHY.

    Mirrors `attachment_detonate.DetonationHalted`. `outcome` names the condition
    so a caller does not have to parse the message text to react to it.
    """

    def __init__(self, reason, *, outcome):
        super().__init__(reason)
        self.outcome = outcome


class Fetcher:
    """What this driver needs from the (not yet built) detonation engine."""

    def fetch(self, url: str, egress_evidence=None) -> dict:
        """Detonate ONE url in the sandbox; return the observation report.

        Must RAISE on failure rather than returning an empty report: an empty
        observation and a failed fetch are the two states that must never be
        conflated, because a failed fetch reads as 'benign page' downstream.

        `egress_evidence` is the dict this driver got from
        `verify_egress_constrained()`, passed through so the engine can REFUSE
        when the caller skipped the check -- without duplicating the check
        itself. Found necessary by wiring the real engine in: it defaults to
        None, and an engine that requires it would otherwise refuse every fetch.
        """
        raise NotImplementedError


#: Matches a literal email address, INCLUDING the percent-encoded form
#: (`x%40example.com`) that mail links routinely use. Both must be caught: a
#: redactor that only handled the plain form would leave most of them, and would
#: look like it was working.
_ADDRESS_RE = re.compile(
    r"[A-Za-z0-9._+-]+(?:@|%40|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}",
    re.IGNORECASE)

#: What a redacted address is replaced with. Deliberately NOT an empty string:
#: an absent value and a removed value must stay distinguishable.
REDACTED = "<redacted-address>"


def redact_addresses(url: str):
    """Replace LITERAL email addresses in a url. Returns (url, count).

    ⚠ SCOPE, decided 2026-08-26 and deliberately narrow: only values that ARE a
    literal address. The opaque recipient identifiers that dominate real mail
    (`e=`, `mail=`, `uid=`, `u=` -- 4,301 of them in the 1,020-message burner
    corpus) are left INTACT. They are pseudonymous rather than directly
    readable, and widening to them is a separate, larger decision.

    WHERE THEY ACTUALLY ARE -- measured, not assumed. In that corpus: 37 URLs
    carry a literal address in the PATH and 18 in the QUERY. An implementation
    that redacted only identity-NAMED params (`email=` and friends) would have
    caught 9 and missed the majority, while appearing to work.

    WHY THE HOST AND PATH STRUCTURE SURVIVE: a URL's host, path and parameter
    NAMES are the detection signal, and `link_classify` already reports stateful
    params by name rather than value. The VALUE of an address adds nothing
    analytically and is the recipient's personal data. This makes the link table
    consistent with `mime_parse`, which already hashes address local parts and
    keeps domains for exactly this reason.

    A url containing no address is returned BYTE-IDENTICAL -- no parse/rebuild
    round-trip, so nothing is silently re-encoded.
    """
    if not url or "@" not in url and "%40" not in url.lower():
        return url, 0
    n = 0

    def _sub(m):
        nonlocal n
        n += 1
        return REDACTED

    out = _ADDRESS_RE.sub(_sub, url)
    return (out, n) if n else (url, 0)


def extract_candidates(parsed) -> dict:
    """Candidate URLs from one parsed message. NO fetching, NO network.

    Deduplicates by exact URL: a marketing message repeats the same tracker many
    times, and detonating it 30 times measures nothing new while multiplying the
    side effects on a real recipient.

    Returns explicit counts so the caller can tell a short list from a truncated
    one -- `truncated` is a fact about THIS message, not an error.
    """
    urls = list(getattr(parsed, "urls", []) or [])
    seen, candidates, skipped_scheme, skipped_unparseable = set(), [], [], []
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        facts = lc.classify_url(u)
        if facts["parse_failed"]:
            skipped_unparseable.append(u)
            continue
        if facts["scheme"] not in FETCHABLE_SCHEMES:
            skipped_scheme.append(u)
            continue
        candidates.append({"url": u, "facts": facts,
                           # A FACT for the record. NOT a gate -- see header.
                           "side_effect_risk": lc.side_effect_risk(facts)})

    kept = candidates[:MAX_LINKS_PER_MESSAGE]
    return {
        "candidates": kept,
        "total_urls_in_message": len(urls),
        "unique_urls": len(seen),
        "duplicates_collapsed": len(urls) - len(seen),
        "skipped_scheme": skipped_scheme,
        "skipped_unparseable": skipped_unparseable,
        # Reported explicitly, both the flag and the numbers behind it.
        "truncated": len(candidates) > MAX_LINKS_PER_MESSAGE,
        "eligible": len(candidates),
        "returned": len(kept),
        # mime_parse caps at MAX_URLS and sets this; a message truncated THERE is
        # already incomplete before this module sees it, and that must surface.
        "upstream_truncated": bool(getattr(parsed, "truncated", False)),
    }


def detonate_link(sandbox, fetcher, candidate) -> dict:
    """Verify egress, then detonate ONE candidate. Returns a result dict.

    Raises LinkDetonationHalted when egress cannot be verified -- that is a
    host/VM configuration condition, not a property of this URL, so every
    subsequent fetch would fail identically. Same reasoning as
    `attachment_detonate`'s IsolationUnverified halt and `scan_file`'s
    ClamEngineUnavailable.
    """
    from modules.malware_detection import link_sandbox as lsb     # noqa: PLC0415

    url = candidate["url"]
    base = {"url": url, "side_effect_risk": candidate["side_effect_risk"],
            "host": candidate["facts"].get("host")}

    # EVERY fetch. Not once per batch -- see the module header.
    try:
        egress = sandbox.verify_egress_constrained()
    except lsb.EgressUnverified as exc:
        raise LinkDetonationHalted(
            "egress not verified as constrained, so nothing was fetched: %s. "
            "This is a host/VM configuration condition, not a property of %s -- "
            "not continuing to the next link." % (exc, url),
            outcome="egress_unverified") from exc

    try:
        report = fetcher.fetch(url, egress_evidence=egress)
    except Exception as exc:                                    # noqa: BLE001
        # A failed fetch is per-URL and recoverable. It is NOT an empty
        # observation, and must never be recorded as one.
        return dict(base, outcome="error",
                    error="%s: %s" % (type(exc).__name__, exc), report=None)

    # CONTRACT ENFORCEMENT (added 2026-08-26, on Window 2's review finding).
    # `Fetcher.fetch` is documented as "raise on failure, never return an empty
    # report". A fetcher that violates that by returning None would otherwise be
    # recorded as outcome='completed' with report=None -- an anomalous shape that
    # nothing guarded, and the closest thing to the "empty report reads as
    # benign" failure this whole stage exists to prevent. Turn the contract
    # violation into a loud error rather than a weird-but-"completed" result.
    # Window 2 raised this while no real Fetcher existed; link_fetch.LinkFetcher
    # now does, so the guard is no longer hypothetical.
    if report is None:
        return dict(base, outcome="error", report=None,
                    error="fetcher CONTRACT VIOLATION: returned None instead of "
                          "raising. A missing report must never be recorded as a "
                          "completed detonation -- see Fetcher.fetch's docstring.")
    return dict(base, outcome="completed", report=report,
                # Carried so a report can never be read as proving more than it
                # does -- the engine's own not-proven list travels with it.
                egress_not_proven=egress.get("not_proven"))


def detonate_message_links(sandbox, fetcher, parsed) -> dict:
    """Detonate every eligible link in one message, in order.

    Propagates LinkDetonationHalted immediately -- remaining links are
    deliberately NOT attempted. The returned `extraction` block always reports
    what was skipped and whether anything was truncated, so a partial run is
    never mistaken for a complete one.
    """
    ex = extract_candidates(parsed)
    results = []
    for cand in ex["candidates"]:
        results.append(detonate_link(sandbox, fetcher, cand))
    return {"extraction": ex, "results": results,
            "detonated": len(results),
            "complete": (not ex["truncated"]) and (not ex["upstream_truncated"])}

def record_results(verdict_id, batch) -> int:
    """Persist one message's link-detonation results. Returns rows written.

    Routed through the Data Manager (ADR 0006). Upserts on (verdict_id, url) so a
    re-detonation UPDATES rather than duplicating -- matching the table's UNIQUE
    constraint.

    ⚠ THE BATCH-LEVEL TRUNCATION FACTS ARE WRITTEN ONTO EVERY ROW, deliberately.
    `link_extract` caps at 25 links/message and `mime_parse` at 500 URLs; a
    persistence layer that drops those turns a PARTIAL run into an apparently
    complete one. A reader must be able to ask "was this message fully covered?"
    from the rows alone, without the caller having kept the batch dict.

    Separate from `detonate_message_links` on purpose: detonation and persistence
    fail for different reasons, and a DB error must not be mistaken for a
    detonation failure.
    """
    from modules import get_data_manager                        # noqa: PLC0415

    ex = batch.get("extraction") or {}
    dm = get_data_manager()
    actor = dm.current_actor()
    now = _now()
    truncated = 1 if (ex.get("truncated") or ex.get("upstream_truncated")) else 0
    written = 0
    for r in batch.get("results") or []:
        if r.get("outcome") not in OUTCOMES:
            raise ValueError("unknown outcome %r" % r.get("outcome"))
        # PERSISTENCE TIME ONLY. The url was fetched with its REAL value; only
        # the stored copy is redacted. Two consequences, both accepted and
        # intended rather than defects:
        #   * a stored url may not be re-detonatable as-is. Re-running should
        #     re-extract from the source message, which is the real source of
        #     truth anyway.
        #   * UNIQUE(verdict_id, url) can now collapse two links that differed
        #     ONLY by recipient address into one row. That is the correct
        #     reading -- same endpoint, same message, different recipient token.
        stored_url, _n_redacted = redact_addresses(r["url"])
        dm.upsert(
            MODULE_NAME, "email_link_detonations",
            {"verdict_id": verdict_id, "url": stored_url, "host": r.get("host"),
             "side_effect_risk": r.get("side_effect_risk"),
             "detonated_at": now, "outcome": r["outcome"],
             "report_json": json.dumps(r["report"]) if r.get("report") is not None else None,
             "error": r.get("error"),
             "batch_truncated": truncated,
             "batch_eligible": ex.get("eligible"),
             "batch_detonated": batch.get("detonated"),
             "actor": actor},
            conflict_cols=("verdict_id", "url"),
            update=["host", "side_effect_risk", "detonated_at", "outcome",
                    "report_json", "error", "batch_truncated", "batch_eligible",
                    "batch_detonated", "actor"])
        written += 1
    return written
