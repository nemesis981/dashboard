"""Curated threat-feed catalogue + the format check that gates every feed.

Pure logic: no I/O, no Pi-hole, no DB. Everything here is a decision that can be
tested directly, which is the point — the validator below is the check whose
ABSENCE produced the defect that started this build.
"""
import re

#: Marker written into Pi-hole's per-list `comment` field on every list this
#: module adds. It is the ownership boundary, and it is the whole safety story
#: for removal.
#:
#: ⛔ THIS IS WHY THE MODULE CANNOT DAMAGE A HAND-CURATED SETUP. The Pi-hole this
#: was built against already had FIVE operator-configured blocklists on it,
#: including an abuse.ch feed, added by hand long before this module existed.
#: Nothing here may touch them. Rather than trusting a code path not to, every
#: read is filtered to tagged rows first, so an untagged list is not merely
#: "skipped" — it never enters the set being operated on at all.
#:
#: Same principle as Rule 11's test-data labelling, applied to live config: mark
#: what you own at write time so a later sweep can find exactly it, instead of
#: inferring ownership from appearance.
OWNERSHIP_TAG = "nemesis-threat-feed"


def tag_for(feed_key):
    """The exact comment string written for a catalogue feed."""
    return "%s:%s" % (OWNERSHIP_TAG, feed_key)


def is_ours(comment):
    """True only for a comment this module wrote.

    Deliberately a PREFIX match on the tag plus a colon, not a substring search:
    a hand-written comment that merely mentions the word would otherwise read as
    ours and become eligible for deletion.
    """
    return isinstance(comment, str) and comment.strip().startswith(OWNERSHIP_TAG + ":")


def feed_key_from_comment(comment):
    """Which catalogue feed a tagged comment refers to, or None."""
    if not is_ours(comment):
        return None
    return comment.strip().split(":", 1)[1].strip() or None


# --------------------------------------------------------------------------- #
# The catalogue — verified-compatible sources only
# --------------------------------------------------------------------------- #
#
# Every entry here was confirmed to serve a DOMAIN/hosts-format list over plain
# HTTP(S), which is the only thing Pi-hole's gravity can ingest. A source being
# reputable, free and security-relevant is NOT sufficient — see EXCLUDED.
#
# `default` marks the conservative starting set. Everything else is opt-in
# individually. Nothing here is applied unless the operator enables the module
# AND applies it.

# ── EXTENSION POINT: a Nemesis-hosted community feed is JUST ANOTHER ENTRY ──
#
# Operator note, 2026-09-02: this manager is the CONSUMPTION side of the same
# pipeline the community/licensing backend will eventually feed. Once Nemesis's
# own vetted community threat data exists, it should appear here as an ordinary
# catalogue entry alongside URLhaus — not as a special case.
#
# Nothing needs building for that today, and this module deliberately has NO
# backend dependency. What is provided now is the seam:
#
#   * Entries are identified by KEY and carry a URL. Nothing in this module
#     cares who serves that URL, so a Nemesis-hosted one is not a new concept.
#   * `resolve_url()` is the single point where a URL becomes concrete, so an
#     entry whose host must come from configuration (as the licence server's
#     does) slots in without touching any caller.
#   * Validation is by FORMAT, never by source. A Nemesis feed passes the same
#     check as a third-party one and gets no privileged treatment — which is the
#     property that matters if the feed is ever wrong.
#
# The one thing NOT to do later: special-case a Nemesis feed to skip validation
# because it is "ours". A first-party feed serving the wrong format fails
# exactly as silently as a third-party one.
#
# See `CUSTOM_THREAT_FEED.md` for the full extension guide.
CATALOG = {
    "urlhaus": {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "description": ("Domains currently serving malware payloads. Updated hourly, "
                        "short-lived entries, very low false-positive rate."),
        "default": True,
    },
    "threatfox": {
        "name": "abuse.ch ThreatFox",
        "url": "https://threatfox.abuse.ch/downloads/hostfile/",
        "description": ("Indicators of compromise associated with active malware "
                        "campaigns, contributed and vetted by the abuse.ch community."),
        "default": False,
    },
}

# --------------------------------------------------------------------------- #
# Explicitly excluded — recorded so it is not re-added from the roadmap doc
# --------------------------------------------------------------------------- #
#
# ⛔ SPAMHAUS IS NOT MISSING. IT WAS MEASURED AND REJECTED.
#
# `docs/roadmap/open-source-threat-feeds.md` lists Spamhaus as a Tier-1 source
# and states it "directly integrates with Pi-hole (already running)" and "could
# be feeding Pi-hole automatically today". Verified against the live source
# 2026-09-02: DROP serves IPv4/IPv6 CIDR RANGES.
#
#     1.10.16.0/20 ; SBL256894
#
# Pi-hole gravity ingests DOMAINS. This is a category mismatch, not a
# configuration gap — no amount of effort makes Pi-hole consume it. Spamhaus's
# DNS-shaped product (DBL) is a query-time DNSBL, not a downloadable list.
#
# The data is genuinely valuable, for the ufw chokepoint rather than DNS. That
# is captured as its own parked item:
# `docs/roadmap/spamhaus-drop-firewall-ingest.md`.
#
# Listed here rather than merely omitted so that anyone reading the roadmap in
# good faith and wondering "why isn't Spamhaus wired up?" finds the answer at
# the point of use.
EXCLUDED = {
    "spamhaus_drop": {
        "name": "Spamhaus DROP",
        "reason": ("Serves IP CIDR ranges, not domains. Pi-hole gravity cannot "
                   "ingest it. Belongs at the firewall chokepoint — see "
                   "docs/roadmap/spamhaus-drop-firewall-ingest.md."),
    },
}


# --------------------------------------------------------------------------- #
# Format validation — the check whose absence caused this build's first scope
# --------------------------------------------------------------------------- #

_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
_CIDR6_RE = re.compile(r"^[0-9a-f:]+/\d{1,3}\b", re.I)
#: hosts format ("0.0.0.0 evil.example") or a bare domain ("evil.example").
_DOMAIN_RE = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}\s+|::1?\s+|0\.0\.0\.0\s+)?"
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\s*$", re.I)


def resolve_url(entry, config=None):
    """The concrete URL for a catalogue entry.

    A one-line indirection today, on purpose. Entries currently carry a literal
    `url`, but a future Nemesis-hosted community feed will need its host from
    configuration rather than baked in (the same shape `LICENSE_SERVER` already
    has). Routing every caller through here now means that entry is a data
    change, not a refactor of everything that reads a feed.

    `url_key` names a config entry to read instead of `url`. Absent config, or a
    key with no value, raises rather than silently falling back to a literal —
    a feed that cannot say where it lives must not quietly become a different
    feed.
    """
    key = entry.get("url_key")
    if not key:
        return entry["url"]
    value = (config or {}).get(key)
    if not value:
        raise FeedFormatError(
            "feed declares url_key=%r but no value is configured; refusing to "
            "guess a source for a blocklist." % (key,))
    return value


class FeedFormatError(ValueError):
    """A feed body that Pi-hole could not use. Raised, never returned as a flag."""


def classify_lines(text, sample=200):
    """Count domain-shaped vs CIDR-shaped lines in a feed body.

    Returns (domains, cidrs, considered). Comments and blanks are not counted in
    `considered`, so a heavily-commented file is judged on its data.
    """
    domains = cidrs = considered = 0
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        # Strip a trailing comment ("1.2.3.0/24 ; SBL123" / "evil.example # note")
        line = re.split(r"\s+[;#]", line, maxsplit=1)[0].strip()
        if not line:
            continue
        considered += 1
        if _CIDR_RE.match(line) or _CIDR6_RE.match(line):
            cidrs += 1
        elif _DOMAIN_RE.match(line):
            domains += 1
        if considered >= sample:
            break
    return domains, cidrs, considered


def validate_feed_body(text, url="<feed>"):
    """Raise FeedFormatError unless this body is something Pi-hole can ingest.

    ⛔ THE CHECK THAT WOULD HAVE CAUGHT SPAMHAUS. The roadmap asserted a feed was
    Pi-hole-compatible; nobody looked at the bytes. Adding a CIDR list to Pi-hole
    does not error loudly — gravity ingests it, matches nothing, and the feed
    sits there looking configured and protecting nothing. A feed that silently
    does nothing is worse than one that fails, because it reports as healthy.

    FAILS CLOSED on ambiguity: an empty body, an unreadable body, or a body with
    no recognisable data lines is refused rather than accepted hopefully.
    """
    domains, cidrs, considered = classify_lines(text)
    if considered == 0:
        raise FeedFormatError(
            "%s: no usable data lines (empty, or entirely comments). Refusing "
            "rather than adding a feed that cannot be shown to contain anything."
            % url)
    if cidrs and not domains:
        raise FeedFormatError(
            "%s: looks like an IP/CIDR list (%d CIDR lines, 0 domain lines in the "
            "first %d data lines). Pi-hole blocks DOMAINS; a CIDR list ingests "
            "cleanly and matches nothing. This is the Spamhaus DROP shape — see "
            "docs/roadmap/spamhaus-drop-firewall-ingest.md."
            % (url, cidrs, considered))
    if domains == 0:
        raise FeedFormatError(
            "%s: no domain-shaped lines found in the first %d data lines; "
            "cannot confirm Pi-hole can use this feed."
            % (url, considered))
    return {"domains": domains, "cidrs": cidrs, "considered": considered}
