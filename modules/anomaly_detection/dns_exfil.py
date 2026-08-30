"""DNS exfiltration / tunnelling detection — PURE core. No DB, no eve.json, no Flask.

WHAT A DNS TUNNEL ACTUALLY LOOKS LIKE, AND WHY THE EXISTING DETECTOR CANNOT SEE IT
    Malware that cannot reach its C2 over HTTP still has DNS: every network
    resolves names, so a query is an outbound channel that survives egress
    filtering. Data rides in the SUBDOMAIN LABELS of a query the attacker's own
    nameserver answers -- `<base32-payload>.tunnel.attacker.com` -- and the reply
    carries instructions back.

    `anomaly_detection`'s shipped detector cannot see this for two reasons that
    are both about DISCARDED DATA rather than weak scoring:
      1. it filters to A/AAAA, dropping TXT/NULL/CNAME/MX -- the classic carriers;
      2. `_root_domain()` collapses the FQDN to its last two labels BEFORE
         aggregation, so `<payload>.tunnel.attacker.com` becomes `attacker.com`
         and the payload -- the entire signal -- is gone before scoring starts.
    This module is fed the FULL record and the FULL name, which is the fix.

A TUNNEL IS A CHANNEL, NOT A QUERY -- the single most important design point
    No individual query is diagnostic. A 63-character label is legal, common, and
    emitted constantly by CDNs, anti-spam DNSBL lookups and AV telemetry.
    MEASURED on the build host before writing any of this: 90 A-queries carried a
    label of >=25 characters in a 40 MB sample, and the longest label seen was 63
    -- the protocol maximum. A per-query detector would fire on all of them.

    So the unit of judgement is the CHANNEL: one (client, registrable domain)
    pair, accumulated over time. Volume, distinct-name count and sustained
    encoded-looking labels are what separate a tunnel from a CDN, and none of
    them is visible one packet at a time.

FAIL SOFT, AND NEVER ON A THIN CHANNEL -- the same shape as the D4 mail baseline
    Below `MIN_CHANNEL_QUERIES` / `MIN_DISTINCT_NAMES` the verdict is
    `NO_OPINION`, never "suspicious". A household's first contact with any new
    CDN starts as a thin channel, and a detector that reads "I have not seen this
    before" as "this is bad" fires hardest on exactly the users it exists to
    protect. Novelty is not evidence.

AN ESTABLISHED CHANNEL IS NOT A TUNNEL -- the core of false-positive suppression
    A (client, domain) pair queried steadily for days, at ordinary rates, is the
    definition of normal traffic. `established` suppresses scoring outright. This
    is why the per-client-per-domain baseline is the feature, not an optimisation.

WHAT THIS DELIBERATELY DOES NOT DO
    No newly-registered-domain check. It needs an external feed, and that is
    deferred to the V2 community backend build by operator ruling -- not
    silently omitted. Its absence is why a brand-new tunnel domain scores no
    higher here than an old one.
"""
import math

# ── Channel maturity floors. Below these the module declines to have a view. ──
MIN_CHANNEL_QUERIES = 20     # a channel below this is thin, not innocent
MIN_DISTINCT_NAMES = 8       # a tunnel needs many DISTINCT names; a CDN reuses few

# An established channel -- seen across enough separate cycles over enough time --
# is ordinary traffic and is suppressed. Tunnels are bursty and new; CDNs are not.
ESTABLISHED_OBSERVATIONS = 12
ESTABLISHED_AGE_SECONDS = 6 * 3600

# ── Feature thresholds, all measured against the build host's real DNS ────────
HIGH_ENTROPY_BITS = 3.6      # Shannon bits/char over the subdomain; English ~2.5-3.0
LONG_LABEL_CHARS = 25        # 90 legitimate A-queries crossed this in a 40 MB sample,
                             # which is exactly why it is a WEAK signal and not a rule
HIGH_ENCODED_RATIO = 0.75    # share of chars that are base32/hex-ish

# Record types that carry payload in tunnelling tools far more often than in
# ordinary browsing. Their PRESENCE is a signal; their absence proves nothing,
# since a tunnel can run entirely over A queries.
CARRIER_RRTYPES = frozenset({"TXT", "NULL", "CNAME", "MX", "SRV", "ANY"})

NO_OPINION, ORDINARY, SUSPICIOUS = "no_opinion", "ordinary", "suspicious"

SCORE_FLOOR = 45             # below this no finding is raised at all
SCORE_HIGH = 70

_ENCODED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789=-")


def shannon_entropy(text: str) -> float:
    """Bits per character. Returns 0.0 for empty input — a genuine property of an
    empty string, not a failure being disguised as a measurement."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def split_name(fqdn: str, root_domain: str):
    """(subdomain, root) for a name, or (None, None) when it cannot be split.

    Explicitly returns None rather than an empty string for the unsplittable case:
    an empty subdomain is a real and common observation (a query for the bare
    registrable domain) and must not be confused with "we could not parse this".
    """
    if not fqdn or not root_domain:
        return None, None
    name = fqdn.rstrip(".").lower()
    root = root_domain.rstrip(".").lower()
    if name == root:
        return "", root
    if not name.endswith("." + root):
        return None, None
    return name[: -(len(root) + 1)], root


def name_features(subdomain: str) -> dict:
    """Per-name features. `subdomain` may legitimately be empty."""
    labels = [l for l in (subdomain or "").split(".") if l]
    joined = "".join(labels)
    encoded = sum(1 for ch in joined if ch in _ENCODED_CHARS)
    return {
        "label_count": len(labels),
        "total_len": len(joined),
        "max_label_len": max((len(l) for l in labels), default=0),
        "entropy": shannon_entropy(joined),
        "encoded_ratio": (encoded / len(joined)) if joined else 0.0,
    }


def score_channel(stats: dict) -> dict:
    """Verdict for one (client, registrable-domain) channel.

    `stats` is the accumulated channel state, not a single query. Returns a dict
    with verdict, score and the signals that produced it — the signals are
    returned so a finding can explain itself rather than asserting a number.
    """
    if not isinstance(stats, dict):
        return {"verdict": NO_OPINION, "score": 0.0,
                "reason": "unusable channel stats", "signals": {}}

    queries = int(stats.get("queries", 0) or 0)
    distinct = int(stats.get("distinct_names", 0) or 0)

    # ── FAIL SOFT: a thin channel gets no opinion, never suspicion ────────────
    if queries < MIN_CHANNEL_QUERIES or distinct < MIN_DISTINCT_NAMES:
        return {"verdict": NO_OPINION, "score": 0.0,
                "reason": "channel too thin to judge (%d queries, %d distinct names)"
                          % (queries, distinct),
                "signals": {}}

    # ── An established channel is ordinary traffic. Suppress outright. ────────
    observations = int(stats.get("observations", 0) or 0)
    age = float(stats.get("age_seconds", 0) or 0)
    if observations >= ESTABLISHED_OBSERVATIONS and age >= ESTABLISHED_AGE_SECONDS:
        return {"verdict": ORDINARY, "score": 0.0,
                "reason": "established channel (%d observations over %.1f h)"
                          % (observations, age / 3600.0),
                "signals": {}}

    signals = {}
    score = 0.0

    # Distinct-name ratio. A tunnel needs a NEW name per message, so distinct
    # names track query count almost 1:1. A CDN re-queries a small set of names.
    ratio = distinct / queries if queries else 0.0
    if ratio >= 0.9:
        score += 25
        signals["near_unique_names"] = round(ratio, 3)
    elif ratio >= 0.6:
        score += 12
        signals["mostly_unique_names"] = round(ratio, 3)

    entropy = float(stats.get("mean_entropy", 0) or 0)
    if entropy >= HIGH_ENTROPY_BITS:
        score += 25
        signals["high_entropy_bits"] = round(entropy, 2)

    encoded = float(stats.get("mean_encoded_ratio", 0) or 0)
    if encoded >= HIGH_ENCODED_RATIO:
        score += 10
        signals["encoded_charset_ratio"] = round(encoded, 3)

    # Long labels are DELIBERATELY WEAK -- 90 legitimate queries crossed this
    # threshold in a single 40 MB sample. It corroborates; it never carries a
    # finding alone, which is why it is worth so much less than the ratio signal.
    if float(stats.get("mean_max_label", 0) or 0) >= LONG_LABEL_CHARS:
        score += 8
        signals["long_labels"] = round(float(stats["mean_max_label"]), 1)

    carriers = set(stats.get("rrtypes", ()) or ()) & CARRIER_RRTYPES
    if carriers:
        score += 15
        signals["carrier_rrtypes"] = sorted(carriers)

    # Sustained volume. A tunnel moving real data is chatty in a way browsing
    # a single domain is not.
    if queries >= 200:
        score += 12
        signals["high_volume"] = queries
    elif queries >= 60:
        score += 6
        signals["elevated_volume"] = queries

    if score < SCORE_FLOOR:
        return {"verdict": ORDINARY, "score": round(score, 1),
                "reason": "below finding threshold", "signals": signals}
    return {"verdict": SUSPICIOUS, "score": round(min(score, 100.0), 1),
            "reason": "encoded-looking sustained DNS channel", "signals": signals}


# ── Self-test: prove the instrument can produce every answer it claims ────────
#
# Standing practice (`scripts/nemesis-fw-neverblock`'s CANARIES): a detector must
# prove its own premise against known-different inputs before anything trusts it.
# A tunnel detector on a clean network is silent, and silence is also what a
# detector broken at import produces. These run in the PRODUCTION path.

def _canary_tunnel():
    return {"queries": 400, "distinct_names": 396, "mean_entropy": 4.2,
            "mean_encoded_ratio": 0.95, "mean_max_label": 48,
            "rrtypes": ["TXT"], "observations": 2, "age_seconds": 600}


def _canary_cdn():
    # Deliberately shaped like the REAL false positive: long, high-entropy labels
    # from an ordinary content network. It must NOT be called a tunnel.
    #
    # ⚠ distinct_names is 40, NOT a handful, and that is load-bearing. An earlier
    # version used 6, which tripped the THIN-CHANNEL gate first -- so the canary
    # passed while never reaching the established-channel branch it exists to
    # protect. Right answer, wrong derivation: exactly the failure shape this
    # codebase catalogues. These numbers clear every earlier gate so that
    # suppression, and only suppression, is what saves it. Without the
    # established check this input scores 55 and IS reported as a tunnel.
    return {"queries": 300, "distinct_names": 40, "mean_entropy": 3.9,
            "mean_encoded_ratio": 0.9, "mean_max_label": 44,
            "rrtypes": ["A", "AAAA"], "observations": 30, "age_seconds": 86400}


def _canary_thin():
    return {"queries": 3, "distinct_names": 3, "mean_entropy": 4.5,
            "mean_encoded_ratio": 1.0, "mean_max_label": 60,
            "rrtypes": ["TXT"], "observations": 1, "age_seconds": 60}


def selftest():
    """(ok, detail). Proves the scorer returns all three verdicts on the right inputs."""
    if score_channel(_canary_tunnel())["verdict"] != SUSPICIOUS:
        return False, "canary: a textbook tunnel did not score as suspicious"
    if score_channel(_canary_cdn())["verdict"] == SUSPICIOUS:
        return False, "canary: an established CDN channel was called a tunnel"
    if score_channel(_canary_thin())["verdict"] != NO_OPINION:
        return False, "canary: a thin channel produced an opinion instead of declining"

    # The CDN canary must be saved by SUPPRESSION, not by an earlier gate. Prove
    # the derivation, not just the answer: the same channel with its established
    # history removed MUST score as a tunnel, or the check above proved nothing.
    _unestablished = dict(_canary_cdn())
    _unestablished["observations"] = 1
    _unestablished["age_seconds"] = 60
    if score_channel(_unestablished)["verdict"] != SUSPICIOUS:
        return False, ("canary: the CDN input is not actually reaching the "
                       "established-channel branch -- it is being saved by an earlier gate")
    if shannon_entropy("aaaaaaaa") >= shannon_entropy("a7f3k9x2"):
        return False, "canary: entropy does not discriminate repetitive from random"
    sub, root = split_name("payload.tunnel.attacker.com", "attacker.com")
    if sub != "payload.tunnel":
        return False, "canary: subdomain split lost the payload labels"
    return True, "6 canaries passed"
