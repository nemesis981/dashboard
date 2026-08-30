"""D4 -- personal-baseline deviation for inbound mail. PURE core.

WHAT THIS IS, AND WHAT IT IS EMPHATICALLY NOT
    A cheap per-account model of what NORMAL looks like for one mailbox --
    which correspondents recur, which attachment extensions are ordinary, how
    often mail arrives. Its output is a WEAK PRIOR that can raise or lower
    attention. It is NOT a verdict and must never become one.

    Nemesis is single-tenant, which is exactly why this is worth building: a
    per-household baseline is achievable here in a way it is not for a
    population-scale vendor.

FAIL SOFT, ALWAYS -- the property the whole design turns on
    On a thin, absent or unusable baseline the answer is `no_opinion`. NEVER
    "suspicious". A cold-start household has no history, and a model that reads
    "I have never seen this" as "this is bad" would fire hardest on exactly the
    users it exists to protect, on their first day. `MIN_MESSAGES` and
    `MIN_DISTINCT_SENDERS` are the floors, and below either of them this module
    declines to have a view.

    Equally: `sender_hash is None` means UNKNOWN (no salt configured, or no
    parseable From -- see sender_id.py). It does NOT mean "a sender never seen
    before", and conflating those would manufacture novelty out of a missing
    config value.

DRIFT IS INHERENT AND IS NOT SOLVED HERE
    A household's pattern legitimately changes -- a new job, a new supplier. This
    module bounds the damage (weak prior, fail soft) rather than pretending to
    detect drift correctly. `RECENT_WINDOW` keeps the baseline moving; it does not
    make it right.

PURE. No DB, no I/O, no clock. Callers supply history and `now`, which is what
makes every branch testable off a live mailbox.
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field

#: Floors below which this module refuses to have an opinion. Deliberately
#: conservative: a wrong "suspicious" on a new install is far more costly than a
#: missed weak prior.
MIN_MESSAGES = 50
MIN_DISTINCT_SENDERS = 5

#: A correspondent seen at least this many times counts as ESTABLISHED.
ESTABLISHED_SEEN = 3

#: Extensions at or below this share of attachment traffic are UNUSUAL for this
#: mailbox. A share, never an absolute count -- "3 .docm" means different things
#: in a 60-message and a 6,000-message history.
UNUSUAL_EXT_SHARE = 0.02

NO_OPINION = "no_opinion"
ORDINARY = "ordinary"
UNUSUAL = "unusual"


@dataclass
class Baseline:
    """Immutable-by-convention summary of one account's normal."""
    messages: int = 0
    sender_counts: dict = field(default_factory=dict)
    ext_counts: dict = field(default_factory=dict)
    attachments: int = 0

    @property
    def distinct_senders(self) -> int:
        return len(self.sender_counts)

    @property
    def usable(self) -> bool:
        """Whether this baseline has earned the right to an opinion."""
        return (self.messages >= MIN_MESSAGES
                and self.distinct_senders >= MIN_DISTINCT_SENDERS)


def build(history) -> Baseline:
    """Fold message history into a Baseline.

    `history` is an iterable of dicts with optional `sender_hash` and `extension`.
    Rows with `sender_hash=None` still count toward `messages` -- they are real
    mail -- but contribute NO sender knowledge, because None is unknown.
    """
    b = Baseline()
    sc, ec = collections.Counter(), collections.Counter()
    for row in history or ():
        b.messages += 1
        sh = (row or {}).get("sender_hash")
        if sh:
            sc[sh] += 1
        ext = ((row or {}).get("extension") or "").lower().lstrip(".")
        if ext:
            ec[ext] += 1
            b.attachments += 1
    b.sender_counts, b.ext_counts = dict(sc), dict(ec)
    return b


def assess(baseline: Baseline, *, sender_hash=None, extension=None) -> dict:
    """Weak prior for one arriving message.

    Returns {"assessment", "reasons", "confidence"}. `assessment` is one of
    NO_OPINION / ORDINARY / UNUSUAL. `confidence` is ALWAYS "low" -- this is a
    prior, and labelling it anything stronger would invite a caller to treat it
    as a verdict.
    """
    if baseline is None or not baseline.usable:
        return {"assessment": NO_OPINION, "confidence": "low",
                "reasons": ["baseline too thin (messages=%d, senders=%d; need >=%d and >=%d)"
                            % ((baseline.messages if baseline else 0),
                               (baseline.distinct_senders if baseline else 0),
                               MIN_MESSAGES, MIN_DISTINCT_SENDERS)]}

    reasons, unusual = [], False

    if sender_hash:
        seen = baseline.sender_counts.get(sender_hash, 0)
        if seen >= ESTABLISHED_SEEN:
            reasons.append("established correspondent (seen %d)" % seen)
        elif seen == 0:
            reasons.append("correspondent not seen before")
            unusual = True
        else:
            reasons.append("infrequent correspondent (seen %d)" % seen)
    else:
        # UNKNOWN, not novel. Contributes nothing in either direction.
        reasons.append("sender unknown (no token) -- not treated as new")

    ext = (extension or "").lower().lstrip(".")
    if ext:
        if baseline.attachments <= 0:
            reasons.append("no attachment history to compare against")
        else:
            share = baseline.ext_counts.get(ext, 0) / float(baseline.attachments)
            if share <= UNUSUAL_EXT_SHARE:
                reasons.append("attachment type '%s' is unusual here (%.1f%% of history)"
                               % (ext, 100 * share))
                unusual = True
            else:
                reasons.append("attachment type '%s' is ordinary here (%.1f%%)"
                               % (ext, 100 * share))

    return {"assessment": UNUSUAL if unusual else ORDINARY,
            "confidence": "low", "reasons": reasons}
