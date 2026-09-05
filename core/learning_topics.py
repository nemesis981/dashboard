"""Learning Center — the built-in topic registry.

Built-in topics are CODE: they ship with Nemesis, are versioned with it, and are
replaced by upgrades. Business-authored custom content (phase 2) is DB rows, owned by
the business and never touched by an upgrade. That split is structural rather than a
label, and it is what keeps the two distinguishable in the UI without relying on
anyone remembering to tag them.

⛔ A TOPIC BEING REGISTERED HERE GRANTS NOTHING.
    Registration means "this topic exists and has content". Whether anyone may READ it
    is decided entirely by `core/learning.py:visible_to()` — the three-state ceiling
    plus a per-user entitlement. A topic added here with no visibility row configured
    is invisible to everyone including admins, which is the intended default now that
    content ships with core unconditionally.

⛔ TIER VARIANTS ARE PRESENTATION, NOT ACCESS CONTROL.
    Each body carries `beginner`/`intermediate`/`pro` text, rendered through the
    existing `data-beginner`/`data-intermediate`/`data-pro` mechanism that `tier.js`
    swaps client-side from localStorage. The server emits ALL THREE variants because it
    cannot read localStorage — so pro text is physically in the DOM for a beginner
    reader. That is fine for prose and is why no capability may ever be gated on tier.

The two topics below are PLACEHOLDERS that exercise the machinery end to end. Real
curriculum content is dropped in as additional entries with no code change.
"""

#: slug -> topic. `slug` must match `^[a-z0-9_-]+$` (checked by `is_valid_slug`) so it
#: can be a URL path segment and a stable database key without escaping.
_TOPICS = {
    "network_basics": {
        "title": "Network Security Basics",
        "summary": "What a firewall does, what it cannot do, and why both matter.",
        "sections": [
            {
                "heading": "What a firewall actually does",
                "beginner": (
                    "A firewall is a gate between your home network and the internet. "
                    "It checks traffic against rules and blocks what does not belong. "
                    "It is not a guarantee that nothing bad gets in &mdash; it is one "
                    "layer, and the most useful thing you can do is understand what it "
                    "does not cover."),
                "intermediate": (
                    "A firewall enforces policy on traffic crossing a boundary, by "
                    "address, port and protocol. It is a boundary control: traffic "
                    "already inside the network, between two devices on the same "
                    "switch, never crosses it and is not inspected."),
                "pro": (
                    "Stateful boundary filtering on the WAN edge. Lateral east-west "
                    "traffic on a flat L2 segment never transits the gateway, so it is "
                    "outside the enforcement path entirely &mdash; a topology property, "
                    "not a tuning gap."),
            },
        ],
    },
    "phishing_awareness": {
        "title": "Recognising Phishing",
        "summary": "Why phishing works on careful people, and what actually helps.",
        "sections": [
            {
                "heading": "Phishing is not about being gullible",
                "beginner": (
                    "Most people who get caught by a phishing email were not being "
                    "careless. The messages are designed to arrive when you are busy "
                    "and to look like something you were already expecting. Slowing "
                    "down on anything that creates urgency is worth more than trying "
                    "to spot a fake by eye."),
                "intermediate": (
                    "Phishing exploits context and timing rather than technical "
                    "weakness. Manufactured urgency suppresses verification, so the "
                    "durable defence is a habit &mdash; verify through a channel you "
                    "chose &mdash; rather than an ability to detect a convincing "
                    "message."),
                "pro": (
                    "Human-layer attack; the failure is procedural, not technical. "
                    "Out-of-band verification against an independently-obtained "
                    "contact path is the only control that survives a message good "
                    "enough to defeat inspection."),
            },
        ],
    },
}

_SLUG_OK = set("abcdefghijklmnopqrstuvwxyz0123456789_-")

#: The tier keys every section must carry. Missing one is a build error, not a
#: runtime fallback: silently substituting another tier's text would show a beginner
#: the pro wording and nobody would find out from the page.
TIERS = ("beginner", "intermediate", "pro")


def is_valid_slug(slug):
    """A slug safe to use as a URL segment and a DB key, with no escaping."""
    return (isinstance(slug, str) and 0 < len(slug) <= 64
            and all(c in _SLUG_OK for c in slug))


def all_slugs():
    """Every built-in topic slug, sorted. Says nothing about who may see them."""
    return sorted(_TOPICS)


def get_topic(slug):
    """One topic, or None. None means 'no such content', NOT 'not permitted'.

    The two are deliberately different answers: the route turns both into the same
    response to the caller, but conflating them here would make a missing topic
    indistinguishable from a permission failure in the logs.
    """
    if not is_valid_slug(slug):
        return None
    return _TOPICS.get(slug)


def exists(slug):
    return get_topic(slug) is not None


def selftest():
    """Every registered topic is well-formed. Returns (ok, detail); never raises.

    Checks the registry can actually be rendered, because a missing tier variant
    would otherwise surface as blank text on a page rather than as an error.
    """
    try:
        if not _TOPICS:
            return False, "registry is empty"
        for slug, t in _TOPICS.items():
            if not is_valid_slug(slug):
                return False, "invalid slug %r" % slug
            for key in ("title", "summary", "sections"):
                if not t.get(key):
                    return False, "topic %r missing %r" % (slug, key)
            for i, sec in enumerate(t["sections"]):
                if not sec.get("heading"):
                    return False, "topic %r section %d has no heading" % (slug, i)
                for tier in TIERS:
                    if not sec.get(tier):
                        return False, ("topic %r section %d missing %r variant "
                                       "-- would render blank" % (slug, i, tier))
        return True, "%d topics, all tiers present" % len(_TOPICS)
    except Exception as e:
        return False, "selftest raised: %s: %s" % (type(e).__name__, e)
