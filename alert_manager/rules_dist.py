"""Canonical resolution of a Suricata ruleset for distribution to agents.

ONE resolver, used by both the route that SERVES rules (dashboard
`api_agent_rules`) and the code that computes the digest bound into a signed
update task (hw_monitor `enqueue_rules_update`). Two copies of the search-path
list would eventually disagree, and the failure that produces is silent: the
server would attest to the digest of one file while serving another, and every
agent would reject a perfectly legitimate update with no indication of why.

WHY A DIGEST EXISTS AT ALL. Signing an update task proves the SERVER asked for a
fetch from URL X. It says nothing about the bytes actually at X. Between the two
sits a plain-HTTP GET, so anyone on the path can substitute content, and the
substituted content is a detection ruleset — the file that decides what the agent
is capable of noticing. Deleting every rule in it is a silent, total blinding
that looks identical to a successful update. Binding sha256 into the signed
envelope closes that, and it is the same shape heartbeat auth already uses:
"<device_id>|<signed_at>|<sha256(body)>".

EVERY failure here RAISES. None of these functions returns None, {} or "" for a
ruleset it could not read. A digest that falls back to a default would let an
unverifiable task be enqueued while looking like it succeeded, which is the exact
defect class this codebase tracks — an instrument reporting a value it never
measured.
"""
from __future__ import annotations

import hashlib
import os

#: The profiles an agent may ask for. Not open-ended: `profile` reaches path
#: construction below, so an unconstrained value is a traversal primitive.
VALID_PROFILES = ("office", "roaming")

#: Searched in order, first hit wins. Kept identical to what the serving route
#: historically used so this refactor changes no behaviour, only its location.
RULES_SEARCH_PATHS = (
    "/var/lib/suricata/rules/{profile}.rules",
    "/var/lib/suricata/rules/suricata.rules",
    "/etc/suricata/rules/{profile}.rules",
)

#: Refuse to distribute a ruleset larger than this. Mirrored by the agent, which
#: enforces its own copy — a bound applied only by the sender is not a bound.
MAX_RULES_BYTES = 32 * 1024 * 1024


class RulesUnavailable(Exception):
    """No ruleset could be resolved. Never signalled by a falsy return value."""


def _validate_profile(profile: str) -> str:
    if profile not in VALID_PROFILES:
        raise RulesUnavailable(
            "unknown profile %r (expected one of %s)" % (profile, ", ".join(VALID_PROFILES)))
    return profile


def resolve_rules(profile: str):
    """(path, content) for a profile, or raise RulesUnavailable.

    Returns the BYTES, not just the path. Every caller needs the content — the
    route to serve it, the enqueue path to hash it — and handing back a path
    would invite each of them to re-open the file separately, reintroducing the
    window where the two read different versions.
    """
    _validate_profile(profile)
    tried = []
    for template in RULES_SEARCH_PATHS:
        path = template.format(profile=profile)
        tried.append(path)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as fh:
                content = fh.read(MAX_RULES_BYTES + 1)
        except OSError as exc:
            # Present but unreadable is a DIFFERENT condition from absent, and
            # collapsing the two would send an operator hunting for a missing
            # file when the real problem is permissions.
            raise RulesUnavailable("%s exists but could not be read: %s" % (path, exc))
        if len(content) > MAX_RULES_BYTES:
            raise RulesUnavailable(
                "%s exceeds the %d-byte distribution limit" % (path, MAX_RULES_BYTES))
        if not content:
            # An empty ruleset detects nothing. Distributing one is
            # indistinguishable, at the agent, from a successful update.
            raise RulesUnavailable("%s is empty — refusing to distribute" % path)
        return path, content
    raise RulesUnavailable(
        "no ruleset found for profile=%s (searched: %s)" % (profile, ", ".join(tried)))


def digest_bytes(content: bytes):
    """(sha256_hex, size) for exactly these bytes."""
    return hashlib.sha256(content).hexdigest(), len(content)


def rules_digest(profile: str) -> dict:
    """What an agent must receive for this profile, or raise.

    The returned dict is embedded verbatim in the signed task envelope, so the
    signature covers the digest and the digest covers the content. Neither can
    be altered in transit without invalidating the other.
    """
    path, content = resolve_rules(profile)
    sha256, size = digest_bytes(content)
    return {"profile": profile, "sha256": sha256, "size": size, "source_path": path}
