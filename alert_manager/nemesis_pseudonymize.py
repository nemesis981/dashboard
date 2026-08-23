"""Pseudonymize network addresses before text is sent to an external model.

WHY THIS IS NOT ``diagnostics/redact.py``. That module is a secrets scrubber:
it loads known values out of ``/etc/nemesis.env`` and substring-replaces them
with ``[REDACTED]``. Its correctness condition is "did I match the known
secret" — it only ever has to recognise strings it was handed in advance, and
destroying them is the whole point.

A pseudonymizer's correctness condition is different in both halves:

  * it must RECOGNISE addresses it was never told about (pattern, not lookup), and
  * it must map them CONSISTENTLY and REVERSIBLY, because destroying them
    destroys exactly the relational reasoning the AI call exists to produce.

"192.0.2.5 is scanning 192.0.2.9" and "host-A is scanning host-B" support the
same conclusion. "[REDACTED] is scanning [REDACTED]" supports none. So the
mapping is stable within a call — the same address always becomes the same
token — and reversed on the way back so the operator still reads real
addresses.

THE MAPPING NEVER LEAVES THE NETWORK. It is returned to the caller, held for
the duration of one request, and discarded. Nothing here writes to disk or to
the database.

TWO SUBSTRING HAZARDS, BOTH REAL, BOTH HANDLED BY SINGLE-PASS REGEX
-------------------------------------------------------------------
Going out:  "192.0.2.1" is a substring of "192.0.2.10". Iterating over found
            addresses calling ``str.replace`` would corrupt the longer one.
Coming back: "host-A" is a prefix of "host-AA". The same bug mirrored.

Both are avoided the same way: ONE ``re.sub`` pass with a boundary-anchored
pattern, never a replace-loop. The regex engine consumes each match whole and
moves past it, so a shorter token can never be found inside a longer one.

FAIL-CLOSED ON AMBIGUITY. A dotted-quad that is really a version number
("build 1.2.3.4") is tokenized. Over-tokenizing costs a little prompt
fidelity; under-tokenizing leaks an address. The lookbehind does spare the
common ``v1.2.3.4`` form (a word character immediately before the digits
suppresses the match), but that is a partial mitigation, not a solution, and
is deliberately not treated as one.
"""

import ipaddress
import re

#: Tokens read as names rather than redactions, so a model treats them as
#: entities it can reason about ("host-A contacted host-B") instead of as
#: missing data it should hedge around.
_TOKEN_PREFIX = "host-"

# ── The address pattern ──────────────────────────────────────────────────────
# ORDER IS LOAD-BEARING. Alternation is first-match-wins, so the branches run
# most-specific first:
#
#   MAC before IPv6 — a MAC is colon-separated hex, so the IPv6 branch would
#     otherwise eat part of one and leave the rest behind as literal text.
#   IPv6 before IPv4 — an IPv4-mapped IPv6 address (::ffff:192.0.2.1) ENDS in
#     a valid dotted quad. IPv4-first would tokenize the tail and strand the
#     "::ffff:" prefix in the outgoing prompt.
_MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
_IPV6 = (r"(?:[0-9A-Fa-f]{0,4}:){2,7}"
         r"(?:[0-9A-Fa-f]{1,4}|\d{1,3}(?:\.\d{1,3}){3})?")
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

# The lookarounds are what make "192.0.2.1" inside "192.0.2.10" impossible, and
# what keeps a port suffix intact: ":" is absent from the trailing class, so
# "192.0.2.5:443" tokenizes the address and leaves ":443" — a port is not a
# personal identifier and is diagnostically essential, so it stays.
#
# ":" is deliberately absent from the LEADING class too. Excluding it would
# break "src:192.0.2.5", a shape that appears in real signature text, and it
# is not needed for IPv6 disambiguation — branch order already handles that.
_ADDR_RE = re.compile(
    r"(?<![\w.\-])(?:" + _MAC + r"|" + _IPV6 + r"|" + _IPV4 + r")(?![\w.\-])"
)

#: Names get their OWN token namespace. Addresses and names are different kinds
#: of identifier and a reader (human or model) benefits from knowing which is
#: which -- "device-A at host-B" says more than "host-A at host-B". It also means
#: adding name coverage could not renumber or collide with existing address
#: tokens, so `resolve()` on an old mapping keeps working unchanged.
_NAME_PREFIX = "device-"

#: Boundary-anchored so "host-A" cannot match inside "host-AA". ``[A-Z]+`` is
#: greedy, so the longest run is always captured and looked up whole.
_TOKEN_RE = re.compile(
    r"\b(?:" + _TOKEN_PREFIX + r"|" + _NAME_PREFIX + r")([A-Z]+)\b")

#: A supplied name shorter than this is NOT scrubbed. A 2-3 character "name"
#: ("PC", "TV", "NAS") appears inside ordinary words and punctuation and would
#: shred the surrounding text for no privacy gain -- it identifies nobody.
_MIN_NAME_LEN = 4

#: Generic names that identify NOTHING and appear as ordinary vocabulary in a
#: security prompt. A device literally named "Router" is real and common, and
#: tokenizing every occurrence of the word "router" would destroy the model's
#: ability to reason about the network while protecting no one.
#:
#: THE LINE THIS DRAWS, STATED PLAINLY: the goal is to remove data that
#: IDENTIFIES a person or household, not to remove every string that happens to
#: be stored in a name column. "Reception-Laptop" and "Pauls-iPhone" identify;
#: "printer" does not. Anything not on this list is scrubbed, so the default is
#: still to protect.
_GENERIC_NAMES = frozenset({
    "router", "gateway", "switch", "printer", "laptop", "desktop", "server",
    "phone", "tablet", "camera", "unknown", "localhost", "device", "computer",
    "firewall", "modem", "access point", "network", "guest", "host",
})


def _scrubbable_names(names):
    """Filter + order supplied names for substitution.

    LONGEST FIRST, and that ordering is load-bearing: with "Reception" and
    "Reception-Laptop" both known, shortest-first would rewrite the prefix and
    strand "-Laptop" in the outgoing text, which leaks the distinguishing half
    of the name while looking like it worked.
    """
    seen, out = set(), []
    for raw in names or ():
        if not isinstance(raw, str):
            continue
        name = raw.strip()
        key = name.casefold()
        if (len(name) < _MIN_NAME_LEN or key in _GENERIC_NAMES or key in seen):
            continue
        seen.add(key)
        out.append(name)
    out.sort(key=len, reverse=True)
    return out


def _looks_like_mac(value: str) -> bool:
    return bool(re.fullmatch(_MAC, value))


def _is_real_address(value: str) -> bool:
    """True when ``value`` is an address worth pseudonymizing.

    A MAC is accepted on pattern alone (there is no stdlib validator and the
    pattern is unambiguous). An IP is accepted only if ``ipaddress`` parses it,
    which rejects near-misses like "999.999.999.999" and "1.2.3.4.5".

    DELIBERATELY NO PUBLIC/PRIVATE BRANCH. Every address is tokenized. A LAN
    address identifies a device on this network and is precisely the data being
    protected, so "only pseudonymize public addresses" would be backwards. It
    would also be untestable in this repo without a trap: Python classifies all
    three RFC 5737 TEST-NET blocks — the convention this codebase uses for test
    addresses — as ``is_private``, so any private-branching logic would be
    silently skipped by its own fixtures and pass without executing.
    """
    if _looks_like_mac(value):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _token_for(index: int) -> str:
    """A, B, ... Z, AA, AB, ... — spreadsheet-column style, unbounded."""
    letters = ""
    n = index
    while True:
        letters = chr(ord("A") + (n % 26)) + letters
        n = n // 26 - 1
        if n < 0:
            return _TOKEN_PREFIX + letters


def pseudonymize(text, names=None):
    """Replace every network address -- and every supplied device name -- in
    ``text`` with a stable token.

    Returns ``(clean_text, mapping)`` where ``mapping`` is ``{token: original}``.

    ``names`` is an iterable of known device/host names. It must be SUPPLIED:
    a name is not pattern-recognisable the way an address is, so there is no way
    to detect one from the text alone. The caller that knows the fleet passes
    them in (`ai_engine` reads them from the devices tables at the chokepoint).
    Passing nothing keeps the previous address-only behaviour exactly.

    NAMES ARE SUBSTITUTED BEFORE ADDRESSES. A name is the longer, more specific
    unit, and some real device names contain digits and dots; scrubbing
    addresses first could bite a chunk out of one and leave the remainder
    behind as a partial leak.

    Tokens are assigned in first-appearance order, and a repeated address always
    receives the token it was given the first time — that repetition is what
    lets a model say "the same host appears on both sides of this".

    An empty or address-free input returns the text unchanged with an EMPTY
    mapping, which is a real result, not a failure. The caller distinguishes
    them by the text, never by the mapping being empty.
    """
    if not text:
        return text, {}

    assigned = {}   # address -> token, so a repeat address reuses its token
    mapping = {}    # token -> address, the direction resolve() needs

    # ── names first (see docstring) ───────────────────────────────────────────
    name_assigned = {}
    for _n, canonical in enumerate(_scrubbable_names(names)):
        # Case-insensitive: the same device is written "Reception-Laptop" in one
        # place and "reception-laptop" in another, and a leak is a leak in either
        # case. The mapping stores the CANONICAL spelling from the devices table,
        # so what the operator sees resolved back is the name they actually know
        # the device by, not whichever casing the prompt happened to use.
        pattern = re.compile(r"(?<![\w-])" + re.escape(canonical) + r"(?![\w-])",
                             re.IGNORECASE)
        if not pattern.search(text):
            continue                      # not mentioned; do not mint a token
        token = _NAME_PREFIX + _token_for(len(name_assigned))[len(_TOKEN_PREFIX):]
        name_assigned[canonical.casefold()] = token
        mapping[token] = canonical
        text = pattern.sub(token, text)

    def _sub(match):
        raw = match.group(0)
        if not _is_real_address(raw):
            # Not an address: leave it exactly as written. Something that
            # merely looks address-shaped is not a leak, and rewriting it
            # would corrupt real content for no privacy gain.
            return raw
        token = assigned.get(raw)
        if token is None:
            token = _token_for(len(assigned))
            assigned[raw] = token
            mapping[token] = raw
        return token

    return _ADDR_RE.sub(_sub, text), mapping


def resolve(text, mapping):
    """Turn tokens in ``text`` back into the real addresses from ``mapping``.

    An UNKNOWN token is left exactly as-is rather than raising or blanking.
    A model can invent "host-Q" when only host-A and host-B were supplied, and
    the honest handling of that is to show the operator that the model referred
    to something that was never in its input — not to crash the request, and
    not to silently delete the evidence that it happened.
    """
    if not text or not mapping:
        return text
    return _TOKEN_RE.sub(
        lambda m: mapping.get(m.group(0), m.group(0)), text
    )
