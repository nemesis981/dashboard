"""Domain / IP lookup — the pure core (no Flask, no DB, no routes).

WHY THIS EXISTS
    Anomaly detection has flagged 148 distinct domains, 148 incidents still open,
    none above medium score. The samples are ordinary CDN and ad domains. An
    operator looking at that list has no way, from the dashboard, to ask the first
    question anyone would ask: *what is this domain?* They must leave the product
    and use a terminal. This closes that.

WHY IT IS NOT A `diagnostics/` CHECK
    That package's contract is `run()` with NO arguments — twelve fixed checks
    with no user input. An interactive tool cannot be expressed in it. Per
    CLAUDE.md ("everything new is a MODULE") this lives in `modules/lookup/`, and
    this file is the part with no framework in it so it can be tested directly.

READ-ONLY BY CONSTRUCTION
    `dig` and `whois` are queries. They emit traffic FROM THE APPLIANCE ONLY and
    task no remote machine, which is what keeps this side of the boundary the
    diagnostics master plan draws: read-only diagnostics first, anything that
    tasks a remote machine behind an authorization + consent layer. Ping,
    traceroute, port scan and packet capture are deliberately NOT here.

TIERING IS RULE-BASED, NOT AI-GENERATED — a deliberate choice
    The only existing precedent for tiered OUTPUT is the AI alert explanation,
    which costs a billed model call and is populated on 2 of 27 alerts. Lookup
    results are structured facts (age, resolver answers, nameservers), and rules
    over structured facts are deterministic, free, instant, and testable — which
    matters because every rule here is mutation-tested. An AI summary can be
    layered on later for the cases rules cannot judge; it is the wrong default for
    "when was this domain registered".
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from datetime import datetime, timezone

#: Hard cap per external command. `whois` in particular can hang on an
#: unresponsive registry server, and a hung lookup would occupy a request worker.
LOOKUP_TIMEOUT = 8

#: Conservative hostname shape. Labels of alphanumerics and hyphens, no leading
#: or trailing hyphen, dot-separated, max 253 chars overall.
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")

KIND_DOMAIN = "domain"
KIND_IPV4 = "ipv4"
KIND_IPV6 = "ipv6"
KIND_INVALID = "invalid"


class LookupRefused(Exception):
    """The target was refused before any command ran.

    An exception rather than an empty result: an empty result is a legal answer
    for a domain that genuinely resolves to nothing, and the caller could not tell
    the two apart.
    """


def classify_target(raw):
    """What kind of thing the operator typed. Returns (kind, normalised).

    SECURITY — argument injection, and TWO INDEPENDENT defences against it.

    Every command runs as an argv LIST, never a shell string, so shell
    metacharacters are already inert. But argv does not protect against a target
    that IS a flag: `-h` or `--host=evil` is passed positionally and the TOOL
    parses it as an option, which for `whois` means redirecting the query to a
    server of the caller's choosing. That survives every shell-focused defence.

    Two guards refuse it, and testing showed which is which — the first version
    of this docstring got it backwards:

      1. PRIMARY: `_HOSTNAME_RE` anchors on `(?!-)`, so a leading dash cannot
         match a hostname at all; and a target with no dot is refused as a bare
         label. Between them these already refuse `-h`, `--verbose`, `--`, and
         `--host=evil.example`.
      2. DEFENCE IN DEPTH: the explicit leading-dash test below. It is REDUNDANT
         with (1) today — verified, not assumed — and kept because it states the
         intent at the top of the function where a future edit to the regex
         cannot silently remove it.

    Plus `--` on every invocation to end option parsing. Three layers, and the
    tests assert each independently rather than trusting that one covers the rest.
    """
    if raw is None:
        return KIND_INVALID, ""
    text = str(raw).strip().lower()
    if not text:
        return KIND_INVALID, ""
    if len(text) > 253:
        return KIND_INVALID, ""
    if text.startswith("-"):
        # See the docstring. Refused before anything else is considered.
        return KIND_INVALID, ""
    # Strip a scheme and any path the operator pasted from a browser.
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0]
    # A bracketed IPv6 literal, or host:port.
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    if not text:
        return KIND_INVALID, ""
    try:
        ip = ipaddress.ip_address(text)
        return (KIND_IPV4 if ip.version == 4 else KIND_IPV6), str(ip)
    except ValueError:
        pass
    text = text.rstrip(".")
    if "." not in text:
        # A bare label is not something either tool can answer usefully.
        return KIND_INVALID, ""
    if not _HOSTNAME_RE.match(text):
        return KIND_INVALID, ""
    return KIND_DOMAIN, text


def _run(argv, timeout=LOOKUP_TIMEOUT):
    """Run a command. Returns (rc, combined_output). Never raises.

    rc 127 means the binary is absent — distinct from a command that ran and
    failed, because "whois is not installed" and "the registry refused" need
    different things said to the operator.
    """
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "<timed out after %ss>" % timeout
    except FileNotFoundError:
        return 127, "<command not found>"
    except Exception as exc:                                 # noqa: BLE001
        return 1, "<error: %s>" % type(exc).__name__


# ── dig ──────────────────────────────────────────────────────────────────────

def dig_argv(target, rrtype="A"):
    """argv for a DNS lookup. `--` is unnecessary for dig but the target is
    already validated; the type is constrained to a fixed set by the caller."""
    return ["dig", "+noall", "+answer", "+time=3", "+tries=1", target, rrtype]


#: Record types offered. A closed set, not free text: an arbitrary string here
#: would be passed to dig as an argument, and the point of validating the target
#: is lost if the type beside it is unconstrained.
RRTYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


def parse_dig(output):
    """Answer-section lines -> [{name, ttl, type, value}]. Never raises.

    dig's +answer format is whitespace-separated:
        example.com.  300  IN  A  93.184.216.34
    """
    rows = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 5 or parts[2].upper() != "IN":
            continue
        name, ttl, _cls, rtype, value = parts
        try:
            ttl = int(ttl)
        except ValueError:
            continue
        rows.append({"name": name.rstrip("."), "ttl": ttl,
                     "type": rtype.upper(), "value": value.strip()})
    return rows


# ── whois ────────────────────────────────────────────────────────────────────

def whois_argv(target):
    """argv for a whois query. `--` ends option parsing (see classify_target)."""
    return ["whois", "--", target]


#: Field aliases across registries. whois output is not standardised; these are
#: the spellings actually seen in practice.
_WHOIS_FIELDS = {
    "registrar":  ("registrar", "registrar name", "sponsoring registrar"),
    "created":    ("creation date", "created", "created on", "registered on",
                   "domain registration date"),
    "expires":    ("registry expiry date", "expiry date", "expires",
                   "expiration date", "registrar registration expiration date"),
    "updated":    ("updated date", "last updated", "last modified"),
    "org":        ("registrant organization", "org", "orgname", "organization"),
    "country":    ("registrant country", "country"),
    "status":     ("domain status", "status"),
}


def parse_whois(output):
    """whois text -> {field: value} plus `nameservers`. Never raises.

    Only the FIRST occurrence of a field is kept. Registries commonly repeat a
    key across referral blocks, and the first is the authoritative one; taking the
    last silently prefers whichever server answered most verbosely.
    """
    found, nameservers = {}, []
    for line in (output or "").splitlines():
        if ":" not in line:
            continue
        key, _sep, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value or value.startswith("http"):
            continue
        if key in ("name server", "nserver", "nameserver"):
            ns = value.split()[0].rstrip(".").lower()
            if ns and ns not in nameservers:
                nameservers.append(ns)
            continue
        for canon, aliases in _WHOIS_FIELDS.items():
            if key in aliases and canon not in found:
                found[canon] = value
                break
    found["nameservers"] = nameservers
    return found


_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                 "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                 "%d-%b-%Y", "%Y.%m.%d")


def parse_date(text):
    """A whois date -> aware datetime, or None. Never raises, never guesses.

    None rather than a fallback date: every datetime is a legal answer, and a
    fabricated one would flow straight into the age judgement below and produce a
    confident wrong verdict about how established a domain is.
    """
    if not text:
        return None
    raw = str(text).strip().split("|")[0].strip()
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ── Judgement: the rules behind the beginner tier ────────────────────────────

#: A domain younger than this is worth a second look. Not a verdict — plenty of
#: legitimate services are new — but domain age is the single most useful cheap
#: signal available here, and newly-registered domains are disproportionately
#: represented in phishing and malware infrastructure.
YOUNG_DOMAIN_DAYS = 90

AGE_ESTABLISHED = "established"
AGE_YOUNG = "young"
AGE_UNKNOWN = "unknown"


def domain_age(created, now=None):
    """(bucket, days) from a creation date. AGE_UNKNOWN when it cannot be read.

    Unknown is a real third answer, never folded into either other bucket. Many
    registries withhold dates, and treating "withheld" as "established" would put
    a reassuring label on a domain nobody has actually vouched for.
    """
    dt = parse_date(created) if not isinstance(created, datetime) else created
    if dt is None:
        return AGE_UNKNOWN, None
    now = now or datetime.now(timezone.utc)
    days = (now - dt).days
    if days < 0:
        # A creation date in the future is a parse or registry error, not a fact.
        return AGE_UNKNOWN, None
    return (AGE_YOUNG if days < YOUNG_DOMAIN_DAYS else AGE_ESTABLISHED), days


# ── Tiering: one lookup, three readers ───────────────────────────────────────
#
# Method 2 of the tier system (data-attributes) is what the caller must use to
# render these, because the result is injected after page load and `tierText()`
# would freeze at render time. The SERVER SENDS ALL THREE and the browser picks —
# the tier preference is browser-local (`localStorage.explanationTier`) and never
# reaches the server, so a single tier-aware string is not possible by design.
#
# The three differ in DEPTH AND VOCABULARY, not merely in length — the same rule
# the AI explanation prompt sets for itself. Beginner also carries a GUIDED NEXT
# STEP, which the other two deliberately omit: a professional does not need to be
# told to look at the nameservers.

#: Addresses that mean "something deliberately answered NOTHING here" rather than
#: a real destination. A DNS sinkhole — which is exactly what this appliance's own
#: Pi-hole does to a blocked domain — answers with one of these.
#:
#: FOUND BY TESTING AGAINST REAL DATA, not anticipated: the first live lookup was
#: `amazon-adsystem.com`, a domain this box's own anomaly detector had flagged. It
#: returned 0.0.0.0, and the beginner text read "points at 1 address on the
#: internet" — which is not merely imprecise, it is the opposite of what happened.
#: For a backlog dominated by ad and tracker domains, a sinkholed answer is the
#: COMMONEST case, so getting it wrong would mislead on most lookups the operator
#: actually performs.
SINKHOLE_ADDRS = frozenset({"0.0.0.0", "::", "0000:0000:0000:0000:0000:0000:0000:0000",
                            "127.0.0.1", "::1"})


def is_sinkholed(records):
    """True when every A/AAAA answer is a sinkhole address.

    ALL, not any: a domain with one real address and one loopback is not blocked,
    it is oddly configured, and calling that "blocked" would be a confident wrong
    answer in the other direction.
    """
    addrs = [r["value"] for r in records if r["type"] in ("A", "AAAA")]
    return bool(addrs) and all(a in SINKHOLE_ADDRS for a in addrs)


TIERS = ("beginner", "intermediate", "pro")


def tier_domain_result(target, records, whois_fields, age_bucket, age_days,
                       raw_output=""):
    """Three explanations of one domain lookup. Returns {tier: text}.

    `raw_output` is handed through verbatim for the pro tier — a professional
    asked for the lookup, not for our summary of it.
    """
    addrs = [r["value"] for r in records if r["type"] in ("A", "AAAA")]
    registrar = whois_fields.get("registrar") or ""
    org = whois_fields.get("org") or ""
    ns = whois_fields.get("nameservers") or []

    # ---- beginner: plain language + what to do next -------------------------
    if is_sinkholed(records):
        b = ("%s is being BLOCKED on your own network. The answer came back as a "
             "dead-end address, which is what your Pi-hole ad and tracker blocking "
             "does to a domain on its block list — the request never left your "
             "network." % target)
        b_next = ("Next: nothing is wrong. This is your blocking working. If you "
                  "WANT this domain to work, allow it in Pi-hole.")
    elif not addrs:
        b = ("%s does not currently point at any address. That usually means the "
             "name is unused, has been taken down, or was mistyped." % target)
        b_next = ("Next: check the spelling. If it came from an alert, the name "
                  "may have already been shut down — which is worth knowing.")
    else:
        b = ("%s currently points at %d address%s on the internet."
             % (target, len(addrs), "" if len(addrs) == 1 else "es"))
        b_next = ""

    if age_bucket == AGE_YOUNG:
        b += (" It was registered only %d days ago. Most established services "
              "have been registered for years, so a very new name is worth a "
              "closer look — though plenty of legitimate sites are new too."
              % age_days)
        b_next = ("Next: if you did not expect this name, treat it with "
                  "suspicion. Check which of your devices contacted it.")
    elif age_bucket == AGE_ESTABLISHED:
        years = age_days // 365
        b += (" It has been registered for %s, which is typical of an "
              "established service rather than something set up recently."
              % ("%d years" % years if years >= 1 else "%d days" % age_days))
    else:
        b += (" How long it has been registered could not be determined — some "
              "registries do not publish that, so this is not itself suspicious.")
        b_next = b_next or ("Next: the owner details below are the most useful "
                            "thing to check when the age is unknown.")
    if org:
        b += " It is registered to %s" % org + ("" if org.endswith(".") else ".")
    if b_next:
        b += " " + b_next

    # ---- intermediate: the facts, no hand-holding ---------------------------
    if is_sinkholed(records):
        m_bits = ["%s -> %s (SINKHOLED — blocked locally, not a real destination)"
                  % (target, ", ".join(addrs))]
    else:
        m_bits = ["%s -> %s" % (target, ", ".join(addrs) if addrs else "no A/AAAA record")]
    if age_bucket != AGE_UNKNOWN:
        m_bits.append("registered %d days ago" % age_days)
    if registrar:
        m_bits.append("registrar %s" % registrar)
    if ns:
        m_bits.append("NS %s" % ", ".join(ns[:3]))
    m = ". ".join(m_bits) + "."

    # ---- pro: the raw answer -----------------------------------------------
    p = raw_output.strip() or "\n".join(
        "%-24s %-6d %-6s %s" % (r["name"], r["ttl"], r["type"], r["value"])
        for r in records) or "(no records)"

    return {"beginner": b, "intermediate": m, "pro": p}


# ── Orchestration ────────────────────────────────────────────────────────────

def lookup_domain(target, rrtype="A", runner=None, now=None):
    """One domain lookup: dig + whois + judgement + three tiers.

    `runner` is injected so the whole path is testable with no network. Raises
    LookupRefused for a target that fails validation — never runs a command on an
    unvalidated string.
    """
    runner = runner or _run
    kind, norm = classify_target(target)
    if kind == KIND_INVALID:
        raise LookupRefused(
            "%r is not a domain name or IP address this tool can look up" % (target,))
    if rrtype not in RRTYPES:
        raise LookupRefused(
            "record type %r is not one of %s" % (rrtype, ", ".join(RRTYPES)))

    dig_rc, dig_out = runner(dig_argv(norm, rrtype))
    records = parse_dig(dig_out) if dig_rc == 0 else []

    problems = []
    if dig_rc == 127:
        problems.append(("E-LOOKUP-001", "dig is not installed"))
    elif dig_rc == 124:
        problems.append(("E-LOOKUP-002", "the DNS lookup timed out"))

    fields, whois_out = {}, ""
    if kind == KIND_DOMAIN:
        w_rc, whois_out = runner(whois_argv(norm))
        # whois exits non-zero for "no match", which is a real answer, so the
        # output is parsed regardless and only the absent/timeout cases are faults.
        fields = parse_whois(whois_out)
        if w_rc == 127:
            problems.append(("E-LOOKUP-003", "whois is not installed"))
        elif w_rc == 124:
            problems.append(("E-LOOKUP-004", "the whois lookup timed out"))
    bucket, days = domain_age(fields.get("created"), now=now)

    raw = dig_out
    if whois_out:
        raw = (raw + "\n\n--- whois ---\n" + whois_out).strip()
    tiers = tier_domain_result(norm, records, fields, bucket, days, raw_output=raw)

    return {"target": norm, "kind": kind, "rrtype": rrtype,
            "records": records, "whois": fields,
            "age_bucket": bucket, "age_days": days,
            "explanation": tiers, "problems": problems}


# ── Canary — the shared harness, not a sixth hand-rolled one ─────────────────

def _load_harness():
    """The diagnostics canary harness. Imported by path: this module lives in a
    different package, and the harness is deliberately not a check so it is not
    exported from `diagnostics/__init__`'s CHECKS list."""
    import importlib.util
    import os
    p = os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), "diagnostics", "canary.py")
    spec = importlib.util.spec_from_file_location("lookup_canary_harness", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_H = _load_harness()


def _fake(dig_out="", whois_out="", dig_rc=0, whois_rc=0):
    """A runner returning canned output, so the canary needs no network."""
    def run(argv, timeout=None):
        return (dig_rc, dig_out) if argv[0] == "dig" else (whois_rc, whois_out)
    return run


_DIG_OK = "example.com.\t300\tIN\tA\t93.184.216.34"
_WHOIS_OLD = "Registrar: Example Registrar\nCreation Date: 2001-01-01T00:00:00Z\n"
_WHOIS_NEW = "Registrar: Example Registrar\nCreation Date: 2026-08-01T00:00:00Z\n"
_NOW = datetime(2026, 8, 23, tzinfo=timezone.utc)


def _refused(target):
    """Truthy when the target is refused — the shape the harness expects."""
    try:
        lookup_domain(target, runner=_fake(_DIG_OK), now=_NOW)
        return None
    except LookupRefused as e:
        return str(e)


CASES = [
    # --- target validation: what must be REFUSED (argument injection first) ---
    _H.bad("a leading-dash target is refused (argv injection)",
           lambda: _refused("-h")),
    _H.bad("a --flag= target is refused",
           lambda: _refused("--host=evil.example")),
    _H.bad("an empty target is refused", lambda: _refused("")),
    _H.bad("a bare label is refused", lambda: _refused("localhost")),
    _H.bad("an over-long target is refused", lambda: _refused("a" * 300)),
    _H.bad("a target with a space is refused", lambda: _refused("ex ample.com")),
    _H.bad("an unknown record type is refused",
           lambda: (lambda: _refused_type())()),
    # --- each defence layer asserted INDEPENDENTLY --------------------------
    # (Testing showed the explicit dash guard is redundant with the hostname
    # regex. Both are kept, and both are pinned, so removing either is visible.)
    _H.bad("whois argv ends option parsing with `--`",
           lambda: ("--" in whois_argv("example.com")
                    and whois_argv("example.com").index("--")
                    < whois_argv("example.com").index("example.com")) or None),
    _H.bad("the hostname regex refuses a leading dash on its own",
           lambda: (not _HOSTNAME_RE.match("-lead.com")) or None),
    _H.bad("a target with no dot is refused as a bare label",
           lambda: _refused("nodots")),
    _H.bad("a target with an illegal character is refused",
           lambda: _refused("exa$mple.com")),
    # --- CONTROL: real targets must NOT be refused ---------------------------
    _H.good("a plain domain is accepted", lambda: _refused("example.com")),
    _H.good("a pasted URL is accepted", lambda: _refused("https://example.com/x?y=1")),
    _H.good("an IPv4 literal is accepted", lambda: _refused("192.0.2.5")),
    _H.good("a trailing-dot FQDN is accepted", lambda: _refused("example.com.")),
    # --- parsing: a BAD case must RETURN the evidence it found ------------
    # (An earlier version returned None on success, which the harness correctly
    # read as "reported nothing" and failed. The thunk's return value IS the
    # finding; it is not an assertion that happens to be true.)
    _H.bad("dig output is actually parsed",
           lambda: parse_dig(_DIG_OK) or None),
    _H.good("dig comment lines yield no records",
            lambda: parse_dig("; a comment\n;; another") or None),
    _H.good("garbage yields no records",
            lambda: parse_dig("total nonsense here") or None),
    _H.good("a malformed TTL is skipped, not crashed on",
            lambda: parse_dig("example.com. NOTANUMBER IN A 1.2.3.4") or None),
    _H.bad("whois fields are extracted",
           lambda: parse_whois(_WHOIS_OLD).get("registrar")),
    _H.good("a whois line with no colon yields nothing",
            lambda: parse_whois("no colon on this line").get("registrar")),
    _H.bad("nameservers are collected",
           lambda: parse_whois("Name Server: ns1.example.com\n").get("nameservers")),
    # --- age judgement: all three buckets reachable -----------------------
    _H.bad("an old domain reads as established",
           lambda: domain_age("2001-01-01T00:00:00Z", now=_NOW)[0]
           == AGE_ESTABLISHED or None),
    _H.bad("a new domain reads as young",
           lambda: domain_age("2026-08-01T00:00:00Z", now=_NOW)[0]
           == AGE_YOUNG or None),
    _H.bad("an unparseable date reads as UNKNOWN, not established",
           lambda: domain_age("not a date", now=_NOW)[0] == AGE_UNKNOWN or None),
    _H.bad("a FUTURE creation date reads as UNKNOWN, not as a real age",
           lambda: domain_age("2030-01-01T00:00:00Z", now=_NOW)[0]
           == AGE_UNKNOWN or None),
    _H.good("an established domain is NOT flagged young",
            lambda: (domain_age("2001-01-01T00:00:00Z", now=_NOW)[0]
                     == AGE_YOUNG) or None),
    # --- tiering: three genuinely different texts -------------------------
    _H.bad("all three tiers are produced",
           lambda: set(_tiers_for(_WHOIS_OLD)) == set(TIERS) or None),
    _H.bad("the three tiers are NOT identical",
           lambda: len(set(_tiers_for(_WHOIS_OLD).values())) == 3 or None),
    _H.bad("a young domain is called out to the beginner",
           lambda: "days ago" in _tiers_for(_WHOIS_NEW)["beginner"] or None),
    _H.bad("the beginner tier carries a guided next step",
           lambda: "Next:" in _tiers_for(_WHOIS_NEW)["beginner"] or None),
    _H.good("the PRO tier carries no hand-holding",
            lambda: "Next:" in _tiers_for(_WHOIS_NEW)["pro"] or None),
    # --- sinkhole detection (REGRESSION: shipped a wrong answer on the very
    #     first real lookup — see SINKHOLE_ADDRS) --------------------------
    _H.bad("an all-0.0.0.0 answer is recognised as sinkholed",
           lambda: is_sinkholed([{"type": "A", "value": "0.0.0.0"}]) or None),
    _H.bad("an IPv6 sinkhole is recognised",
           lambda: is_sinkholed([{"type": "AAAA", "value": "::"}]) or None),
    _H.bad("a sinkholed domain tells the beginner it is BLOCKED",
           lambda: "BLOCKED" in _tiers_sink()["beginner"] or None),
    _H.bad("...and says the blocking is working, not that something is wrong",
           lambda: "nothing is wrong" in _tiers_sink()["beginner"] or None),
    _H.good("a real address is NOT called sinkholed",
            lambda: is_sinkholed([{"type": "A", "value": "93.184.216.34"}]) or None),
    _H.good("NO records is not 'sinkholed' (it is a different answer)",
            lambda: is_sinkholed([]) or None),
    _H.good("a MIXED answer is not called blocked",
            lambda: is_sinkholed([{"type": "A", "value": "0.0.0.0"},
                                  {"type": "A", "value": "93.184.216.34"}]) or None),
    _H.good("a real lookup is not described as blocked",
            lambda: ("BLOCKED" in _tiers_for(_WHOIS_OLD)["beginner"]) or None),
    _H.good("the beginner tier does not dump raw records",
            lambda: ("93.184.216.34" in _tiers_for(_WHOIS_OLD)["beginner"]) or None),
]


def _refused_type():
    try:
        lookup_domain("example.com", rrtype="; rm -rf /",
                      runner=_fake(_DIG_OK), now=_NOW)
        return None
    except LookupRefused as e:
        return str(e)


def _tiers_sink():
    return lookup_domain("example.com",
                         runner=_fake("example.com.\t2\tIN\tA\t0.0.0.0", _WHOIS_OLD),
                         now=_NOW)["explanation"]


def _tiers_for(whois_out):
    return lookup_domain("example.com", runner=_fake(_DIG_OK, whois_out),
                         now=_NOW)["explanation"]


def canary():
    """Returns (ok, detail). Runs on every invocation, in the production path."""
    return _H.run_cases(CASES)


def _assert_canary_at_import():
    """Refuse to load if the canary cannot vouch for this module.

    `canary()` RETURNS a verdict; calling it and discarding the result proves
    nothing. The first version of this file did exactly that — the canary ran at
    import, reported failure, and the module loaded anyway. It was invisible
    because the mutation suite was independently broken and reported every
    mutation as caught.

    Raising here is what makes the import-time check a gate rather than a
    gesture: a mutated or broken lookup core does not reach a caller at all.
    """
    ok, detail = canary()
    if not ok:
        raise AssertionError("lookup_core canary failed at import: %s" % detail)


_assert_canary_at_import()
