#!/usr/bin/env python3
"""Does a tailnet packet actually REACH our raw-table DROP? (ADR 0026 step 4)

WHY `iptables -C` IS NOT THE INSTRUMENT. `-C` answers "does this rule exist".
The failure mode step 4 has to survive is a rule that exists, reads correctly in
`iptables -L`, and is never reached -- because something ABOVE it terminated
traversal first. Presence and reachability are different questions, and only the
second one is the one worth asking. `-C` cannot tell them apart, so a check built
on it reports healthy in exactly the case that matters.

WHY NOT A LIVE PROBE FROM THE APPLIANCE. Measured 2026-08-25:

    $ ip route get <own-tailnet-ip>
    local <own-tailnet-ip> dev lo

Traffic the appliance sends to its own tailnet address is delivered over `lo`. It
never arrives `-i tailscale0`, so the DROP cannot match it and a self-probe returns
the same answer whether the rule is working perfectly or has been deleted outright.
That is an instrument with one possible answer. The ground-truth live probe has to
come from a REMOTE tailnet device, which makes it an acceptance test, not something
that can run every minute. This module is what runs every minute instead.

WHAT IT ACTUALLY DOES. Parses `iptables -t raw -S` and walks PREROUTING in order for
a synthetic packet, following jumps into user chains, and reports the verdict that
packet would receive. That answers reachability-by-position, which is the real
question, without needing a packet to exist.

FAIL-CLOSED, EVERYWHERE. Every way of not knowing returns UNDETERMINED, never a
default that happens to be a legal answer. An unmodelled match option, an unknown
target, a jump to an undeclared chain, a malformed line, a traversal loop -- all of
them refuse to vouch rather than guessing the reassuring answer. A wrong "healthy"
here is worse than no check at all, because it is the line that stops anyone looking.

NOISE CONTROL, AND WHY THE PARSE/EVALUATE SPLIT MATTERS. A rule is parsed into
modelled constraints plus a list of options this module does not understand. If a
MODELLED constraint already excludes our packet -- wrong interface, wrong port --
the rule cannot match and is skipped, unmodelled options and all. UNDETERMINED is
raised only when every modelled constraint passes AND something unmodelled remains,
i.e. only when the rule genuinely might match and we genuinely cannot tell. Without
that split, one `-m conntrack` rule on an unrelated interface would blind the whole
check.

PURE. No subprocess, no privilege, no I/O. It takes dump TEXT and returns a verdict,
which is what makes it testable against rulesets that would be a nuisance to create
for real -- including the ones we hope never to see.
"""
import shlex

#: Our packet reached a DROP: the guard is working.
DROP = "DROP"
#: Our packet survived to something that is not a DROP: the guard is defeated.
NOT_DROP = "NOT_DROP"
#: We cannot tell. NEVER collapse this into either of the above.
UNDETERMINED = "UNDETERMINED"

#: Targets that end traversal with a verdict.
_TERMINAL = {"ACCEPT", "DROP", "REJECT"}

#: Targets that are documented to continue traversal (kernel XT_CONTINUE), so a
#: rule carrying one does not stop our packet reaching the DROP below it.
#:
#: NOTRACK and CT are DELIBERATELY ABSENT even though they are the raw table's
#: signature targets and are very likely non-terminating. "Very likely" is not
#: verified, and this module's whole value is that it does not guess. They land in
#: UNDETERMINED, which is loud and investigable. The cost of that choice is close to
#: zero in practice: a target is only ever consulted for a rule that already matches
#: our packet on every modelled field, and nothing in the live ruleset does.
#: Promote them here only with an empirical result, not a reading of the manpage.
_NON_TERMINATING = {"LOG", "NFLOG", "AUDIT", "TRACE", "MARK", "CONNMARK", "TOS", "TTL"}

#: Match modules that constrain nothing we have not already modelled directly.
#: `-p tcp --dport N` is emitted by iptables as `-p tcp -m tcp --dport N`, so `-m tcp`
#: MUST be benign here -- found the hard way on 2026-08-25: the rule we install does
#: not contain `-m tcp`, but the rule `-S` reads back always does, and a parser that
#: treats it as unmodelled fails to recognise our own rule and reports the guard
#: defeated forever.
_BENIGN_MATCH_MODULES = {"tcp", "udp"}

_MAX_DEPTH = 40

#: The rule nemesis_fwd's op_deny_port_on_interface installs, as a set of modelled
#: predicates. Identity is STRUCTURAL rather than textual because `-S` reads the rule
#: back in a different form from the one inserted (`-m tcp` appears), so a string
#: comparison would fail against our own rule. Matching on the parsed predicates is
#: immune to that -- and to option reordering.
_OUR_RULE_PREDICATES = {("iface", False, "tailscale0"),
                        ("proto", False, "tcp"),
                        ("dport", False, "80")}


def rule_matches_spec(toks, iface, proto, dport, target="DROP"):
    """Is this rule exactly `-i iface -p proto --dport dport -j target`, and nothing more?

    Structural rather than textual, which is the whole point: `-S` reads the rule back
    in a different form from the one inserted (`-m tcp` appears), so a string compare
    fails against our own rule. Comparing parsed predicates is immune to that and to
    option reordering. Extra constraints -- a source address, a conntrack state -- make
    it NOT this rule, because such a rule does not do the same job.
    """
    modelled, unmodelled, tgt, _goto = _parse_rule(toks)
    if tgt != target or unmodelled:
        return False
    return set(modelled) == {("iface", False, iface),
                             ("proto", False, proto),
                             ("dport", False, str(dport))}


def is_our_rule(toks):
    """Is this specific rule the one Nemesis installs, rather than a lookalike?

    Expressed through rule_matches_spec so the healer (which must find the rule by
    POSITION, for a port it is told at runtime) and the checker share one definition
    of what the rule is. Two definitions would drift, and the drift would be silent.
    """
    return rule_matches_spec(toks, "tailscale0", "tcp", 80)


def chain_rules(dump, chain):
    """[(index, tokens)] for `chain` from `iptables -S` text, 1-based, in order.

    1-based and in evaluation order because that is what `-D <chain> <n>` expects:
    the caller deleting a duplicate needs the same numbering the kernel uses, and an
    off-by-one here deletes the WRONG RULE. Kept next to the parser rather than
    reimplemented at the call site for exactly that reason.
    """
    out = []
    for line in dump.splitlines():
        line = line.strip()
        if not line.startswith("-A "):
            continue
        try:
            toks = shlex.split(line)
        except ValueError:
            continue
        if len(toks) >= 3 and toks[1] == chain:
            out.append((len(out) + 1, toks[2:]))
    return out


class Undetermined(Exception):
    """Raised the moment anything cannot be decided. Carries why."""


class SelfTestFailed(Exception):
    """The simulator disagreed with a known answer, so it must not vouch for anything."""


class Packet:
    """The synthetic packet. Fields not listed here are UNKNOWN, and any rule that
    constrains an unknown field is unmodelled by construction."""

    __slots__ = ("iface", "proto", "dport")

    def __init__(self, iface, proto, dport):
        self.iface = iface
        self.proto = proto
        self.dport = int(dport)

    def __repr__(self):
        return "Packet(in=%s, %s, dport=%d)" % (self.iface, self.proto, self.dport)


class Result:
    """Verdict plus the reasoning that produced it.

    The trace is not decoration. It is what goes into the alert, so an operator
    reading it at 3am can see WHICH rule terminated traversal instead of being told
    only that something did.
    """

    __slots__ = ("status", "verdict", "reason", "trace", "by_our_rule", "terminator")

    def __init__(self, status, verdict, reason, trace, by_our_rule=False, terminator=None):
        self.status = status
        self.verdict = verdict
        self.reason = reason
        self.trace = trace
        #: DROP alone is not the healer's condition. The chain policy could be DROP,
        #: or someone else's rule could be dropping the packet -- both leave OUR rule
        #: absent while the traffic happens to be blocked. A healer that keyed only on
        #: `status == DROP` would see "fine" and never reinstall the guard it owns,
        #: right up until the unrelated thing that was doing the work went away.
        self.by_our_rule = by_our_rule
        #: Tokens of the rule that ended traversal, or None if a policy did.
        self.terminator = terminator

    def __repr__(self):
        return "Result(%s, verdict=%r, %s)" % (self.status, self.verdict, self.reason)


class Ruleset:
    __slots__ = ("policies", "rules", "user_chains")

    def __init__(self, policies, rules, user_chains):
        self.policies = policies
        self.rules = rules
        self.user_chains = user_chains


def _iface_match(pattern, actual):
    """iptables interface matching: a trailing `+` is a prefix wildcard."""
    if pattern.endswith("+"):
        return actual.startswith(pattern[:-1])
    return pattern == actual


def _port_match(spec, actual):
    """A single port or an inclusive `lo:hi` range."""
    if ":" in spec:
        lo, hi = spec.split(":", 1)
        lo = int(lo) if lo else 0
        hi = int(hi) if hi else 65535
        return lo <= actual <= hi
    return int(spec) == actual


def parse(dump):
    """`iptables -S` text -> Ruleset. Raises Undetermined on anything unrecognised."""
    policies, rules, user_chains = {}, {}, set()
    for lineno, raw in enumerate(dump.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            toks = shlex.split(line)
        except ValueError as exc:
            raise Undetermined("line %d does not tokenise (%s): %r" % (lineno, exc, line))
        if not toks:
            continue
        kind = toks[0]
        if kind == "-P" and len(toks) >= 3:
            policies[toks[1]] = toks[2]
            rules.setdefault(toks[1], [])
        elif kind == "-N" and len(toks) >= 2:
            user_chains.add(toks[1])
            rules.setdefault(toks[1], [])
        elif kind == "-A" and len(toks) >= 2:
            rules.setdefault(toks[1], []).append(toks[2:])
        else:
            raise Undetermined("line %d is not a form this parser models: %r" % (lineno, line))
    return Ruleset(policies, rules, user_chains)


def _parse_rule(toks):
    """One rule's tokens -> (modelled predicates, unmodelled options, target, goto).

    Split deliberately from evaluation: an unmodelled option must not blind us to a
    modelled constraint that already rules the packet out. See the module docstring.
    """
    modelled = []          # list of (kind, negated, value)
    unmodelled = []
    target = None
    goto = False
    i = 0
    neg = False
    while i < len(toks):
        t = toks[i]
        if t == "!":
            neg = True
            i += 1
            continue
        if t in ("-i", "--in-interface"):
            modelled.append(("iface", neg, toks[i + 1])); i += 2
        elif t in ("-p", "--protocol"):
            modelled.append(("proto", neg, toks[i + 1])); i += 2
        elif t == "--dport" or t == "--destination-port":
            modelled.append(("dport", neg, toks[i + 1])); i += 2
        elif t == "-m":
            mod = toks[i + 1]
            if mod not in _BENIGN_MATCH_MODULES:
                unmodelled.append("-m " + mod)
            i += 2
        elif t == "-j":
            target = toks[i + 1]; i += 2
        elif t == "-g":
            target = toks[i + 1]; goto = True; i += 2
        else:
            # Anything else constrains something we do not model (-s, -d, --sport,
            # --ctstate, ...) or is an argument to a target we will not reach a
            # decision on anyway. Either way: not understood, so recorded as such.
            unmodelled.append(t)
            i += 1
        neg = False
    return modelled, unmodelled, target, goto


def _rule_matches(toks, packet):
    """True / False, or raise Undetermined when the rule might match and we cannot tell."""
    modelled, unmodelled, target, goto = _parse_rule(toks)
    for kind, negated, value in modelled:
        if kind == "iface":
            ok = _iface_match(value, packet.iface)
        elif kind == "proto":
            ok = (value in ("all", packet.proto))
        elif kind == "dport":
            try:
                ok = _port_match(value, packet.dport)
            except ValueError:
                raise Undetermined("unparseable port spec %r" % value)
        else:                                                  # pragma: no cover
            raise Undetermined("unhandled modelled predicate %r" % kind)
        if negated:
            ok = not ok
        if not ok:
            # Definitively excluded on a field we DO model. Unmodelled options are
            # irrelevant now -- the rule cannot match whatever they say.
            return False, target, goto
    if unmodelled:
        raise Undetermined(
            "a rule that matches on every modelled field also carries options this "
            "module does not model (%s), so whether it matches cannot be decided: %s"
            % (", ".join(unmodelled), " ".join(toks)))
    return True, target, goto


def _walk(rs, chain, packet, trace, depth, seen):
    """Return a terminal verdict string, or None meaning 'fell off the end / RETURN'."""
    if depth > _MAX_DEPTH:
        raise Undetermined("traversal exceeded %d chains -- possible rule loop" % _MAX_DEPTH)
    if chain in seen:
        raise Undetermined("traversal re-entered chain %r -- rule loop" % chain)
    if chain not in rs.rules:
        raise Undetermined("chain %r is jumped to but never declared" % chain)

    for idx, toks in enumerate(rs.rules[chain], 1):
        matched, target, goto = _rule_matches(toks, packet)
        if not matched:
            continue
        where = "%s[%d]" % (chain, idx)
        if target is None:
            raise Undetermined("%s matches but has no target: %s" % (where, " ".join(toks)))
        if target in _TERMINAL:
            trace.append("%s %s => %s" % (where, " ".join(toks), target))
            return target, toks
        if target == "RETURN":
            trace.append("%s %s => RETURN" % (where, " ".join(toks)))
            return None, None
        if target in _NON_TERMINATING:
            trace.append("%s %s => %s (continues)" % (where, " ".join(toks), target))
            continue
        if target in rs.user_chains:
            trace.append("%s %s => jump %s" % (where, " ".join(toks), target))
            sub, sub_toks = _walk(rs, target, packet, trace, depth + 1, seen | {chain})
            if sub is not None:
                return sub, sub_toks
            if goto:
                # -g does not come back to this chain; it returns to OUR caller.
                trace.append("%s: -g, so traversal does not resume in %s" % (where, chain))
                return None, None
            trace.append("%s: %s returned, continuing in %s" % (where, target, chain))
            continue
        raise Undetermined(
            "%s matches and jumps to %r, which is neither a verdict this module "
            "knows nor a declared chain" % (where, target))
    return None, None


def evaluate(rs, packet, chain="PREROUTING"):
    """Walk `chain` for `packet` and classify the outcome. Never raises Undetermined
    to the caller -- it is converted into an UNDETERMINED Result, because the caller's
    job is to alert on it, not to crash on it."""
    trace = []
    try:
        verdict, toks = _walk(rs, chain, packet, trace, 0, frozenset())
    except Undetermined as exc:
        return Result(UNDETERMINED, None, str(exc), trace)
    if verdict is None:
        policy = rs.policies.get(chain)
        if policy is None:
            return Result(UNDETERMINED, None,
                          "traversal fell off the end of %r and it has no policy" % chain,
                          trace)
        trace.append("%s policy => %s" % (chain, policy))
        verdict = policy
        reason = "no rule matched; chain policy %s applies" % policy
        ours = False
    else:
        ours = is_our_rule(toks)
        reason = "terminated by %s rule" % ("OUR" if ours else "another")
    if verdict == "DROP":
        return Result(DROP, verdict, reason, trace, ours, toks)
    return Result(NOT_DROP, verdict, reason, trace, ours, toks)


# ── self-test: prove the instrument can tell these cases apart, every call ────
#
# The reference shape is scripts/nemesis-fw-neverblock's CANARIES: a tool does not
# get to vouch for real data until it has re-derived answers it already knows, on
# every invocation and not merely in a test suite. Each case below is a distinct way
# this simulator could be wrong while still returning a plausible-looking verdict.

_OURS = "-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 80 -j DROP"

#: (label, dump, expected status, expected by_our_rule)
_CANARIES = (
    ("healthy: our DROP is reached",
     "-P PREROUTING ACCEPT\n" + _OURS, DROP, True),

    # The one that matters. A jump ABOVE ours into a chain that accepts: the rule
    # still exists and `iptables -C` would still say yes.
    ("case 3: a jump above ours terminates in ACCEPT",
     "-P PREROUTING ACCEPT\n"
     "-N vpn.PREROUTING\n"
     "-A PREROUTING -j vpn.PREROUTING\n"
     + _OURS + "\n"
     "-A vpn.PREROUTING -j ACCEPT", NOT_DROP, False),

    ("the rule is simply absent",
     "-P PREROUTING ACCEPT", NOT_DROP, False),

    ("position matters: a terminal ACCEPT above ours",
     "-P PREROUTING ACCEPT\n"
     "-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 80 -j ACCEPT\n"
     + _OURS, NOT_DROP, False),

    # Today's live shape: an empty chain above ours must RETURN and let traversal
    # continue, or we would report defeat while the guard is fine.
    ("an empty jumped-to chain returns and traversal continues",
     "-P PREROUTING ACCEPT\n"
     "-N vpn.PREROUTING\n"
     "-N vpn.a.slot\n"
     "-A PREROUTING -j vpn.PREROUTING\n"
     + _OURS + "\n"
     "-A vpn.PREROUTING -j vpn.a.slot", DROP, True),

    ("an unmodelled match on a rule that could match refuses to answer",
     "-P PREROUTING ACCEPT\n"
     "-A PREROUTING -i tailscale0 -p tcp -m conntrack --ctstate NEW -j ACCEPT\n"
     + _OURS, UNDETERMINED, False),

    # ... but the same unmodelled match on a rule that CANNOT match our packet must
    # NOT blind the check. This is the canary that keeps the fail-closed rule from
    # degenerating into "always UNDETERMINED".
    ("an unmodelled match on a NON-matching rule is ignored",
     "-P PREROUTING ACCEPT\n"
     "-A PREROUTING -i eth0 -p tcp -m conntrack --ctstate NEW -j ACCEPT\n"
     + _OURS, DROP, True),

    ("an unknown target refuses to answer",
     "-P PREROUTING ACCEPT\n"
     "-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 80 -j SOMETHING_NEW", UNDETERMINED, False),

    ("a jump to an undeclared chain refuses to answer",
     "-P PREROUTING ACCEPT\n"
     "-A PREROUTING -j nowhere.chain\n" + _OURS, UNDETERMINED, False),

    # Proves the port and interface predicates actually discriminate. Without these
    # a simulator that matched everything would pass every case above.
    ("a DROP on a different port does not count",
     "-P PREROUTING ACCEPT\n"
     "-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 443 -j DROP", NOT_DROP, False),

    ("a DROP on a different interface does not count",
     "-P PREROUTING ACCEPT\n"
     "-A PREROUTING -i eth0 -p tcp -m tcp --dport 80 -j DROP", NOT_DROP, False),

    ("blocked by the chain POLICY, not by our rule",
     "-P PREROUTING DROP", DROP, False),

    # A DROP that genuinely blocks our packet but is NOT the rule we install: a port
    # RANGE covering 80 rather than the exact port. Decidable, correct, and still not
    # ours -- so the guard is missing even though the traffic is blocked today.
    ("blocked by SOMEONE ELSE's rule, not ours",
     "-P PREROUTING ACCEPT\n"
     "-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 79:81 -j DROP", DROP, False),
)

#: The packet every canary is evaluated against, and the one the real check uses.
TAILNET_HTTP = Packet("tailscale0", "tcp", 80)


def selftest(packet=None):
    """Re-derive every known answer. Raises SelfTestFailed on any disagreement."""
    pkt = packet or TAILNET_HTTP
    for label, dump, expected, expected_ours in _CANARIES:
        try:
            res = evaluate(parse(dump), pkt)
            got, got_ours = res.status, res.by_our_rule
        except Undetermined as exc:
            got, got_ours = "PARSE_UNDETERMINED(%s)" % exc, False
        if got != expected or got_ours != expected_ours:
            raise SelfTestFailed(
                "SELF-TEST FAILED: %r produced %s/by_our_rule=%s, expected %s/%s. The "
                "simulator cannot distinguish these cases, so it must not vouch for "
                "the live ruleset." % (label, got, got_ours, expected, expected_ours))
    return len(_CANARIES)


def classify(dump, packet=None):
    """THE ENTRY POINT. Self-tests first, then answers about the real dump.

    Everything a caller should use goes through here, so there is no path to a
    verdict that skipped the self-test.
    """
    selftest(packet)
    pkt = packet or TAILNET_HTTP
    try:
        rs = parse(dump)
    except Undetermined as exc:
        return Result(UNDETERMINED, None, str(exc), [])
    return evaluate(rs, pkt)
