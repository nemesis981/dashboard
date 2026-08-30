"""Drift detection for two security properties set once at install and never re-checked.

    1. Tailscale's netfilter mode is `nodivert` (1), not `on` (2).
    2. The tailnet anti-spoof DROP is present in ufw's before-rules, ABOVE the
       conntrack RELATED,ESTABLISHED accept.

⚠ WHY THESE TWO, AND WHY SILENTLY. If the mode reverts to `on`, Tailscale re-inserts
`-A INPUT -j ts-input` ahead of every ufw chain and that chain ends in a terminating
ACCEPT -- the MEASURED 2026-07-30 defect where a `nemesis_fwd` block reported "Rule
inserted" and the blocked peer still connected. If the anti-spoof DROP is lost, ADR
0011's enrollment trust breaks, because its guarantee -- "the server-observed tailnet
source IP cannot be forged" -- IS that rule, and under `nodivert` we are the only ones
providing it. Neither failure produces a symptom.

⚠ AND `nemesis_fw_watch` DOES NOT COVER THIS -- traced 2026-08-30, do not assume
otherwise. It SEES both events, but `classify()` matches them against `UFW_TABLES`
(which includes `("ip","filter")`, where both live), the `"ufw"` response is
`rerender()`, and `rerender()` REBASELINES. So a reversion is absorbed as the new
normal after one INFO log line. That is CORRECT for the watcher -- every `nemesis_fwd`
block is also an `ip filter` change, so table-level classification must treat them as
benign -- which is exactly why this needs rule-level assertion in a separate mechanism.
**Do not "fix" it by adding `ip filter` to the watcher's tamper branch.**

⚠ POSITION IS PART OF THE PROPERTY, NOT A DETAIL. install.sh places the rule after the
loopback ACCEPT and states it "MUST stay above the conntrack RELATED,ESTABLISHED accept
below", because a spoofed packet matching an existing flow is accepted before it is ever
checked. A check that only asked "is the rule present?" would pass a ruleset in which
the rule had been moved below the accept and made useless.

⚠ NO `systemctl is-active tailscaled` ANYWHERE IN HERE, deliberately. On a snap install
the unit is `snap.tailscale.tailscaled.service` and the plain name is `not-found`, so
`is-active` returns "inactive" for a RUNNING daemon -- a drift check built on it would
report all-clear forever. The fix is to stop using a proxy: being able to READ the prefs
is itself the proof the daemon answered. If we cannot read them, that is UNDETERMINED,
never OK.
"""
import json
import re

OK, DRIFTED, UNDETERMINED = "ok", "drifted", "undetermined"

#: Tailscale's NetfilterMode. 0=off, 1=nodivert, 2=on. We require 1.
#: Both plausible enum orderings put nodivert at 1 (Go's Off/NoDivert/On, and the CLI
#: help's "on, nodivert, off"), so this value is robust to which is authoritative.
MODE_NODIVERT = 1

ANTISPOOF_MARKER = "NEMESIS-TAILNET-ANTISPOOF"

#: Matches the rule install.sh writes, tolerating whitespace and any tunnel device
#: name -- the DEVICE is name-matched by install.sh itself, so this mirrors it rather
#: than inventing a stricter form that would false-alarm on a renamed interface.
_ANTISPOOF_RE = re.compile(
    r"-A\s+ufw-before-input\s+-s\s+100\.64\.0\.0/10\s+!\s+-i\s+\S+\s+-j\s+DROP")
_CONNTRACK_RE = re.compile(r"RELATED\s*,\s*ESTABLISHED")


def parse_netfilter_mode(prefs_text):
    """NetfilterMode as an int, or None if it could not be read.

    None means UNREADABLE. Returning a default here would be the whole bug: a check
    that answers "1" when it read nothing reports all-clear forever.
    """
    if not prefs_text:
        return None
    try:
        d = json.loads(prefs_text)
    except Exception:  # noqa: BLE001
        return None
    v = d.get("NetfilterMode") if isinstance(d, dict) else None
    return v if isinstance(v, int) else None


def check_netfilter_mode(prefs_text):
    """(status, detail). UNDETERMINED when prefs are unreadable -- never OK."""
    mode = parse_netfilter_mode(prefs_text)
    if mode is None:
        return (UNDETERMINED,
                "could not read Tailscale prefs -- the daemon did not answer, so the "
                "netfilter mode is unknown. NOT treated as healthy.")
    if mode == MODE_NODIVERT:
        return OK, "netfilter mode is nodivert (%d), as configured" % mode
    return (DRIFTED,
            "netfilter mode is %d, expected %d (nodivert). If this is 'on', Tailscale "
            "has re-inserted its jump ahead of ufw and per-IP blocks are unreachable "
            "for tunnel traffic." % (mode, MODE_NODIVERT))


def check_antispoof(rules_text):
    """(status, detail). Presence AND position, both required."""
    if not rules_text or not rules_text.strip():
        return (UNDETERMINED,
                "could not read ufw's before-rules -- refusing to report on a file "
                "that was not read.")
    m = _ANTISPOOF_RE.search(rules_text)
    if not m:
        if ANTISPOOF_MARKER in rules_text:
            return (DRIFTED,
                    "the %s comment is present but its DROP rule is not -- the rule was "
                    "removed and only the explanation survives." % ANTISPOOF_MARKER)
        return (DRIFTED,
                "the tailnet anti-spoof DROP is MISSING. ADR 0011 enrollment trust "
                "rests on it, and under nodivert nothing else provides it.")
    ct = _CONNTRACK_RE.search(rules_text)
    if ct and ct.start() < m.start():
        return (DRIFTED,
                "the anti-spoof DROP is present but sits BELOW the conntrack "
                "RELATED,ESTABLISHED accept, so a spoofed packet matching an existing "
                "flow is accepted before it is ever checked.")
    return OK, "anti-spoof DROP present, above the conntrack accept"


def overall(statuses):
    """Worst-of. DRIFTED beats UNDETERMINED beats OK -- an unknown is never allowed to
    round down to healthy, and a known failure is never masked by an unknown."""
    if DRIFTED in statuses:
        return DRIFTED
    if UNDETERMINED in statuses:
        return UNDETERMINED
    return OK


# ── Self-test: known-good AND known-bad, in the production path ───────────────
#
# Same discipline as scripts/nemesis-integrity-check's selftest and
# nemesis-fw-neverblock's CANARIES: a drift check on a healthy box says "fine"
# forever, which is also what a broken one says. These fixtures prove it can produce
# BOTH answers before it is allowed to vouch for anything real.

_GOOD_RULES = """\
-A ufw-before-input -i lo -j ACCEPT

# NEMESIS-TAILNET-ANTISPOOF - replaces the DROP that ts-input provided
-A ufw-before-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
"""

_BAD_MISSING = """\
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
"""

_BAD_BELOW = """\
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# NEMESIS-TAILNET-ANTISPOOF
-A ufw-before-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP
"""


def selftest():
    """(ok, detail). Proves the checks distinguish healthy from reverted."""
    if check_netfilter_mode('{"NetfilterMode": 1}')[0] != OK:
        return False, "canary: nodivert was not recognised as healthy"
    if check_netfilter_mode('{"NetfilterMode": 2}')[0] != DRIFTED:
        return False, "canary: mode 'on' (2) was NOT flagged as drifted"
    if check_netfilter_mode('{"NetfilterMode": 0}')[0] != DRIFTED:
        return False, "canary: mode 'off' (0) was not flagged"
    if check_netfilter_mode("")[0] != UNDETERMINED:
        return False, "canary: unreadable prefs did not fail closed"
    if check_netfilter_mode("not json")[0] != UNDETERMINED:
        return False, "canary: unparseable prefs did not fail closed"

    if check_antispoof(_GOOD_RULES)[0] != OK:
        return False, "canary: a correct ruleset was not recognised as healthy"
    if check_antispoof(_BAD_MISSING)[0] != DRIFTED:
        return False, "canary: a MISSING anti-spoof rule was not caught"
    if check_antispoof(_BAD_BELOW)[0] != DRIFTED:
        return False, "canary: a rule below the conntrack accept was accepted"
    if check_antispoof("")[0] != UNDETERMINED:
        return False, "canary: an unread rules file did not fail closed"

    if overall([OK, DRIFTED]) != DRIFTED or overall([OK, UNDETERMINED]) != UNDETERMINED:
        return False, "canary: worst-of aggregation rounds down"
    return True, "10 canaries passed"
