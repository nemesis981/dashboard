"""Guided setup that works out whether VLAN segmentation is available here.

PURE. Questions in, outcome out. No probing, no I/O, no privileged calls, and
no HTML -- same discipline as core/gateway_mode.py, and for the same reason: the
part that decides is worth being able to test exhaustively on its own.

WHY A GUIDED FLOW AND NOT A TOGGLE
    Most people do not know whether their hardware supports VLANs. Asking
    directly ("is your switch 802.1Q-capable?") only gets an answer from someone
    who never needed the wizard, and gets a guess from everyone else -- and a
    guess here silently enables a mode that enforces nothing. So the questions
    are about things a person can actually check: who supplied the box, whether
    there is a separate box with several ports, whether they have ever opened its
    settings page.

⛔ THREE OUTCOMES, NOT TWO, AND THE MIDDLE ONE IS WHY THIS IS NOT A YES/NO
    A VLAN-capable switch that is not CONFIGURED still cannot be used: Nemesis
    cannot trunk a switch port from an end-host position -- it has no credentials
    for the hardware and will not ask for them. So "capable" and "usable" are
    different answers.

      UNAVAILABLE    -- honest full stop; nothing to configure that would help
      PREREQUISITES  -- the hardware could do this; here is what YOU must set up
      READY          -- capable and already trunked; the mode can be offered

    Collapsing the middle fails in both directions: fold it into UNAVAILABLE and
    someone with good hardware is told they cannot have the feature; fold it into
    READY and the product enables a mode that does nothing. The middle case is
    the common one -- anyone who bought a managed switch and never configured it.

FAILS CLOSED, EVERYWHERE
    Unknown, unanswered, unrecognised and "I am not sure" all resolve AWAY from
    READY. A wrong "no" costs someone a lookup. A wrong "yes" produces a mode
    that appears enabled and enforces nothing, which is the failure this whole
    feature exists to avoid claiming.

DETECTION IS DELIBERATELY ABSENT
    No LLDP, no SNMP, no probing. An end host cannot reliably determine a
    switch's capability: LLDP's Port-VLAN TLV is a trustworthy POSITIVE but its
    silence is uninformative (unmanaged switches say nothing; managed ones
    commonly ship with it off). An instrument whose negative means "I could not
    tell" must never gate anything. If a hint is added later it belongs INSIDE
    this flow as supporting text -- "here is what we can see, here is what to
    check" -- never as a silent answer.
"""

OUTCOME_UNDECIDED = "undecided"
OUTCOME_UNAVAILABLE = "unavailable"
OUTCOME_PREREQUISITES = "prerequisites"
OUTCOME_READY = "ready"

#: Asked in this order so the flow can stop early. Most networks are answered by
#: question one, and nobody is asked something whose answer cannot change the
#: result. No question uses the words the wizard exists to avoid needing.
QUESTIONS = (
    {
        "id": "gear_origin",
        "text": "Did your internet provider supply the box your devices connect to, "
                "or did you buy your own?",
        "options": (
            {"value": "provider", "label": "My provider supplied it"},
            {"value": "own", "label": "I bought my own"},
            {"value": "unsure", "label": "I am not sure"},
        ),
    },
    {
        "id": "separate_switch",
        "text": "Is there a separate box between your router and your devices — "
                "often a small metal one with several network ports?",
        "options": (
            {"value": "yes", "label": "Yes, there is one"},
            {"value": "no", "label": "No, everything plugs into the router"},
            {"value": "unsure", "label": "I am not sure"},
        ),
    },
    {
        "id": "managed_ui",
        "text": "Have you ever opened that box's own settings page in a browser?",
        "options": (
            {"value": "yes", "label": "Yes, it has settings I can log into"},
            {"value": "no", "label": "No, it has no settings — you just plug things in"},
            {"value": "unsure", "label": "I am not sure"},
        ),
    },
    {
        "id": "vlans_configured",
        "text": "In those settings, have you already created separate networks and "
                "set the port this Nemesis box uses to carry all of them?",
        "options": (
            {"value": "yes", "label": "Yes, that is already set up"},
            {"value": "no", "label": "No, not yet"},
            {"value": "unsure", "label": "I am not sure"},
        ),
    },
)

#: Answers that end the flow immediately, with the reason recorded so the copy
#: can say WHICH dead end was reached rather than a generic refusal.
_STOPS = (
    ("gear_origin", "provider", "isp_supplied"),
    ("separate_switch", "no", "no_switch"),
    ("managed_ui", "no", "unmanaged_switch"),
)


def _valid(question, value):
    """True only for a value the question actually offered.

    An unrecognised answer is NOT passed through. A typo, a stale form field or a
    hand-crafted request must not become a decision -- it resolves to undecided,
    which fails closed.
    """
    return any(o["value"] == value for o in question["options"])


def next_question(answers):
    """The next question to ask, or None when the flow has resolved."""
    answers = answers or {}
    for qid, stop_value, _reason in _STOPS:
        if answers.get(qid) == stop_value:
            return None
    for q in QUESTIONS:
        v = answers.get(q["id"])
        if v is None or not _valid(q, v):
            return q
    return None


def evaluate(answers):
    """(outcome, reason) for the answers so far. Never raises, never guesses."""
    answers = answers or {}
    for qid, stop_value, reason in _STOPS:
        if answers.get(qid) == stop_value:
            return OUTCOME_UNAVAILABLE, reason
    for q in QUESTIONS:
        v = answers.get(q["id"])
        if v is None or not _valid(q, v):
            return OUTCOME_UNDECIDED, "incomplete"
    # Every question answered with a legal value and no stop reached. Only an
    # explicit yes on BOTH the managed-switch and already-trunked questions can
    # reach READY; "unsure" on either lands in PREREQUISITES, which tells the
    # person what to go and check rather than deciding for them.
    if answers["managed_ui"] == "yes" and answers["vlans_configured"] == "yes":
        return OUTCOME_READY, "capable_and_configured"
    return OUTCOME_PREREQUISITES, "not_configured"


def declares_capable(outcome):
    """Translate an outcome into the declaration `gateway_mode.vlan_available()` takes.

    ONLY READY declares capability. PREREQUISITES deliberately does not: the
    hardware may well be capable, but the mode is not usable until the switch is
    trunked, and offering it meanwhile would be the "looks implemented" failure
    this feature is built to avoid.
    """
    return outcome == OUTCOME_READY
