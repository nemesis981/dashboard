"""Canonical severity vocabulary and ordering for Nemesis.

ONE ladder, so that severities written by different processes can be compared
without every caller re-deriving what "worse than" means.

WHY THIS EXISTS. Before 2026-07-29 two files carried byte-identical private
copies of the same dict — ``core_module/watchdog/watchdog.py`` and
``modules/malware_detection/module.py``, both spelling
``{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}`` inline to decide whether an
alert crosses the auto-ticket threshold. Two copies of a comparison is two things
that can drift, and only one of them normalised its input, so the same severity
string could rank differently depending on which file asked.

CASE-INSENSITIVE ON PURPOSE — this is load-bearing, not politeness. The database
holds five severity-bearing columns and they do not agree on case:

    alerts.risk_level            LOW / MEDIUM / HIGH
    hw_alerts.severity           CRITICAL
    correlation_events.severity  HIGH / CRITICAL
    ip_enrichment.threat_level   LOW / MEDIUM
    malware_findings.severity    historically lowercase, now canonical

``malware_findings`` in particular will contain BOTH cases for as long as its
pre-2026-07-29 rows survive, so anything comparing severities has to cope with
mixed data rather than assume a cleanup already happened.

FIVE RUNGS, NOT FOUR. ``INFO`` is a malware-detection concept meaning "analysis
ran and found nothing" — ``module.py`` uses it as a sentinel to decide whether a
heuristic result counts as a finding at all. It is deliberately NOT folded into
``LOW``: doing so would turn every clean scan into a low-severity finding. It sits
below LOW here so cross-table comparisons still work, and no other column ever
uses it.
"""

#: Lowest to highest. Index is the rank.
CANONICAL = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

_RANK = {name: i for i, name in enumerate(CANONICAL)}


def normalize(value, default=None):
    """Return the canonical spelling of ``value``, or ``default`` if unrecognised.

    Accepts any case and surrounding whitespace. Returns ``default`` — NOT a
    guessed severity — for None, empty strings, and values outside the ladder
    (e.g. the status-page vocabulary's "major", or the AI analyser's "UNKNOWN"),
    so a caller is never silently handed a severity that was never written.
    """
    if value is None:
        return default
    name = str(value).strip().upper()
    return name if name in _RANK else default


def rank(value, default=0):
    """Position of ``value`` on the ladder; ``default`` if unrecognised.

    ``default=0`` means an unknown severity sorts as the LEAST severe, which
    preserves the behaviour of the dicts this replaces (both used ``.get(x, 0)``
    for the observed severity). Callers comparing against a configured threshold
    should pass an explicit default for the threshold side — e.g.
    ``rank(min_sev, default=rank("HIGH"))`` — because a missing threshold must
    not silently become "alert on everything".
    """
    name = normalize(value)
    return _RANK[name] if name is not None else default


def meets_threshold(observed, minimum, default_minimum="HIGH"):
    """True when ``observed`` is at least as severe as ``minimum``.

    THE comparison the auto-ticket paths make, defined once. Both call sites
    previously spelled it out with their own dict and their own two magic
    defaults; getting either default wrong changes when tickets fire, which is
    not the kind of thing to leave duplicated.

    The two defaults are deliberately different, and both preserve the behaviour
    of the dicts this replaced:

    * unrecognised ``observed`` ranks as **LOW**, not INFO. Under the old 4-rung
      ordering LOW was 0 and an unknown severity also defaulted to 0, so an
      unparseable severity still crossed a ``LOW`` threshold. A ``LOW`` threshold
      means "ticket everything", and silently dropping alerts there would
      contradict the operator's setting. Verified equivalent across all 25
      observed/threshold combinations.
    * unrecognised ``minimum`` falls back to ``default_minimum`` (HIGH), so a
      missing or mistyped setting cannot quietly become "ticket everything".
    """
    return (rank(observed, default=rank("LOW"))
            >= rank(minimum, default=rank(default_minimum)))


def is_canonical(value):
    """True if ``value`` is already spelled exactly as this module defines it."""
    return isinstance(value, str) and value in _RANK
