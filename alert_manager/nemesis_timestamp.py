"""Canonical timestamp format for Nemesis audit and event records.

ONE format, produced in ONE place, so that timestamps written by different
processes can be compared and ordered without every caller re-deriving what a
timestamp looks like.

WHY THIS EXISTS. Before 2026-08-06, four processes wrote ``audit_log.ts`` and
three of them agreed by coincidence rather than by contract:

    dashboard.py `_audit()`        datetime.now().isoformat()      ISO-T
    core/manage.py                 datetime.now().isoformat()      ISO-T
    degraded_ingest.py             (preserves the journal's own)   ISO-T
    nemesis_fwd.py                 time.strftime("%Y-%m-%d %H...") space-separated

Nobody chose the split; it happened because each writer decided independently.
The result was measured on the live table 2026-08-06: 140 ISO-``T`` rows, 35
space-separated, and **five distinct dates containing both**.

THE DEFECT THAT MAKES THIS MORE THAN A STYLE PREFERENCE. A space (0x20) sorts
before ``T`` (0x54), so every space-separated row of a given day sorts ahead of
every ISO-``T`` row of that SAME day, regardless of the actual time. Measured on
2026-08-05: ``ORDER BY ts`` reports the day beginning at 11:04:15 with a firewall
block; it actually began at 09:15:52. Worse, the two formats were never separate
event streams — on 2026-07-31 ``fw_deny_ip`` (nemesis_fwd) at 11:19:48 and
``block`` (dashboard) at 11:19:48.150060 are ONE operator action recorded by two
writers 150ms apart, and string ordering separated the pair.

WHY ``T`` AND NOT THE SPACE FORM. ISO-``T`` was already the house norm by every
measure — most rows, three of four writers, and a month older (earliest ISO-``T``
row 2026-06-28; earliest space row 2026-07-28). It is also what
``datetime.isoformat()`` produces natively, so the space form took deliberate
``strftime`` work to diverge. Normalising the other way would have meant changing
more code to land on the format that fights the standard library.

WHY OFFSET-AWARE. Both old formats were timezone-naive, which is the more
consequential half of the problem: a naive local timestamp is ambiguous across a
DST transition and anchors to nothing when correlated against another machine.
The offset is folded in here rather than left for later specifically so the audit
trail's format changes ONCE.

WHY LOCAL TIME AND NOT UTC. Deliberate, and it follows an existing decision
rather than making a new one: ``degraded_ingest.write_offset`` was writing
SQLite's ``datetime('now')`` (UTC) against local comparisons until 2026-08-05,
which produced a wrong health verdict; the fix (31a9bbf) states that every other
timestamp in this database is local and made it so. Switching this module to UTC
would re-introduce exactly the mismatch that fix removed.

ORDERING CAVEAT — STATED BECAUSE IT IS NOT ELIMINATED, ONLY NARROWED. Within a
single UTC offset, string ordering of this format IS chronological ordering. It
stops being exact across a DST fall-back, where the local wall clock repeats: two
instants an hour apart can render as the same local time with different offsets
and therefore tie or invert as strings. That window is one hour per year, versus
a defect that was live on five dates in six weeks. **For authoritative insertion
order, order by ``audit_log.id``** — it is monotonic and immune to all of this;
``ts`` is what an event CLAIMS its time was, ``id`` is the order rows arrived.

NOT A MIGRATION. Existing rows are deliberately left as-is (operator decision,
2026-08-06). ``normalize()`` exists for values arriving from outside — journal
records, imported data — not to rewrite history. Rewriting stored ``ts`` values
would also break ``degraded_ingest._already_present()``, which dedupes on exact
``ts`` string equality against the journal's own value.
"""

from datetime import datetime

#: What this module emits. Local time, ISO-8601, ``T`` separator, UTC offset.
CANONICAL_EXAMPLE = "2026-08-06T07:15:00.123456-05:00"


def now(timespec="microseconds"):
    """Current local time as a canonical offset-aware ISO-8601 string.

    ``.astimezone()`` on a naive ``datetime.now()`` attaches the system's offset
    *for that moment*, so the DST offset is correct on both sides of a transition
    rather than being a constant read once at import.

    ``timespec`` defaults to microseconds because that is what the 140 existing
    ISO-``T`` rows already carry, and because two writers recording the same
    operator action 150ms apart (see the module docstring) need sub-second
    resolution to stay in the right order.
    """
    return datetime.now().astimezone().isoformat(timespec=timespec)


def normalize(value, default=None):
    """Return ``value`` in the canonical format, or ``default`` if unparseable.

    Accepts what this codebase actually produces: ISO-``T`` and space-separated,
    with or without microseconds, with or without an offset.

    A NAIVE input is interpreted as LOCAL time, because that is what every naive
    timestamp in this database is (see the module docstring). ``.astimezone()``
    resolves the offset that applied *on that date*, so a July timestamp gets the
    summer offset and a January one the winter offset — a fixed offset captured
    at import time would silently mis-stamp half the year.

    PRECISION IS PRESERVED, NEVER INVENTED: a seconds-resolution input returns a
    seconds-resolution string. Padding it to microseconds would manufacture a
    precision the source never had, and would make two records of the same event
    compare unequal.

    Returns ``default`` — NOT a guessed or substituted timestamp — for None,
    empty strings, and anything unparseable, so a caller is never silently handed
    a time that was never recorded. Callers that must not lose data should pass
    the original value as ``default`` and keep it verbatim.
    """
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    try:
        parsed = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return default
    # Naive -> local; already-aware values keep the offset they arrived with
    # rather than being shifted into this machine's zone.
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    spec = "microseconds" if parsed.microsecond else "seconds"
    return parsed.isoformat(timespec=spec)


def is_canonical(value):
    """True if ``value`` is already exactly what this module would emit.

    Round-trip test rather than a regex: the definition of canonical is
    "what ``normalize()`` produces", so asking ``normalize()`` cannot drift from
    it the way a second, independent pattern would.
    """
    return isinstance(value, str) and bool(value) and normalize(value) == value
