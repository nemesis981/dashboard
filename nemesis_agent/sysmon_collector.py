#!/usr/bin/env python3
"""Sysmon Event Log -> normalized behavioral records. The Windows front door.

Malware Layer B behavioral half, Windows arm. The Linux counterpart is Falco
writing JSON lines to a file that `agent.py`'s tailer reads; this module is what
stands in for that on Windows, because **Sysmon does not write a file** — it
writes to the `Microsoft-Windows-Sysmon/Operational` Event Log channel.

WHAT THIS MODULE IS, AND DELIBERATELY IS NOT
--------------------------------------------
It is EXTRACTION ONLY: Sysmon event XML -> a flat dict of fields -> the normalized
record shape `behavioral_agent.ingest_sysmon()` expects.

It does NOT decide what a given event MEANS. That judgement — which Event ID or
RuleName counts as `privilege_escalation` — lives in `behavioral_agent`'s
SYSMON_RULE_MAP / SYSMON_EVENTID_MAP, beside the Falco map, and is reached here
only through `classify_sysmon()`. That split is deliberate (operator decision,
2026-08-21): the vocabulary is the security-relevant half and belongs somewhere
reviewable and testable on any OS, while the XML shape is Windows trivia. It also
means this whole module is unit-testable on Linux against captured XML, with no
Windows, no Sysmon and no Event Log — which is the only reason the Windows path
can be proven before a Windows VM exists.

TWO CONSUMERS, TWO MODES — a real difference from the Linux side
----------------------------------------------------------------
Falco satisfies both consumers with one file. Sysmon does not, so both are served
from this one mapping layer:

  * DUMP (the detonation sandbox): one-shot. The host runs `dump_command()` in the
    guest over guestcontrol, which writes JSONL to a path, then pulls it with
    `copyfrom`. No service inside a throwaway VM, no state, and it captures
    everything since boot.
  * STREAM (a live endpoint): a small forwarder runs `to_jsonl()` over new records
    and appends them to a file, so `agent.py`'s existing tailer works unchanged.

Both produce the SAME JSONL, so everything downstream — tailer, monitor, dedup,
rate ceiling, heartbeat — is shared with Linux.

NEVER RAISES on a single malformed record: one bad event must not stall a reader
loop or cost a heartbeat, matching the module it feeds.
"""
import json
import logging
import re
import xml.etree.ElementTree as _ET

from behavioral_agent import classify_sysmon

log = logging.getLogger("nemesis_agent.sysmon")

#: Bound on one XML blob. A guest under detonation is exactly the situation where
#: an enormous or pathological document could arrive, and an unbounded parse on
#: the HOST side of a malware sandbox is not a risk worth taking for tidiness.
MAX_XML_BYTES = 8 * 1024 * 1024

#: Sysmon names the ACTING process differently per event type. For 8
#: (CreateRemoteThread) and 10 (ProcessAccess) the actor is Source*, and Image is
#: absent — reading `Image` blindly would attribute an injection to nothing at
#: all, losing the one field that says WHO did it.
_ACTOR_IMAGE = ("Image", "SourceImage")
_ACTOR_PID = ("ProcessId", "SourceProcessId")


def _localname(tag):
    """Tag without its XML namespace. Sysmon events carry a default namespace, so
    every ElementTree lookup would otherwise need it spelled out."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _first(fields, names):
    for n in names:
        v = fields.get(n)
        if v:
            return v
    return None


def parse_event_xml(xml_text):
    """One Sysmon `<Event>` XML string -> flat {field: value}, or None.

    Merges `<System>` metadata (EventID, TimeCreated) with the `<EventData>`
    `<Data Name="X">` pairs into one dict. Returns None on anything unparseable —
    never raises.
    """
    if not xml_text or len(xml_text) > MAX_XML_BYTES:
        return None
    try:
        root = _ET.fromstring(xml_text)
    except Exception as exc:                                  # noqa: BLE001
        log.debug("sysmon: unparseable event xml: %s", exc)
        return None
    fields = {}
    for el in root.iter():
        name = _localname(el.tag)
        if name == "EventID":
            fields["EventID"] = (el.text or "").strip()
        elif name == "TimeCreated":
            st = el.attrib.get("SystemTime")
            if st:
                fields["SystemTime"] = st
        elif name == "Computer":
            fields["Computer"] = (el.text or "").strip()
        elif name == "Data":
            key = el.attrib.get("Name")
            if key:
                fields[key] = (el.text or "").strip()
    return fields or None


def normalize(fields):
    """Flat Sysmon fields -> the record `ingest_sysmon()` expects, or None.

    None means "not in our vocabulary" — the overwhelming majority of Sysmon
    output — and is returned rather than a default record, for the same reason
    `classify_sysmon` returns None: inventing a behavior for unmapped kernel noise
    is how a behavioral layer becomes a noise generator.
    """
    if not fields:
        return None
    rule_name = fields.get("RuleName") or None
    # Sysmon writes the literal "-" for an unmatched RuleName. Treated as absent,
    # or every unnamed event would share one bogus rule identity and dedup would
    # fold unrelated events together.
    if rule_name in ("-", ""):
        rule_name = None
    event_id = fields.get("EventID")
    hit = classify_sysmon(rule_name, event_id)
    if hit is None:
        return None
    behavior, severity = hit

    image = _first(fields, _ACTOR_IMAGE)
    proc = {
        "proc_name": image.rsplit("\\", 1)[-1] if image else None,
        "proc_path": image,
        "proc_cmdline": fields.get("CommandLine"),
        "proc_pid": _as_int(_first(fields, _ACTOR_PID)),
        "proc_ppid": _as_int(fields.get("ParentProcessId")),
        "proc_user": fields.get("User"),
    }
    # A target, when the event has one, is the most useful thing in the record:
    # "opened a handle to lsass.exe" is the finding, not "opened a handle".
    detail_bits = []
    target = fields.get("TargetImage") or fields.get("TargetFilename")
    if target:
        detail_bits.append("target=%s" % target)
    if fields.get("DestinationIp"):
        detail_bits.append("dest=%s:%s" % (fields.get("DestinationIp"),
                                           fields.get("DestinationPort") or "?"))
    if fields.get("QueryName"):
        detail_bits.append("query=%s" % fields["QueryName"])
    if fields.get("GrantedAccess"):
        detail_bits.append("granted=%s" % fields["GrantedAccess"])

    return {
        "behavior": behavior,
        "severity": severity,
        # `rule` is what dedup keys on, so an unnamed event must still get a
        # STABLE, event-type-specific identity — not a single shared placeholder.
        "rule": rule_name or ("sysmon_eventid_%s" % event_id),
        "ts": fields.get("UtcTime") or fields.get("SystemTime") or "",
        "proc": proc,
        "detail": "; ".join(detail_bits) or None,
    }


# ---- process-ancestry filtering ------------------------------------------
#
# WHY THIS EXISTS, measured rather than assumed. A live Windows detonation on
# 2026-08-21 produced ~1550 mapped Sysmon records of which only ~6% came from the
# sample. The rest was the operating system doing its job: svchost opening LSASS
# handles, System and svchost issuing RawAccessRead, SearchIndexer walking the
# disk, Edge WebView writing files. Narrowing the Sysmon config by EVENT TYPE
# halved the volume and moved that ratio by barely a point -- because the noise is
# the SAME event types from DIFFERENT processes.
#
# Ancestry is the discriminator that actually separates them: in a detonation we
# KNOW which process was launched (detonate.ps1 records its PID), so everything
# outside that process tree is, by construction, not the sample.
#
# WHY GUID FIRST, PID SECOND. Windows reuses PIDs, and a detonation deliberately
# churns processes. Sysmon stamps every process with a ProcessGuid that is unique
# for the life of the machine, so the tree is walked on GUIDs and PIDs are only a
# fallback for records that carry no GUID. Getting this backwards would silently
# adopt an unrelated process that inherited a recycled PID -- which in a malware
# sandbox means attributing someone else's behaviour to the sample.
#
# Filtering happens on the RAW parsed fields, before normalize(), because the
# normalized record intentionally does not carry GUIDs and because a ProcessCreate
# that maps to nothing is still needed to build the tree.

#: Sysmon names the acting process differently per event type (see _ACTOR_*).
_ACTOR_GUID = ("ProcessGuid", "SourceProcessGuid")


def build_parent_map(field_dicts):
    """{child_guid: parent_guid} plus {guid: pid}, from ProcessCreate records.

    Only EventID 1 carries ParentProcessGuid, so only those can extend the tree.
    Returns ({}, {}) when there are none, which makes the caller fall back to
    PID-only matching rather than silently filtering everything away.
    """
    parent = {}
    guid_pid = {}
    for f in field_dicts:
        if not f:
            continue
        guid = f.get("ProcessGuid")
        if guid:
            guid_pid[guid] = _as_int(f.get("ProcessId"))
        if f.get("EventID") == "1" and guid and f.get("ParentProcessGuid"):
            parent[guid] = f["ParentProcessGuid"]
    return parent, guid_pid


def descendant_guids(parent_map, root_guid):
    """`root_guid` and every process descended from it."""
    tree = {root_guid}
    # Repeat to a fixed point: children can appear in any order in the log, so a
    # single pass would miss a grandchild logged before its parent.
    changed = True
    while changed:
        changed = False
        for child, parent in parent_map.items():
            if parent in tree and child not in tree:
                tree.add(child)
                changed = True
    return tree


def _root_guid_for_pid(field_dicts, root_pid):
    """The ProcessGuid of the process that had `root_pid`, or None.

    Prefers a ProcessCreate record, which is the authoritative birth record for
    that PID in this run.
    """
    for f in field_dicts:
        if f and f.get("EventID") == "1" and _as_int(f.get("ProcessId")) == root_pid:
            return f.get("ProcessGuid")
    for f in field_dicts:
        if f and _as_int(f.get("ProcessId")) == root_pid and f.get("ProcessGuid"):
            return f.get("ProcessGuid")
    return None


def _in_tree(fields, guids, pids):
    for k in _ACTOR_GUID:
        g = fields.get(k)
        if g:
            return g in guids
    for k in _ACTOR_PID:
        p = _as_int(fields.get(k))
        if p is not None:
            return p in pids
    return False


def parse_events(xml_text, root_pid=None):
    """A blob of one or more `<Event>` documents -> list of normalized records.

    Accepts either a single event, several concatenated (what `wevtutil qe`
    produces), or a wrapping root element. Unmapped and unparseable events are
    skipped, so the returned list is only what this layer actually claims.

    `root_pid` (optional) restricts the result to that process and its
    descendants -- the detonation case, where everything else is the operating
    system rather than the sample. Omitted, this behaves exactly as before, so
    the live-endpoint streaming path is unaffected.
    """
    parsed = [f for f in (parse_event_xml(c) for c in _split_events(xml_text)) if f]

    guids = pids = None
    if root_pid is not None:
        parent_map, guid_pid = build_parent_map(parsed)
        root_guid = _root_guid_for_pid(parsed, root_pid)
        if root_guid:
            guids = descendant_guids(parent_map, root_guid)
            pids = {guid_pid.get(g) for g in guids if guid_pid.get(g) is not None}
            pids.add(root_pid)
        else:
            # No birth record for that PID. Fall back to the PID alone rather
            # than returning nothing: a narrowed-but-honest result beats an empty
            # one that reads as "the sample did nothing".
            log.warning("sysmon: no ProcessGuid found for root pid %s; "
                        "falling back to PID-only attribution", root_pid)
            guids, pids = set(), {root_pid}

    records = []
    for f in parsed:
        if pids is not None and not _in_tree(f, guids, pids):
            continue
        rec = normalize(f)
        if rec is not None:
            records.append(rec)
    return records


def _split_events(xml_text):
    """Yield individual `<Event>...</Event>` documents from a blob."""
    if not xml_text:
        return
    # Fast path: a single well-formed document that already parses.
    stripped = xml_text.strip()
    if stripped.count("<Event") <= 1:
        yield stripped
        return
    start = 0
    while True:
        i = xml_text.find("<Event", start)
        if i < 0:
            return
        j = xml_text.find("</Event>", i)
        if j < 0:
            return
        yield xml_text[i:j + len("</Event>")]
        start = j + len("</Event>")


def to_jsonl(records):
    """Normalized records -> JSON lines, the ONE format both modes emit.

    Identical to what Falco writes on Linux in shape-of-consumption: one JSON
    object per line, so `agent.py`'s tailer and the sandbox's `copyfrom`
    collector both work unchanged.
    """
    return "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records)


#: Where the Windows observer writes its JSONL, mirroring Falco's
#: /var/log/falco/events.json. Passed to DisposableSandbox(observer_path=...).
DEFAULT_OBSERVER_PATH = r"C:\ProgramData\Nemesis\behavioral\events.json"

#: The Sysmon channel. Named once, here, so the deploy script, the dump command
#: and any future reader cannot drift apart on it.
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


#: FULL PATH, because guestcontrol resolves no PATH. Passing a bare
#: "powershell.exe" fails with `No such file or directory "powershell.exe" on
#: guest` -- found on the first live detonation 2026-08-21, after a unit test
#: that asserted only `startswith("powershell")` had passed happily.
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def dump_command(out_path=DEFAULT_OBSERVER_PATH, max_events=5000):
    """The in-guest PowerShell one-shot dump, as an argv list for guestcontrol.

    Emits the RAW Sysmon XML for the channel to `out_path`. Raw rather than
    pre-normalized on purpose: normalization happens HOST-side through this
    module, so the mapping the host applies is the same code the unit tests
    exercise — a guest-side transform would be an untested second implementation
    running inside the very VM that just detonated malware.

    Bounded by `max_events`: a detonation that generates unbounded events must not
    produce an unbounded file to pull back across the control channel.
    """
    # AN EMPTY RESULT AND A FAILED READ MUST NOT LOOK THE SAME.
    #
    # This used to run under $ErrorActionPreference='SilentlyContinue', so a real
    # failure -- the channel unreadable by this account, Sysmon not installed, the
    # log absent -- produced an EMPTY file and exit 0. The host then reported
    # "0 events", which is indistinguishable from "the sample did nothing": a
    # false BENIGN, the worst direction for a malware sandbox to fail in.
    # (Window 1 found the identical shape in the streaming path from the same
    # unprivileged-read wall; this is that fix applied to the dump path.)
    #
    # READABILITY IS PROBED SEPARATELY FROM EMPTINESS. `-ListLog` answers "can this
    # account see this channel at all", which is the auth/existence question;
    # only then is an empty event set a genuine answer. Deliberately NOT done by
    # matching the "No events were found" message: that string is localized, so a
    # non-English guest would take the wrong branch silently.
    ps = (
        # `Write-Error` is NOT used here, deliberately. Under
        # $ErrorActionPreference='Stop' it is itself a TERMINATING error, so it
        # would abort the script from inside the catch block and the `exit 2`
        # below would never run -- yielding exit 1 and a contract that says one
        # thing and does another. [Console]::Error.WriteLine just writes, so the
        # explicit exit code survives. (Pattern taken from the streaming path,
        # where Window 1 proved it live on Windows.)
        "$ErrorActionPreference='Stop';"
        "try { $null = Get-WinEvent -ListLog '%s' -ErrorAction Stop } catch {"
        " [Console]::Error.WriteLine("
        "'SYSMON_READ_ERROR: sysmon channel not readable: ' + $_.Exception.Message);"
        " exit 2 };"
        "New-Item -ItemType Directory -Force -Path (Split-Path '%s') | Out-Null;"
        "$ev = @(Get-WinEvent -LogName '%s' -MaxEvents %d"
        " -ErrorAction SilentlyContinue);"
        "($ev | ForEach-Object { $_.ToXml() }) |"
        " Set-Content -Encoding UTF8 '%s';"
        "exit 0"
    ) % (SYSMON_CHANNEL, out_path, SYSMON_CHANNEL, int(max_events), out_path)
    return [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", ps]


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ── STREAM mode: the live-endpoint poller (the agent's own collector path) ────
#
# dump_command above is the sandbox's one-shot. A LIVE endpoint instead needs to
# poll for NEW events and feed them to the running agent's behavioral monitor.
# That poller lives here (it was the STREAM mode this module's header promised but
# had not built); agent.py drives it on Windows exactly as _behavioral_tail drives
# Falco on Linux, and both end at the same BehavioralMonitor.

class SysmonPollError(RuntimeError):
    """The live event source could not be read at all (as opposed to a single bad
    event, which is swallowed). Lets the agent record E-AGENT-080 and back off."""


_RECORD_ID_RE = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")


def event_record_id(xml_text):
    """The EventRecordID from one raw Sysmon event's XML, or None. The live poller
    advances its high-water mark past EVERY fetched event — including unmapped ones —
    so it never re-fetches the same noise forever."""
    m = _RECORD_ID_RE.search(xml_text or "")
    return int(m.group(1)) if m else None


def stream_command(after_record_id=0, max_events=1000):
    """PowerShell argv for the live agent poller: emit the raw XML of Sysmon events
    with RecordId > after_record_id to STDOUT (unlike dump_command, which writes a
    file for the sandbox's copyfrom — the live agent captures stdout directly).

    after_record_id=0 on the first poll returns up to max_events recent events; the
    agent then tracks the high-water RecordId so each later poll returns only what
    is new. Sorted ascending so the high-water advances monotonically.

    ERROR HANDLING IS LOAD-BEARING, not tidiness. A naive `2>$null /
    SilentlyContinue` here would turn the 'channel not readable by this account'
    error (the unprivileged agent user is not in Event Log Readers) into EMPTY
    output — i.e. a failed read masquerading as 'no events', the exact
    default-a-failure-to-a-legal-value trap this codebase keeps finding.

    It discriminates READABILITY from EMPTINESS with two separate steps, so the
    check is language-independent (Window 3's catch, 2026-08-21: matching the
    localized 'No events were found' text would false-alarm E-AGENT-080 on a healthy
    quiet NON-ENGLISH endpoint):
      1. `Get-WinEvent -ListLog` PROBES access to the channel. If the account cannot
         see it, this throws in ANY locale -> exit 2 -> runner raises ->
         SysmonPollError -> E-AGENT-080.
      2. Only after that succeeds do we read events; an empty result there is now
         genuinely an empty log (SilentlyContinue), not a masked auth failure."""
    ps = (
        "$ProgressPreference='SilentlyContinue';"
        "try { $null = Get-WinEvent -ListLog '%s' -ErrorAction Stop }"
        " catch { [Console]::Error.WriteLine('SYSMON_READ_ERROR: ' + $_.Exception.Message); exit 2 }"
        "Get-WinEvent -FilterHashtable @{LogName='%s'} -MaxEvents %d -ErrorAction SilentlyContinue |"
        " Where-Object { $_.RecordId -gt %d } |"
        " Sort-Object RecordId |"
        " ForEach-Object { $_.ToXml() }"
    ) % (SYSMON_CHANNEL, SYSMON_CHANNEL, int(max_events), int(after_record_id))
    return [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", ps]


def read_new_events(run_ps, after_record_id=0, max_events=1000):
    """One live poll. `run_ps(argv) -> xml_text` is injected (the agent supplies a
    subprocess runner; tests supply captured XML), so this whole path is testable on
    Linux with no Sysmon. Normalizes the mapped events and advances the high-water
    mark past ALL fetched events.

    Returns (records, high_water_record_id). NEVER raises for a single malformed
    event. Raises SysmonPollError if the source could not be read at all — the one
    condition the agent turns into E-AGENT-080."""
    try:
        xml = run_ps(stream_command(after_record_id, max_events))
    except Exception as exc:                                  # noqa: BLE001
        raise SysmonPollError("event source invocation failed: %s" % exc)
    if xml is None:
        raise SysmonPollError("event source returned no output")
    records = []
    high = after_record_id
    for raw in _split_events(xml):
        rid = event_record_id(raw)
        if rid is not None and rid > high:
            high = rid
        try:
            fields = parse_event_xml(raw)
            rec = normalize(fields) if fields else None
        except Exception:                                    # noqa: BLE001
            rec = None                                       # one bad event, skip
        if rec:
            records.append(rec)
    return records, high
