#!/usr/bin/env python3
"""The Windows behavioral path, proven end to end WITHOUT Windows.

Run: python3 nemesis_agent/test_sysmon_collector.py   (exit 0 = all pass)

WHAT THIS COVERS. Sysmon event XML -> `sysmon_collector` -> `classify_sysmon` ->
`BehavioralMonitor.ingest_sysmon` -> `drain()` -> records that pass the shared
`behavioral_events.validate()`. That whole chain is deliberately platform-free,
which is the entire reason the Windows arm can be finished and proven before a
Windows VM exists. If this suite passes, what remains for Phase 2 is provisioning
(Sysmon install, base image, privilege), not mapping logic.

WHY THE "NOISY EVENT ID" CASES ARE ASSERTIONS AND NOT OMISSIONS. EventIDs 1, 3, 11
and 22 (process create, network connect, file create, DNS) are deliberately absent
from the fallback map: mapped unconditionally they would run to thousands per hour
and bury Layer A's real hits, which the behavioral module's own header names as
the primary failure mode. "Absent" and "forgotten" look identical in a map, so the
absence is PINNED here — if someone later adds EventID 1 without also adding the
config selectivity that makes it safe, this suite says so.

CONTROLS THROUGHOUT. Every "is dropped" assertion is paired with a mapped event
that IS forwarded (a filter that dropped everything would otherwise pass every
negative case), and the parser is proved to extract fields at all before any
mapping conclusion is trusted.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import behavioral_agent as ba          # noqa: E402
import behavioral_events as be         # noqa: E402
import sysmon_collector as sc          # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + detail) if detail else ""))


def ev(event_id, **data):
    """Build a realistic Sysmon <Event> document."""
    rows = "".join('<Data Name="%s">%s</Data>' % (k, v) for k, v in data.items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Microsoft-Windows-Sysmon"/>'
        '<EventID>%d</EventID>'
        '<TimeCreated SystemTime="2026-08-21T12:00:00.000000000Z"/>'
        '<Computer>WS-01</Computer></System>'
        '<EventData>%s</EventData></Event>' % (event_id, rows)
    )


PROC_CREATE = ev(1, RuleName="-", UtcTime="2026-08-21 12:00:00.000",
                 ProcessId="1234", Image=r"C:\Windows\System32\cmd.exe",
                 CommandLine="cmd.exe /c whoami", User="WS-01\\alice",
                 ParentProcessId="1000")
LSASS_ACCESS = ev(10, RuleName="-", UtcTime="2026-08-21 12:00:01.000",
                  SourceProcessId="4321", SourceImage=r"C:\tools\dump.exe",
                  TargetImage=r"C:\Windows\System32\lsass.exe",
                  GrantedAccess="0x1410", User="WS-01\\alice")
INJECTION = ev(8, RuleName="Process Injection", UtcTime="2026-08-21 12:00:02.000",
               SourceProcessId="5555", SourceImage=r"C:\tmp\eviI.exe",
               TargetImage=r"C:\Windows\explorer.exe")


def main():
    print("\n-- PREMISE: the parser extracts fields at all --")
    f = sc.parse_event_xml(PROC_CREATE)
    check("System EventID extracted", f and f.get("EventID") == "1", repr(f))
    check("EventData pairs extracted", f and f.get("CommandLine") == "cmd.exe /c whoami")
    check("namespaced XML handled", f is not None and "Image" in f)

    print("\n-- vocabulary: RuleName beats EventID --")
    check("RuleName maps", ba.classify_sysmon("LSASS Access", 1)
          == ("privilege_escalation", "high"))
    check("EventID fallback maps", ba.classify_sysmon(None, 8)
          == ("privilege_escalation", "high"))
    check("RuleName WINS over the EventID fallback",
          ba.classify_sysmon("Unusual Outbound Connection", 8)
          == ("suspicious_network", "medium"))

    print("\n-- PINNED: the noisy Event IDs are deliberately unmapped --")
    for eid, name in ((1, "process create"), (3, "network connect"),
                      (11, "file create"), (22, "DNS query")):
        check("EventID %d (%s) is NOT mapped by bare ID" % (eid, name),
              ba.classify_sysmon(None, eid) is None,
              "If this now maps, config selectivity must land with it.")
    check("...but the SAME id maps when the config names it",
          ba.classify_sysmon("Suspicious Process Creation", 1)
          == ("suspicious_process", "high"))

    print("\n-- unmapped events are dropped, mapped ones are not (paired) --")
    check("an unnamed process-create normalizes to None",
          sc.normalize(sc.parse_event_xml(PROC_CREATE)) is None)
    check("CONTROL: an LSASS handle-open does normalize",
          sc.normalize(sc.parse_event_xml(LSASS_ACCESS)) is not None)

    print("\n-- the ACTING process is read from the right field --")
    r = sc.normalize(sc.parse_event_xml(LSASS_ACCESS))
    check("EventID 10 actor comes from SourceImage, not Image",
          r["proc"]["proc_path"] == r"C:\tools\dump.exe", repr(r["proc"]))
    check("actor pid comes from SourceProcessId", r["proc"]["proc_pid"] == 4321)
    check("proc_name is the basename", r["proc"]["proc_name"] == "dump.exe")
    check("the TARGET is preserved in detail (the finding is WHAT it opened)",
          "lsass.exe" in (r["detail"] or ""), repr(r["detail"]))

    print("\n-- Sysmon's '-' RuleName means ABSENT, not a rule called '-' --")
    check("'-' does not become the rule identity",
          r["rule"] == "sysmon_eventid_10", repr(r["rule"]))
    named = sc.normalize(sc.parse_event_xml(INJECTION))
    check("a real RuleName IS the rule identity",
          named["rule"] == "Process Injection", repr(named["rule"]))
    check("rule identity is event-type specific (dedup would not merge 8 and 10)",
          sc.normalize(sc.parse_event_xml(ev(25, RuleName="-")))["rule"]
          == "sysmon_eventid_25")

    print("\n-- robustness: never raises, never invents --")
    check("malformed XML -> None", sc.parse_event_xml("<Event><broken") is None)
    check("empty input -> None", sc.parse_event_xml("") is None)
    check("oversized input is refused, not parsed",
          sc.parse_event_xml("<Event/>" + "x" * (sc.MAX_XML_BYTES + 1)) is None)
    check("normalize(None) -> None", sc.normalize(None) is None)
    check("a blob of several events splits",
          len(sc.parse_events(LSASS_ACCESS + INJECTION)) == 2)
    check("CONTROL: a blob of unmapped events yields nothing",
          sc.parse_events(PROC_CREATE + PROC_CREATE) == [])

    print("\n-- JSONL is the shared format both modes emit --")
    line = sc.to_jsonl(sc.parse_events(LSASS_ACCESS))
    check("one record -> one line", line.count("\n") == 1)
    import json as _json
    check("the line round-trips", _json.loads(line.strip())["behavior"]
          == "privilege_escalation")

    print("\n-- the in-guest dump command is bounded and targets the right channel --")
    cmd = sc.dump_command(out_path=r"C:\tmp\obs.json", max_events=10)
    joined = " ".join(cmd)
    # ABSOLUTE path, not just "looks like powershell": guestcontrol resolves no
    # PATH, so a bare "powershell.exe" is unusable in the guest. The weaker
    # assertion passed while the command could not run -- caught only by the
    # first live detonation.
    check("interpreter is an ABSOLUTE path (guestcontrol resolves no PATH)",
          cmd[0].startswith("C:\\") and cmd[0].lower().endswith("powershell.exe"),
          repr(cmd[0]))
    check("names the Sysmon channel", sc.SYSMON_CHANNEL in joined)
    check("is BOUNDED (MaxEvents)", "-MaxEvents 10" in joined, joined[:200])
    check("writes to the requested path", r"C:\tmp\obs.json" in joined)
    check("is non-interactive (a detonation guest has no console)",
          "-NonInteractive" in joined)

    print("\n-- PROCESS-ANCESTRY FILTER (the detonation noise fix) --")
    #
    # Modelled on the real problem: the sample's tree is a handful of events
    # inside a flood the operating system produced. Unrelated events use the SAME
    # event types, so only ancestry can separate them.
    def pcreate(pid, ppid, guid, pguid, image):
        return ev(1, RuleName="Suspicious Process Creation",
                  UtcTime="2026-08-21 12:00:00.000", ProcessId=str(pid),
                  ParentProcessId=str(ppid), ProcessGuid=guid,
                  ParentProcessGuid=pguid, Image=image)

    ROOT, CHILD, GRAND, OTHER = 100, 200, 300, 999
    G = {ROOT: "{g-root}", CHILD: "{g-child}", GRAND: "{g-grand}", OTHER: "{g-other}"}
    blob = (
        pcreate(ROOT, 4, G[ROOT], "{g-boot}", r"C:\sample.exe")
        # grandchild logged BEFORE its parent, on purpose: a single-pass tree walk
        # would lose it, and losing a descendant means losing the sample's work.
        + pcreate(GRAND, CHILD, G[GRAND], G[CHILD], r"C:\Windows\System32\whoami.exe")
        + pcreate(CHILD, ROOT, G[CHILD], G[ROOT], r"C:\Windows\System32\cmd.exe")
        + pcreate(OTHER, 4, G[OTHER], "{g-boot}", r"C:\Windows\System32\svchost.exe")
        + ev(9, RuleName="-", ProcessId=str(OTHER), ProcessGuid=G[OTHER],
             Image=r"C:\Windows\System32\svchost.exe")
        + ev(9, RuleName="-", ProcessId=str(GRAND), ProcessGuid=G[GRAND],
             Image=r"C:\Windows\System32\whoami.exe")
    )
    unfiltered = sc.parse_events(blob)
    filtered = sc.parse_events(blob, root_pid=ROOT)
    check("CONTROL: unfiltered keeps everything (filter is opt-in)",
          len(unfiltered) == 6, len(unfiltered))
    check("filtering actually REMOVES records (not a vacuous no-op)",
          len(filtered) < len(unfiltered), (len(filtered), len(unfiltered)))
    names = sorted((r["proc"] or {}).get("proc_name") for r in filtered)
    check("the root, its child and its GRANDCHILD are kept",
          names.count("sample.exe") == 1 and names.count("cmd.exe") == 1
          and names.count("whoami.exe") == 2, names)
    check("the unrelated svchost tree is dropped entirely",
          "svchost.exe" not in names, names)

    print("\n-- GUID beats PID: a recycled PID must NOT be adopted --")
    recycled = blob + ev(9, RuleName="-", ProcessId=str(CHILD),
                         ProcessGuid="{g-someone-else}",
                         Image=r"C:\Windows\System32\lsass.exe")
    f2 = sc.parse_events(recycled, root_pid=ROOT)
    check("a different process reusing the child's PID is EXCLUDED",
          all((r["proc"] or {}).get("proc_name") != "lsass.exe" for r in f2),
          [(r["proc"] or {}).get("proc_name") for r in f2])
    check("CONTROL: without the filter that same record IS present",
          any((r["proc"] or {}).get("proc_name") == "lsass.exe"
              for r in sc.parse_events(recycled)))

    print("\n-- fallback when the root has no birth record --")
    orphan = (ev(9, RuleName="-", ProcessId="777", Image=r"C:\x.exe")
              + ev(9, RuleName="-", ProcessId="888", Image=r"C:\y.exe"))
    f3 = sc.parse_events(orphan, root_pid=777)
    check("falls back to PID-only rather than returning nothing",
          len(f3) == 1 and (f3[0]["proc"] or {}).get("proc_name") == "x.exe",
          [(r["proc"] or {}).get("proc_name") for r in f3])

    print("\n-- the tree-walk helpers are usable on their own --")
    parsed = [sc.parse_event_xml(c) for c in sc._split_events(blob)]
    pm, gp = sc.build_parent_map([f for f in parsed if f])
    check("parent map is built from ProcessCreate records", pm.get(G[CHILD]) == G[ROOT])
    check("descendants reach the grandchild",
          G[GRAND] in sc.descendant_guids(pm, G[ROOT]))
    check("descendants exclude an unrelated tree",
          G[OTHER] not in sc.descendant_guids(pm, G[ROOT]))

    print("\n-- dump_command distinguishes UNREADABLE from EMPTY --")
    #
    # The failure this guards: under SilentlyContinue a real error (channel not
    # readable, Sysmon absent) produced an EMPTY file and exit 0, so the host
    # reported "0 events" -- indistinguishable from "the sample did nothing".
    # In a malware sandbox that is a false BENIGN, the worst direction.
    d = " ".join(sc.dump_command())
    check("readability is probed with -ListLog before reading events",
          "-ListLog" in d, d[:200])
    check("a real error exits NON-ZERO (so the caller can see it)",
          "exit 2" in d, d[:200])
    # SUBSTRING PRESENCE IS NOT REACHABILITY. `exit 2` being in the string proves
    # nothing about whether it RUNS. Under $ErrorActionPreference='Stop',
    # `Write-Error` is itself terminating: it would abort from inside the catch
    # block, the exit 2 would never execute, and the script would exit 1 -- while
    # this very check still passed. That is a check that can only ever say yes,
    # which is the failure class this repo greps for. So assert the structural
    # property that makes the exit REACHABLE, not merely present.
    _stops = "$ErrorActionPreference='Stop'" in d
    _catch = d.split("catch {", 1)[-1].split("};", 1)[0] if "catch {" in d else ""
    check("the catch block emits its message NON-terminatingly",
          not _stops or "Write-Error" not in _catch,
          "Write-Error inside catch under Stop => exit 2 unreachable: %r" % _catch[:120])
    check("CONTROL: the catch block really was located (not a vacuous pass)",
          "exit 2" in _catch, _catch[:120])
    check("the success path exits 0 explicitly", "exit 0" in d)
    # Localized-string matching is what makes this kind of check fail on a German
    # or Japanese guest, silently taking the wrong branch.
    check("discrimination does NOT depend on a localized message string",
          "No events were found" not in d, d[:200])
    check("an empty log is still tolerated (SilentlyContinue on the READ only)",
          "-ErrorAction SilentlyContinue" in d)

    print("\n-- END TO END: Sysmon XML -> monitor -> SCHEMA-VALID events --")
    mon = ba.BehavioralMonitor("dev-win-1", window_s=60, max_per_window=100)
    for rec in sc.parse_events(LSASS_ACCESS + INJECTION):
        mon.ingest_sysmon(rec, consent_version=3)
    drained = mon.drain()
    check("both mapped events were forwarded", len(drained) == 2, repr(len(drained)))
    errs = [e for d in drained for e in be.validate(d)]
    # `errs == []` and `all(...)` are both VACUOUSLY true on an empty list, so the
    # non-emptiness is asserted first -- otherwise a chain that produced nothing
    # would report a clean pass.
    check("there ARE records to validate (not a vacuous pass)", len(drained) > 0)
    check("every emitted record passes the SHARED wire schema", errs == [], repr(errs))
    check("they are labelled source=sysmon",
          all(d["source"] == "sysmon" for d in drained))
    check("consent rides every record", all(d["consent_version"] == 3 for d in drained))

    print("\n-- consent gate still applies on the Windows path --")
    mon2 = ba.BehavioralMonitor("dev-win-2")
    got = mon2.ingest_sysmon(sc.parse_events(LSASS_ACCESS)[0], consent_version=None)
    check("no consent -> not ingested", got is False and mon2.drain() == [])

    print("\n-- BUG FIX 1: suppression summary names the RIGHT engine --")
    mon3 = ba.BehavioralMonitor("dev-win-3", window_s=600, max_per_window=1)
    recs = sc.parse_events(LSASS_ACCESS + INJECTION)
    for rec in recs:
        mon3.ingest_sysmon(rec, consent_version=1)
    # a third, distinct event to push past the cap of 1
    mon3.ingest_sysmon(sc.parse_events(ev(25, RuleName="-"))[0], consent_version=1)
    out = mon3.drain()
    supp = [d for d in out if d["rule"] == "__rate_suppressed__"]
    check("a suppression summary was emitted", len(supp) == 1, repr(out))
    check("it says source=sysmon, NOT the hardcoded 'falco'",
          supp and supp[0]["source"] == "sysmon",
          repr(supp[0]["source"]) if supp else "none")
    check("the summary itself is schema-valid", supp and be.validate(supp[0]) == [])
    check("CONTROL: a Falco suppression still says falco",
          _falco_suppression_source() == "falco")

    print("\n-- BUG FIX 2: status_reader knows what OS it is on --")
    check("unknown platform -> not present (honest gap)",
          ba.status_reader(platform="sunos5", runner=lambda c: (1, "", ""),
                           which=lambda n: None) == (False, None, None, False))

    def win_runner(cmd):
        if cmd[:2] == ["sc", "query"] and cmd[2] == "Sysmon64":
            return 0, "SERVICE_NAME: Sysmon64\n  STATE : 4  RUNNING", ""
        if cmd[0] == "powershell":
            return 0, "15.15\n", ""
        return 1, "", ""
    present, version, _rs, running = ba.status_reader(platform="win32",
                                                      runner=win_runner)
    check("Windows: a running Sysmon service is PRESENT", present is True)
    check("Windows: and reported RUNNING", running is True)
    check("Windows: version is read", version == "15.15", repr(version))

    def win_stopped(cmd):
        if cmd[:2] == ["sc", "query"] and cmd[2] == "Sysmon64":
            return 0, "SERVICE_NAME: Sysmon64\n  STATE : 1  STOPPED", ""
        return 1, "", ""
    present, _v, _r, running = ba.status_reader(platform="win32", runner=win_stopped)
    check("Windows: installed-but-stopped is present AND not running",
          present is True and running is False)

    def win_absent(cmd):
        return 1, "", "The specified service does not exist"
    check("Windows: no service -> not present",
          ba.status_reader(platform="win32", runner=win_absent)
          == (False, None, None, False))

    def win32_only(cmd):
        if cmd[:2] == ["sc", "query"] and cmd[2] == "Sysmon":
            return 0, "SERVICE_NAME: Sysmon\n  STATE : 4  RUNNING", ""
        return 1, "", ""
    present, _v, _r, running = ba.status_reader(platform="win32", runner=win32_only)
    check("Windows: a 32-bit 'Sysmon' install is also found",
          present is True and running is True)

    check("Linux branch still uses which()+pgrep and reports absent when missing",
          ba.status_reader(platform="linux", which=lambda n: None,
                           runner=lambda c: (1, "", ""))
          == (False, None, None, False))
    check("CONTROL: Linux reports PRESENT when falco is on PATH",
          ba.status_reader(platform="linux", which=lambda n: "/usr/bin/falco",
                           runner=lambda c: (0, "falco 0.44.1", ""))[0] is True)

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


def _falco_suppression_source():
    """Drive the Falco path past the cap and report the summary's source."""
    mon = ba.BehavioralMonitor("dev-lnx", window_s=600, max_per_window=1)
    for rule in ("Read sensitive file untrusted", "Write below binary dir",
                 "Modify binary dirs"):
        mon.ingest_falco({"rule": rule, "output_fields": {"proc.name": "x"},
                          "output": "o"}, consent_version=1)
    for d in mon.drain():
        if d["rule"] == "__rate_suppressed__":
            return d["source"]
    return None


if __name__ == "__main__":
    sys.exit(main())
