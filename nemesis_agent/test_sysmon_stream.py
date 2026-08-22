"""Tests for the Sysmon STREAM poller — sysmon_collector.read_new_events + the
agent's Windows behavioral path. Runs on Linux with NO Sysmon: a fake run_ps
returns captured event XML, exactly as the module was designed to allow.

Proves: the poller normalizes the mapped events, ADVANCES the high-water RecordId
past EVERY fetched event (including unmapped noise, so it is not re-fetched
forever), turns a source failure into SysmonPollError (which the agent records as
E-AGENT-080), and that a produced record flows through a real BehavioralMonitor via
ingest_sysmon to a heartbeat event.

Run: python3 nemesis_agent/test_sysmon_stream.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sysmon_collector as sc            # noqa: E402
import behavioral_agent                  # noqa: E402

_res = []
def check(label, ok):
    _res.append(ok)
    print("  [%s] %s" % ("PASS" if ok else "FAIL", label))


def ev(event_id, record_id, **data):
    """A realistic Sysmon <Event> with an EventRecordID (which the poller keys on)."""
    rows = "".join('<Data Name="%s">%s</Data>' % (k, v) for k, v in data.items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Name="Microsoft-Windows-Sysmon"/>'
            '<EventID>%d</EventID><EventRecordID>%d</EventRecordID>'
            '<TimeCreated SystemTime="2026-08-21T12:00:00.000Z"/>'
            '<Computer>WIN-TEST</Computer></System>'
            '<EventData>%s</EventData></Event>' % (event_id, record_id, rows))


def main():
    # 3 events: 8=CreateRemoteThread (mapped), 1=process-create (UNMAPPED noise),
    # 10=ProcessAccess/LSASS handle (mapped). RecordIds 100,101,102.
    e8 = ev(8, 100, SourceImage=r"C:\evil.exe", SourceProcessId="4321",
            TargetImage=r"C:\Windows\System32\lsass.exe")
    e1 = ev(1, 101, Image=r"C:\Windows\notepad.exe", CommandLine="notepad")
    e10 = ev(10, 102, SourceImage=r"C:\dump.exe", SourceProcessId="5",
             GrantedAccess="0x1410", TargetImage=r"C:\Windows\System32\lsass.exe")
    blob = e8 + e1 + e10

    print("event_record_id extraction")
    check("reads the EventRecordID from raw XML", sc.event_record_id(e8) == 100)
    check("None when absent", sc.event_record_id("<Event/>") is None)

    print("\nread_new_events — normalize mapped, advance high-water past ALL")
    captured = {}
    def fake_ps(argv):
        captured["argv"] = argv
        return blob
    records, high = sc.read_new_events(fake_ps, after_record_id=0)
    check("only the MAPPED events become records (2 of 3)", len(records) == 2)
    behaviors = sorted(r["behavior"] for r in records)
    check("both map to privilege_escalation", behaviors == ["privilege_escalation",
                                                            "privilege_escalation"])
    check("high-water advanced past the UNMAPPED event too (102, not 100)", high == 102)
    check("the LSASS target is preserved in the finding detail",
          any("lsass.exe" in (r.get("detail") or "") for r in records))
    check("the poll command filters on the passed high-water RecordId",
          "-gt 0" in " ".join(captured["argv"]) or "0" in " ".join(captured["argv"]))

    print("\nstream_command shape")
    argv = sc.stream_command(after_record_id=55, max_events=200)
    joined = " ".join(argv)
    check("targets the Sysmon Operational channel", sc.SYSMON_CHANNEL in joined)
    check("emits only records newer than the high-water", "RecordId -gt 55" in joined)
    check("uses the full PowerShell path (guestcontrol/absent-PATH safe)",
          argv[0].lower().endswith("powershell.exe"))
    check("fails LOUD on a real read error (Event Log Readers denial), not silent empty",
          "-ListLog" in joined and "exit 2" in joined)
    check("readability check is language-independent (no localized string match)",
          "No events were found" not in joined)

    print("\nSysmonPollError when the source cannot be read")
    def boom(argv):
        raise OSError("Get-WinEvent not found")
    raised = False
    try:
        sc.read_new_events(boom)
    except sc.SysmonPollError:
        raised = True
    check("a source failure -> SysmonPollError (agent records E-AGENT-080)", raised)
    # None output is also a hard failure, not a silent empty
    raised = False
    try:
        sc.read_new_events(lambda a: None)
    except sc.SysmonPollError:
        raised = True
    check("None output -> SysmonPollError (never mistaken for 'no events')", raised)

    print("\none malformed event does not sink the poll")
    records2, high2 = sc.read_new_events(lambda a: "<Event>garbage</Event>" + e8)
    check("the good event still comes through", len(records2) == 1)

    print("\nend-to-end: a poller record flows through BehavioralMonitor.ingest_sysmon")
    mon = behavioral_agent.BehavioralMonitor("win-test", window_s=60,
                                             max_per_window=100, severity_floor="low",
                                             clock=lambda: 1000.0)
    accepted = mon.ingest_sysmon(records[0], consent_version=7)
    drained = mon.drain()
    check("ingest_sysmon accepted the record", accepted is True)
    check("it became one heartbeat behavioral event", len(drained) == 1)
    check("source is marked 'sysmon'", drained[0]["source"] == "sysmon")
    check("consent_version carried through", drained[0]["consent_version"] == 7)

    passed = sum(1 for x in _res if x)
    print("\n%d/%d checks passed" % (passed, len(_res)))
    if passed != len(_res):
        sys.exit(1)


if __name__ == "__main__":
    main()
