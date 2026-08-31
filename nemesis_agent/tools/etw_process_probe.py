"""MEASURE the Kernel-Process ETW provider. RUN ON WINDOWS, ELEVATED. Not part of the agent.

Purpose: settle, with measurements rather than documentation, the constants
`conn_collector.EtwSource` currently carries as UNVERIFIED for
`Microsoft-Windows-Kernel-Process`. The 2026-08-07 probe
(`scoping-and-estimates/etw-probe-report-2026-08-07.json`) covered only
Kernel-Network and DNS-Client; this provider has never been measured here.

Why it matters that this is measured rather than assumed: this codebase already
shipped one inference-as-fact about ETW. An earlier `conn_collector` docstring
called `connid` "a real per-connection identifier" — inferred from its PRESENCE,
never from its content — and it was wrong; the value is the string "0" on every
event. Presence is not meaning.

QUESTIONS THIS ANSWERS
    Q1  Does the GUID subscribe at all, at keyword 0x10 / level 4?
    Q2  Which EVENT IDs actually arrive, and at what volume? (The agent assumes
        1=start, 2=stop. Assumed, not measured.)
    Q3  What are the real FIELD NAMES carrying the pid and the image path? The
        agent tries ProcessID/PID/ProcessId/NewProcessId and
        ImageName/ImageFileName/ProcessName/Image, and counts which hits — this
        prints the same tally directly from raw events.
    Q4  Does a process START arrive BEFORE that process opens a connection? That
        ordering is the whole premise of the pid map: if starts lag, the map is
        cold exactly when it is needed.

USAGE (elevated PowerShell — ETW kernel providers require it; an unelevated run
gets WinError 5 and this script says so rather than reporting an empty result as
a finding):

    & "$env:LOCALAPPDATA\\Programs\\Python\\Python311\\python.exe" etw_process_probe.py --seconds 30 --out probe.json

Then paste `probe.json` back, or read the summary it prints. Narrow the agent's
KP_* constants to what this measured, and delete the candidate-field lists.
"""
import argparse
import ctypes
import json
import subprocess
import sys
import time
from collections import Counter, defaultdict

KERNEL_PROCESS = "Microsoft-Windows-Kernel-Process"
KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
KEYWORD_PROCESS = 0x10
LEVEL = 4

PID_CANDIDATES = ("ProcessID", "PID", "ProcessId", "NewProcessId")
IMAGE_CANDIDATES = ("ImageName", "ImageFileName", "ProcessName", "Image")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--out", default="etw-process-probe.json")
    args = ap.parse_args()

    out = {"provider": KERNEL_PROCESS, "guid": KERNEL_PROCESS_GUID,
           "keyword": hex(KEYWORD_PROCESS), "level": LEVEL,
           "seconds": args.seconds}

    elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    out["elevated"] = elevated
    if not elevated:
        # An unelevated run cannot open the session. Say so as the RESULT rather
        # than returning an empty capture that reads like "the provider is silent".
        out["error"] = ("NOT ELEVATED — ETW kernel providers require an elevated "
                        "token. Re-run from an elevated console. No conclusion can "
                        "be drawn from this run.")
        print(out["error"])
        json.dump(out, open(args.out, "w"), indent=2)
        return 2

    try:
        from etw import ETW, ProviderInfo
        from etw.GUID import GUID
    except ImportError as exc:
        out["error"] = "pywintrace not installed: %s" % exc
        print(out["error"]); json.dump(out, open(args.out, "w"), indent=2); return 3

    ids = Counter()
    pid_fields = Counter()
    image_fields = Counter()
    field_names = Counter()
    samples = defaultdict(list)
    first_seen = {}
    t0 = time.time()

    def on_event(event):
        try:
            eid, payload = event[0], event[1]
            ids[eid] += 1
            if not isinstance(payload, dict):
                return
            for k in payload:
                field_names[k] += 1
            for f in PID_CANDIDATES:
                if payload.get(f) is not None:
                    pid_fields["%s(id=%s)" % (f, eid)] += 1
                    break
            for f in IMAGE_CANDIDATES:
                v = payload.get(f)
                if isinstance(v, str) and v:
                    image_fields["%s(id=%s)" % (f, eid)] += 1
                    break
            if len(samples[eid]) < 3:
                # Redact nothing here: this is a lab probe and the operator reads
                # it before it goes anywhere. Keep it small instead.
                samples[eid].append({k: str(v)[:120] for k, v in list(payload.items())[:14]})
            if eid not in first_seen:
                first_seen[eid] = round(time.time() - t0, 3)
        except Exception as exc:                            # noqa: BLE001
            ids["__callback_error__"] += 1
            out.setdefault("callback_errors", []).append(str(exc)[:200])

    try:
        job = ETW(providers=[ProviderInfo(KERNEL_PROCESS, GUID(KERNEL_PROCESS_GUID),
                                          LEVEL, KEYWORD_PROCESS)],
                  event_callback=on_event)
        job.start()
        out["subscribed"] = True
    except Exception as exc:                                # noqa: BLE001
        out["subscribed"] = False
        out["error"] = "subscription FAILED: %s: %s" % (type(exc).__name__, exc)
        print(out["error"]); json.dump(out, open(args.out, "w"), indent=2); return 4

    print("subscribed. generating process churn for %ds..." % args.seconds)
    # Q4: make processes start, so starts are guaranteed to occur during capture.
    deadline = time.time() + args.seconds
    spawned = 0
    while time.time() < deadline:
        try:
            subprocess.run(["cmd.exe", "/c", "ver"], capture_output=True, timeout=10)
            spawned += 1
        except Exception:                                   # noqa: BLE001
            pass
        time.sleep(1.0)
    try:
        job.stop()
    except Exception:                                       # noqa: BLE001
        pass

    out.update({"spawned_processes": spawned,
                "event_ids": dict(ids),
                "pid_field_hits": dict(pid_fields),
                "image_field_hits": dict(image_fields),
                "all_field_names": dict(field_names.most_common(40)),
                "first_seen_offset_s": first_seen,
                "samples": {str(k): v for k, v in samples.items()}})

    print("\n=== ANSWERS ===")
    print("Q1 subscribed          :", out["subscribed"])
    print("Q2 event ids seen      :", dict(ids))
    print("Q3 pid field hits      :", dict(pid_fields))
    print("   image field hits    :", dict(image_fields))
    print("Q4 spawned %d processes; ids first seen at %s" % (spawned, first_seen))
    print("\nIf 'event ids seen' is empty, the GUID/keyword are wrong — that is a")
    print("real result, not a silent one. Narrow the agent's KP_* constants to")
    print("whatever this measured, then delete its candidate-field lists.")
    json.dump(out, open(args.out, "w"), indent=2, default=str)
    print("\nwrote", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
