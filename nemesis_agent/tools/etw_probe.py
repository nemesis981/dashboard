"""Track C step 4 — ETW capability probe. RUN ON WINDOWS, NOT PART OF THE AGENT.

Purpose: answer, with measurements rather than assumptions, the four questions the
collector cannot be written confidently without.

    Q1  Can an ETW real-time session be created at the privilege level the agent
        normally runs at? (And: what IS that level here?)
    Q2  Does `Microsoft-Windows-Kernel-Network` give per-connection byte counts,
        or only per-send/recv events that must be summed?
    Q3  Does `Microsoft-Windows-DNS-Client` yield a usable QueryName + resolved
        address list (event 3008), so `resolved_name` can be populated at all?
    Q4  What is the event rate under ordinary desktop load? (Sizes the step-5
        buffer.)

Usage, on the probe VM:

    py -3 -m pip install pywintrace
    py -3 etw_probe.py --seconds 60 --out probe-report.json

Then generate traffic during the window (open a browser, run a few `curl`s).

DESIGN NOTE — why this reports "not observed" rather than guessing.
Every question above is answered from events that actually arrived. A field that
never appeared is reported as NOT OBSERVED, which is different from "absent from
the provider" — 60 seconds of light traffic is not proof a field does not exist.
The report says which of the two it is entitled to claim. Getting this wrong is
how an unverified assumption gets laundered into a measurement.
"""
import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict

KERNEL_NETWORK = "Microsoft-Windows-Kernel-Network"
DNS_CLIENT = "Microsoft-Windows-DNS-Client"

#: Field names we care about, per question. Matched case-insensitively against
#: whatever the provider actually emits, because ETW field naming varies by
#: provider version and guessing the exact casing is not a measurement.
BYTES_HINTS = ("size", "bytes", "numbytes", "datalength")
ADDR_HINTS = ("daddr", "saddr", "address", "destaddr", "sourceaddr")
PORT_HINTS = ("dport", "sport", "port")
PID_HINTS = ("pid", "processid")
NAME_HINTS = ("queryname", "name")
RESULT_HINTS = ("queryresults", "results", "addresses")


def _priv_report():
    """Q1 — what privilege are we actually running at? Measured, not assumed."""
    out = {"is_admin": None, "username": None, "in_perf_log_users": None, "error": None}
    try:
        import ctypes
        out["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as e:                                   # noqa: BLE001
        out["error"] = "IsUserAnAdmin failed: %s" % e
    try:
        out["username"] = os.environ.get("USERNAME")
        import subprocess
        r = subprocess.run(["whoami", "/groups"], capture_output=True, text=True, timeout=20)
        blob = (r.stdout or "").lower()
        # The group that grants ETW session creation without full admin.
        out["in_perf_log_users"] = "performance log users" in blob
    except Exception as e:                                   # noqa: BLE001
        out["error"] = (out["error"] or "") + " | whoami failed: %s" % e
    return out


def _match(keys, hints):
    lower = {k.lower(): k for k in keys}
    return sorted({lower[k] for k in lower if any(h in k for h in hints)})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--out", default="probe-report.json")
    args = ap.parse_args()

    report = {"probe_version": 1, "seconds": args.seconds,
              "privilege": _priv_report(),
              "session_created": False, "session_error": None,
              "providers": {}, "answers": {}}

    try:
        from etw import ETW, ProviderInfo          # pywintrace
        from etw.GUID import GUID
    except Exception as e:                                   # noqa: BLE001
        report["session_error"] = ("pywintrace not importable: %s — install with "
                                   "`py -3 -m pip install pywintrace`" % e)
        _write(report, args.out)
        return 2

    seen = defaultdict(Counter)          # provider -> field name -> count
    events = Counter()                   # provider -> event count
    task_ids = defaultdict(Counter)      # provider -> event id -> count
    samples = {}                         # provider -> one redacted sample
    # INSTRUMENT INTEGRITY. The first run of this probe reported "no events" while
    # swallowing every callback exception — so a signature mismatch and genuine
    # silence produced identical output. These three counters make them different
    # answers, which is the whole point.
    stats = {"callbacks": 0, "callback_errors": 0, "first_error": None,
             "first_raw_shape": None}

    def on_event(event):
        """pywintrace hands the callback (event_id:int, payload:dict).

        MEASURED, not guessed: the previous shape (header:dict, payload) produced
        422/422 AttributeErrors — which the hardened counters surfaced instead of
        reporting as silence. Provider attribution comes from the payload where
        available, and otherwise from the event id, because the callback does not
        carry a provider name of its own.
        """
        stats["callbacks"] += 1
        try:
            if stats["first_raw_shape"] is None:
                stats["first_raw_shape"] = "%s len=%s first=%s" % (
                    type(event).__name__,
                    len(event) if hasattr(event, "__len__") else "n/a",
                    type(event[0]).__name__ if hasattr(event, "__getitem__") else "n/a")
            eid, payload = event[0], event[1]
            if not isinstance(payload, dict):
                stats["callback_errors"] += 1
                return
            prov = str(payload.get("ProviderName") or payload.get("Provider") or "?")
            key = "%s#%s" % (prov, eid)
            events[prov] += 1
            task_ids[prov][str(eid)] += 1
            for k in payload:
                seen[prov][k] += 1
            if key not in samples:
                # Rule 8: field NAMES and value TYPES only — never values. The
                # probe VM is doing real browsing.
                samples[key] = {k: type(v).__name__ for k, v in payload.items()}
        except Exception as e:                               # noqa: BLE001
            stats["callback_errors"] += 1
            if stats["first_error"] is None:
                stats["first_error"] = "%s: %s" % (type(e).__name__, str(e)[:200])

    # Level 5 (verbose) and ALL keywords. A provider whose keyword mask is 0
    # emits NOTHING while the session still starts cleanly — which is one of the
    # two explanations for a zero-event run and must be eliminated before the
    # other (wrong GUID / wrong callback shape) can be blamed.
    ALL_KEYWORDS = 0xFFFFFFFFFFFFFFFF
    VERBOSE = 5
    try:
        providers = [ProviderInfo(KERNEL_NETWORK, GUID("{7DD42A49-5329-4832-8DFD-43D979153A88}"),
                                  VERBOSE, ALL_KEYWORDS),
                     ProviderInfo(DNS_CLIENT, GUID("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"),
                                  VERBOSE, ALL_KEYWORDS)]
        report["provider_args"] = "name+guid+level+any_keywords"
    except TypeError as e:
        # pywintrace's ProviderInfo signature differs across versions. Record which
        # form was used rather than silently falling back to a weaker one.
        report["provider_args"] = "name+guid only (level/keywords unsupported: %s)" % e
        providers = [ProviderInfo(KERNEL_NETWORK, GUID("{7DD42A49-5329-4832-8DFD-43D979153A88}")),
                     ProviderInfo(DNS_CLIENT, GUID("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"))]
    job = None
    try:
        job = ETW(providers=providers, event_callback=on_event)
        job.start()
        report["session_created"] = True
    except Exception as e:                                   # noqa: BLE001
        report["session_error"] = "%s: %s" % (type(e).__name__, e)
        _write(report, args.out)
        return 3

    print("ETW session running for %ds — generate traffic now "
          "(browse, curl a few hosts)..." % args.seconds)
    try:
        time.sleep(args.seconds)
    finally:
        try:
            job.stop()
        except Exception:                                    # noqa: BLE001
            pass

    # Report EVERY bucket that actually received events, not just the two names we
    # expected. The previous version reported only the expected keys and therefore
    # showed 0/0 while 10,869 events sat in an unnamed bucket — a report shaped by
    # what it assumed rather than by what arrived.
    for prov in sorted(set(list(events.keys()) + [KERNEL_NETWORK, DNS_CLIENT])):
        keys = list(seen.get(prov, {}).keys())
        report["providers"][prov] = {
            "events_seen": events.get(prov, 0),
            "event_ids": dict(task_ids.get(prov, {})),
            "field_names": sorted(keys),
            "sample_field_types_by_event": {k: v for k, v in samples.items()
                                            if k.startswith(prov + "#")},
            "byte_like_fields": _match(keys, BYTES_HINTS),
            "addr_like_fields": _match(keys, ADDR_HINTS),
            "port_like_fields": _match(keys, PORT_HINTS),
            "pid_like_fields": _match(keys, PID_HINTS),
            "name_like_fields": _match(keys, NAME_HINTS),
            "result_like_fields": _match(keys, RESULT_HINTS),
        }

    report["instrument"] = dict(stats)
    kn = report["providers"].get(KERNEL_NETWORK, {"events_seen": 0, "byte_like_fields": []})
    dns = report["providers"].get(DNS_CLIENT, {"events_seen": 0, "name_like_fields": [],
                                               "result_like_fields": []})
    # If attribution failed, the unnamed bucket holds everything — say so loudly
    # rather than reporting two zeroes.
    unnamed = report["providers"].get("?", {})
    if unnamed.get("events_seen"):
        report["answers_note"] = (
            "Provider attribution FAILED: %d events landed in the unnamed bucket. "
            "The per-provider verdicts below are therefore not measurements; read "
            "providers['?'] field_names and event_ids instead."
            % unnamed["events_seen"])

    def verdict(saw_any_events, found):
        if stats["callbacks"] and stats["callback_errors"] == stats["callbacks"]:
            return ("INSTRUMENT BROKEN — %d callbacks fired, ALL raised (%s). This is "
                    "not a measurement of the provider."
                    % (stats["callbacks"], stats["first_error"]))
        # THE HONEST DISTINCTION. No events at all means we measured nothing and
        # must say so; events but no field means the field is genuinely absent
        # from what this provider emitted.
        if not saw_any_events:
            return "NOT MEASURED — no events arrived from this provider"
        return "PRESENT: %s" % ", ".join(found) if found else "ABSENT in observed events"

    report["answers"] = {
        "Q1_privilege": ("session created OK as %s (admin=%s, perf_log_users=%s)"
                         % (report["privilege"].get("username"),
                            report["privilege"].get("is_admin"),
                            report["privilege"].get("in_perf_log_users"))
                         if report["session_created"] else
                         "SESSION FAILED: %s" % report["session_error"]),
        "Q2_bytes": verdict(kn["events_seen"], kn["byte_like_fields"]),
        "Q2_note": ("per-connection vs per-send cannot be decided from field names "
                    "alone — compare events_seen against the number of distinct "
                    "connections you generated; many events per connection means "
                    "summing is required"),
        "Q3_resolved_name": verdict(dns["events_seen"],
                                    dns["name_like_fields"] + dns["result_like_fields"]),
        "Q4_event_rate_per_sec": round((kn["events_seen"] + dns["events_seen"])
                                       / float(max(1, args.seconds)), 2),
    }
    _write(report, args.out)
    return 0


def _write(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report.get("answers") or report, indent=2))
    print("\nfull report -> %s" % path)


if __name__ == "__main__":
    sys.exit(main())
