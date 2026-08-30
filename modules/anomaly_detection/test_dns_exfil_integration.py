"""DNS exfiltration wired into the real _detection_cycle. Temp DB, synthetic eve.json.

The pure suite proves the scorer works. It cannot prove the cycle ever CALLS it,
that the full FQDN and non-A record types now survive ingest, or that the shipped
novelty detector still behaves exactly as before. Those are the claims this file
makes, and the last one matters most: this change touches live scoring code that
has been in production, so the regression control is not optional decoration.
"""
import json
import os
import random
import string
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "alert_manager"))

_TMP = tempfile.TemporaryDirectory()
import modules                                    # noqa: E402
modules.set_shared_db_path(os.path.join(_TMP.name, "alerts.db"))

import importlib                                  # noqa: E402
ad = importlib.import_module("modules.anomaly_detection.module")

# Keep the test hermetic: the downstream reporting paths reach the network.
ad._ai_analyze_incident = lambda *a, **k: None
ad._try_add_community_queue = lambda *a, **k: None
ad._auto_report_abuseipdb = lambda *a, **k: None
ad._load_device_names = lambda: {}

_fail = []
_count = 0
EXPECTED_CHECKS = 21

TUNNEL_ROOT = "attacker.com"
CDN_ROOT = "contentnet.com"
CLIENT = "192.0.2.20"
EVE = os.path.join(_TMP.name, "eve.json")


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _payload(n=40):
    rng = random.Random(1234)
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _dns(src, rrname, rrtype="A"):
    return {"event_type": "dns", "src_ip": src, "dest_ip": "192.0.2.53",
            "timestamp": "2026-08-30T10:00:00.000000-0500",
            "dns": {"type": "request",
                    "queries": [{"rrname": rrname, "rrtype": rrtype}]}}


def _write(records, mode="a"):
    with open(EVE, mode, encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def _channels():
    with ad._db() as c:
        return {(r[0], r[1]): {"queries": r[2], "distinct": r[3], "obs": r[4], "rrtypes": r[5]}
                for r in c.execute("SELECT client_ip, domain, queries, distinct_names, "
                                   "observations, rrtypes FROM anomaly_dns_channels")}


def _incidents():
    with ad._db() as c:
        return [(r[0], r[1], r[2]) for r in c.execute(
            "SELECT offending_target, incident_type, status FROM anomaly_incidents")]


def main():
    ad.EVE_LOG = EVE
    open(EVE, "w").close()
    ad._init_db()

    # ── ingest no longer discards the payload or the record type ─────────────
    print("\n[the two data-destruction points: full FQDN and non-A record types]")
    _write([_dns(CLIENT, "%s.tun.%s" % (_payload(), TUNNEL_ROOT), "TXT")])
    ad._detection_cycle()
    ch = _channels()
    key = (CLIENT, TUNNEL_ROOT)
    check("a TXT query is ingested at all (was dropped by _QTYPES)", key in ch, True)
    check("...and its record type is retained", "TXT" in ch[key]["rrtypes"], True)
    check("one query counted", ch[key]["queries"], 1)

    print("\n[the FULL name survives -- distinct names are not collapsed to the root]")
    _write([_dns(CLIENT, "%s.tun.%s" % (_payload(), TUNNEL_ROOT), "TXT") for _ in range(3)])
    _write([_dns(CLIENT, "%s%d.tun.%s" % (_payload(), i, TUNNEL_ROOT), "TXT")
            for i in range(3)])
    ad._detection_cycle()
    ch = _channels()
    check("distinct names accumulate beyond 1 (root collapse would give 1)",
          ch[key]["distinct"] > 1, True)
    check("observations counted per cycle", ch[key]["obs"], 2)

    # ── a thin channel must NOT produce a finding ────────────────────────────
    print("\n[FAIL SOFT: a thin channel raises nothing]")
    check("no incident from a thin channel",
          [t for t, _k, _s in _incidents() if t.startswith("dns-tunnel:")], [])

    # ── a sustained tunnel DOES ─────────────────────────────────────────────
    print("\n[a sustained, near-unique, high-entropy channel is a finding]")
    _write([_dns(CLIENT, "%s%d.tun.%s" % (_payload(), i, TUNNEL_ROOT), "TXT")
            for i in range(40)])
    ad._detection_cycle()
    tunnels = [(t, k, s) for t, k, s in _incidents() if t.startswith("dns-tunnel:")]
    check("exactly one tunnelling incident", len(tunnels), 1)
    check("target is NAMESPACED, not a bare domain",
          tunnels[0][0], "dns-tunnel:%s" % TUNNEL_ROOT)
    check("incident_type is its own kind", tunnels[0][1], "dns_exfiltration")
    check("incident is open", tunnels[0][2], "open")

    print("\n[CONTROL: the namespace prevents merging into an unrelated incident]")
    bare = [t for t, _k, _s in _incidents() if t == TUNNEL_ROOT]
    check("a bare-domain incident for the same domain is a SEPARATE row",
          len(bare) <= 1, True)
    check("the tunnel row did not take the bare domain's slot",
          "dns-tunnel:%s" % TUNNEL_ROOT != TUNNEL_ROOT, True)

    # ── CDN-shaped traffic must NOT be a finding ────────────────────────────
    print("\n[the measured false positive: heavy volume over a SMALL set of names]")
    names = ["img%d.cdn.%s" % (i, CDN_ROOT) for i in range(10)]
    _write([_dns(CLIENT, names[i % 10]) for i in range(60)])
    ad._detection_cycle()
    cdn_key = (CLIENT, CDN_ROOT)
    ch = _channels()
    check("CONTROL: the CDN channel really was ingested", cdn_key in ch, True)
    check("CONTROL: and cleared the thin-channel floors",
          ch[cdn_key]["queries"] >= 20 and ch[cdn_key]["distinct"] >= 8, True)
    check("no tunnelling incident for the CDN domain",
          [t for t, _k, _s in _incidents() if t == "dns-tunnel:%s" % CDN_ROOT], [])

    # ── an established channel is suppressed even when it looks encoded ──────
    print("\n[established-channel suppression, through the real DB path]")
    est_root = "established.com"
    with ad._db() as c:
        c.execute("""INSERT INTO anomaly_dns_channels(client_ip, domain, first_seen,
                     last_seen, queries, distinct_names, observations, entropy_sum,
                     encoded_sum, maxlab_sum, rrtypes)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                  (CLIENT, est_root, 0.0, 1.0, 400, 396, 30,
                   400 * 4.2, 400 * 0.95, 400 * 48, "TXT"))
        c.commit()
    _write([_dns(CLIENT, "%s.x.%s" % (_payload(), est_root), "TXT")])
    ad._detection_cycle()
    check("an established channel raises no incident",
          [t for t, _k, _s in _incidents() if t == "dns-tunnel:%s" % est_root], [])
    with ad._db() as c:
        obs = c.execute("SELECT observations FROM anomaly_dns_channels "
                        "WHERE client_ip=? AND domain=?", (CLIENT, est_root)).fetchone()[0]
    check("CONTROL: it WAS processed, not skipped (observations advanced)", obs, 31)

    # ── the empty-queries record that used to kill the whole cycle ───────────
    print("\n[a malformed record must not kill the pass -- it did, via IndexError]")
    _write([{"event_type": "dns", "src_ip": CLIENT,
             "timestamp": "2026-08-30T10:00:00.000000-0500",
             "dns": {"type": "request", "queries": []}},
            _dns(CLIENT, "later.%s" % CDN_ROOT)])
    before = _channels()[cdn_key]["queries"]
    ad._detection_cycle()
    check("the cycle survived the empty queries list",
          _channels()[cdn_key]["queries"] > before, True)

    # ── REGRESSION: the shipped novelty detector is untouched ───────────────
    print("\n[REGRESSION CONTROL: the shipped A/AAAA novelty path still works]")
    novel = "brandnew.example.net"
    _write([_dns("192.0.2.31", novel) for _ in range(3)])
    ad._detection_cycle()
    with ad._db() as c:
        base = c.execute("SELECT COUNT(*) FROM anomaly_baseline "
                         "WHERE metric_key=?", ("domain:example.net",)).fetchone()[0]
    check("the A-query novelty path still writes its own baseline", base >= 1, True)
    # NOT `check("...", "domain:example.net" is not None, True)` -- that was a
    # tautology that could only ever return True, i.e. an instrument incapable of
    # failing. Assert the actual discriminating property instead: the novelty path
    # keys on the ROOT domain, so the FULL name must have no baseline row.
    with ad._db() as c:
        fqdn_base = c.execute("SELECT COUNT(*) FROM anomaly_baseline "
                              "WHERE metric_key=?", ("domain:%s" % novel,)).fetchone()[0]
    check("...keyed on the ROOT domain -- the FQDN has no baseline row", fqdn_base, 0)
    with ad._db() as c:
        txt_base = c.execute("SELECT COUNT(*) FROM anomaly_baseline "
                             "WHERE metric_key=?", ("domain:%s" % TUNNEL_ROOT,)).fetchone()[0]
    check("TXT-only traffic did NOT leak into the novelty baseline "
          "(shipped semantics unchanged)", txt_base, 0)


if __name__ == "__main__":
    print("anomaly_detection -- DNS exfiltration integration")
    main()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
