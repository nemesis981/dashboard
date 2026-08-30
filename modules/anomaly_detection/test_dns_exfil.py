"""DNS exfiltration scorer — pure tests. No DB, no eve.json.

The load-bearing cases are the SUPPRESSIONS. A tunnel detector that flags tunnels
is easy; one that does not flag a CDN is the entire product problem, because the
measured false-positive base rate is real: 90 legitimate A-queries carried a label
of >=25 characters in a single 40 MB sample from the build host, and the longest
label observed was 63 -- the protocol maximum.

Every suppression test below also proves its own DERIVATION, not just its answer:
the same input with the suppressing property removed must score as a tunnel.
Otherwise a case can pass because some earlier gate caught it, while the branch
under test is never reached -- which happened for real in this file's own canary
during development.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns_exfil as dx

_fail = []
_count = 0
EXPECTED_CHECKS = 41


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _tunnel(**over):
    base = {"queries": 400, "distinct_names": 396, "mean_entropy": 4.2,
            "mean_encoded_ratio": 0.95, "mean_max_label": 48,
            "rrtypes": ["TXT"], "observations": 2, "age_seconds": 600}
    base.update(over)
    return base


def test_entropy():
    print("\n[entropy must discriminate encoded payload from ordinary names]")
    check("empty string -> 0.0", dx.shannon_entropy(""), 0.0)
    check("single repeated char -> 0.0", dx.shannon_entropy("aaaaaa"), 0.0)
    check("random-looking beats repetitive",
          dx.shannon_entropy("a7f3k9x2") > dx.shannon_entropy("aaaaaaaa"), True)
    check("random-looking beats a real word",
          dx.shannon_entropy("q7z2m9k4x1") > dx.shannon_entropy("images"), True)


def test_split_name():
    print("\n[the subdomain IS the payload -- losing it is the bug this fixes]")
    check("payload labels preserved",
          dx.split_name("payload.tunnel.attacker.com", "attacker.com"),
          ("payload.tunnel", "attacker.com"))
    check("bare registrable domain -> EMPTY subdomain, not None",
          dx.split_name("attacker.com", "attacker.com"), ("attacker.com" and "", "attacker.com"))
    check("trailing dot tolerated",
          dx.split_name("a.b.attacker.com.", "attacker.com"), ("a.b", "attacker.com"))
    check("case normalised",
          dx.split_name("A.B.Attacker.COM", "attacker.com"), ("a.b", "attacker.com"))
    check("mismatched root -> (None, None), never a guess",
          dx.split_name("a.b.example.org", "attacker.com"), (None, None))
    check("empty fqdn -> (None, None)", dx.split_name("", "attacker.com"), (None, None))
    check("empty root -> (None, None)", dx.split_name("a.b.c", ""), (None, None))


def test_name_features():
    print("\n[per-name features]")
    f = dx.name_features("deadbeefcafe.payload")
    check("label count", f["label_count"], 2)
    check("max label length", f["max_label_len"], 12)
    check("total length excludes dots", f["total_len"], 19)
    check("encoded ratio is 1.0 for hex+alpha", f["encoded_ratio"], 1.0)
    empty = dx.name_features("")
    check("empty subdomain is a real observation, not a crash", empty["label_count"], 0)
    check("empty subdomain entropy 0.0", empty["entropy"], 0.0)
    check("empty subdomain encoded ratio 0.0", empty["encoded_ratio"], 0.0)


def test_thin_channel_declines():
    print("\n[FAIL SOFT: novelty is not evidence -- a thin channel gets NO opinion]")
    thin = _tunnel(queries=5, distinct_names=5)
    v = dx.score_channel(thin)
    check("few queries -> NO_OPINION, not suspicious", v["verdict"], dx.NO_OPINION)
    check("...and scores zero, not a small number", v["score"], 0.0)
    check("few distinct names -> NO_OPINION",
          dx.score_channel(_tunnel(distinct_names=2))["verdict"], dx.NO_OPINION)
    check("reason states which floor was missed", "too thin" in v["reason"], True)
    # DERIVATION: the same channel above the floors IS reported.
    check("CONTROL: identical channel above the floors scores suspicious",
          dx.score_channel(_tunnel())["verdict"], dx.SUSPICIOUS)


def test_established_channel_suppressed():
    print("\n[an established channel is ordinary traffic -- the core FP suppression]")
    est = _tunnel(observations=30, age_seconds=86400)
    v = dx.score_channel(est)
    check("established -> ORDINARY, not suspicious", v["verdict"], dx.ORDINARY)
    check("reason names the history", "established" in v["reason"], True)
    # DERIVATION: prove suppression is what saved it, not an earlier gate.
    check("CONTROL: same channel WITHOUT history is suspicious",
          dx.score_channel(_tunnel(observations=1, age_seconds=60))["verdict"],
          dx.SUSPICIOUS)
    check("age alone is not enough to establish",
          dx.score_channel(_tunnel(observations=1, age_seconds=86400))["verdict"],
          dx.SUSPICIOUS)
    check("observation count alone is not enough either",
          dx.score_channel(_tunnel(observations=30, age_seconds=60))["verdict"],
          dx.SUSPICIOUS)


def test_cdn_shape_is_not_a_tunnel():
    print("\n[the measured false positive: long high-entropy labels from a CDN]")
    cdn = dx.score_channel(dx._canary_cdn())
    check("established CDN -> not suspicious", cdn["verdict"] != dx.SUSPICIOUS, True)
    # A CDN re-queries a SMALL set of names. That ratio is the discriminator.
    reused = _tunnel(distinct_names=20, queries=400, observations=1, age_seconds=60,
                     rrtypes=["A"], mean_entropy=3.0, mean_encoded_ratio=0.5,
                     mean_max_label=10)
    check("heavy volume with REUSED names does not score as a tunnel",
          dx.score_channel(reused)["verdict"], dx.ORDINARY)
    check("CONTROL: the same volume with UNIQUE names does",
          dx.score_channel(_tunnel(queries=400, distinct_names=398))["verdict"],
          dx.SUSPICIOUS)


def test_long_labels_are_weak_alone():
    print("\n[long labels corroborate; they must never carry a finding alone]")
    only_long = {"queries": 100, "distinct_names": 20, "mean_entropy": 2.0,
                 "mean_encoded_ratio": 0.3, "mean_max_label": 60,
                 "rrtypes": ["A"], "observations": 1, "age_seconds": 60}
    v = dx.score_channel(only_long)
    check("long labels alone -> ORDINARY", v["verdict"], dx.ORDINARY)
    check("...and score stays below the floor", v["score"] < dx.SCORE_FLOOR, True)


def test_carrier_rrtypes_contribute():
    print("\n[TXT/NULL/etc are a signal -- and their ABSENCE proves nothing]")
    with_txt = dx.score_channel(_tunnel(rrtypes=["TXT"]))
    without = dx.score_channel(_tunnel(rrtypes=["A"]))
    check("carrier rrtype raises the score", with_txt["score"] > without["score"], True)
    check("carrier type is named in the signals",
          with_txt["signals"].get("carrier_rrtypes"), ["TXT"])
    check("a tunnel over plain A queries is STILL detected",
          without["verdict"], dx.SUSPICIOUS)


def test_malformed_input_declines():
    print("\n[a failed derivation must not return a legal-looking answer]")
    check("None -> NO_OPINION", dx.score_channel(None)["verdict"], dx.NO_OPINION)
    check("string -> NO_OPINION", dx.score_channel("nonsense")["verdict"], dx.NO_OPINION)
    check("empty dict -> NO_OPINION", dx.score_channel({})["verdict"], dx.NO_OPINION)


def test_selftest():
    print("\n[the instrument proves it can produce every verdict it claims]")
    ok, detail = dx.selftest()
    check("selftest passes", ok, True)
    check("selftest counts its canaries", "canaries passed" in detail, True)


if __name__ == "__main__":
    print("anomaly_detection -- DNS exfiltration scorer")
    test_entropy()
    test_split_name()
    test_name_features()
    test_thin_channel_declines()
    test_established_channel_suppressed()
    test_cdn_shape_is_not_a_tunnel()
    test_long_labels_are_weak_alone()
    test_carrier_rrtypes_contribute()
    test_malformed_input_declines()
    test_selftest()
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
