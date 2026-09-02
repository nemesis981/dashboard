#!/usr/bin/env python3
"""threat_feeds — safety properties, format validation, and registry completeness.

Run: python3 modules/threat_feeds/test_threat_feeds.py

The three properties this module's whole design rests on, each with a control
that separates it from an adjacent almost-right behaviour:

  1. It CANNOT touch a list it did not add. The Pi-hole this was built against
     already had five hand-curated lists on it.
  2. It CANNOT write anything but /api/lists — non-collision with
     vpn_dns_guard's /api/config writes is structural, and this asserts it
     against the real source rather than trusting the docstring.
  3. A CIDR feed is REFUSED. This is the check whose absence put an
     architecturally-impossible feed into the build scope in the first place.

Pi-hole is faked at the client boundary — no network, no live Pi-hole. The fake
records every call so the tests can assert what WOULD have been sent, which is
the only way to prove property 2 without a real server.
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

EXPECTED_CHECKS = 50
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


class FakePihole:
    """Records calls instead of making them. Seeded with operator-owned lists."""

    def __init__(self, seed):
        self.lists = list(seed)
        self.added = []
        self.removed = []

    def get_lists(self):
        return [dict(r) for r in self.lists]

    def add_list(self, address, comment, enabled=True):
        self.added.append({"address": address, "comment": comment})
        self.lists.append({"address": address, "comment": comment,
                           "type": "block", "enabled": enabled})

    def remove_list(self, address):
        self.removed.append(address)
        self.lists = [r for r in self.lists if r.get("address") != address]


#: What the real Pi-hole looked like when this module was built — five lists
#: added by hand, none of them ours. Using the real shape matters: property 1 is
#: about THESE rows surviving.
OPERATOR_LISTS = [
    {"address": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
     "comment": "", "type": "block", "enabled": True},
    {"address": "https://blocklistproject.github.io/Lists/malware.txt",
     "comment": None, "type": "block", "enabled": True},
    {"address": "https://urlhaus.abuse.ch/downloads/hostfile/",
     "comment": "added by hand 2026-07", "type": "block", "enabled": True},
    {"address": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
     "comment": "nemesis-threat-feed is mentioned here but this is MINE",
     "type": "block", "enabled": True},
    {"address": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts",
     "comment": "", "type": "block", "enabled": True},
]


def main():
    import importlib
    F = importlib.import_module("modules.threat_feeds.feeds")
    M = importlib.import_module("modules.threat_feeds.module")
    import roles as R

    # ── 1. ownership ────────────────────────────────────────────────────────
    print("ownership: a tag this module wrote, and nothing else")
    check("its own tag is recognised", F.is_ours("nemesis-threat-feed:urlhaus"), True)
    check("CONTROL an empty comment is not ours", F.is_ours(""), False)
    check("CONTROL a None comment is not ours", F.is_ours(None), False)
    check("CONTROL an operator comment is not ours",
          F.is_ours("added by hand 2026-07"), False)
    # The nastiest case, and it is in the seed above on purpose: a hand-written
    # comment that MENTIONS the tag. A substring search would claim it.
    check("THE PROPERTY: a comment merely MENTIONING the tag is NOT ours",
          F.is_ours("nemesis-threat-feed is mentioned here but this is MINE"), False)
    check("the feed key round-trips out of a tag",
          F.feed_key_from_comment(F.tag_for("urlhaus")), "urlhaus")
    check("CONTROL no key is extracted from a foreign comment",
          F.feed_key_from_comment("someone else's list"), None)

    # ── 2. format validation ────────────────────────────────────────────────
    print("\nformat validation: the check that would have caught Spamhaus")
    SPAMHAUS = ("; Spamhaus DROP List 2026/09/02\n"
                "1.10.16.0/20 ; SBL256894\n"
                "1.19.0.0/16 ; SBL434604\n"
                "1.32.128.0/18 ; SBL286275\n")
    HOSTS = ("# abuse.ch URLhaus Host file\n"
             "0.0.0.0 evil.example\n"
             "0.0.0.0 malware.test\n"
             "0.0.0.0 phish.example\n")
    BARE = "evil.example\nmalware.test\n"
    try:
        F.validate_feed_body(SPAMHAUS, url="drop.txt")
        spam_ok = True
    except F.FeedFormatError as e:
        spam_ok = False
        spam_msg = str(e)
    check("THE PROPERTY: a CIDR feed is REFUSED", spam_ok, False)
    check("  ...and the refusal names the real reason", "CIDR" in spam_msg, True)
    check("  ...and points at where that data belongs",
          "spamhaus-drop-firewall-ingest" in spam_msg, True)
    check("CONTROL a hosts-format feed is ACCEPTED",
          F.validate_feed_body(HOSTS, url="urlhaus")["domains"], 3)
    check("CONTROL a bare domain list is ACCEPTED",
          F.validate_feed_body(BARE, url="bare")["domains"], 2)
    # Fail-closed cases: "cannot determine" must never mean "fine".
    for label, body in (("empty body", ""),
                        ("comments only", "# nothing here\n; still nothing\n")):
        try:
            F.validate_feed_body(body, url=label)
            refused = False
        except F.FeedFormatError:
            refused = True
        check("fails closed on %s" % label, refused, True)
    check("CONTROL classify counts CIDR vs domain separately",
          F.classify_lines(SPAMHAUS)[:2], (0, 3))

    # ── 3. Spamhaus is excluded ON PURPOSE, not merely absent ───────────────
    print("\nSpamhaus: recorded as rejected, not silently missing")
    check("it is NOT in the catalogue", "spamhaus_drop" in F.CATALOG, False)
    check("THE PROPERTY: it IS in EXCLUDED with a reason",
          "spamhaus_drop" in F.EXCLUDED, True)
    check("  ...and the reason explains the category mismatch",
          "CIDR" in F.EXCLUDED["spamhaus_drop"]["reason"], True)
    check("CONTROL the catalogue is not empty (exclusion is not vacuous)",
          len(F.CATALOG) >= 2, True)

    # ── 4. writes are confined to /api/lists ────────────────────────────────
    print("\nnon-collision with vpn_dns_guard is STRUCTURAL")
    # ⚠ READ EXECUTABLE CODE, NOT THE SOURCE TEXT. The first version of this
    # check grepped the raw file for "/api/config" and FAILED -- because the
    # module's docstring EXPLAINS that it never writes /api/config. A grep for a
    # term matches the prose saying the term is excluded, which is a standing
    # trap in this codebase and caught this suite on its first run.
    #
    # So: parse, drop docstrings, and look only at string literals that real code
    # actually evaluates.
    import ast
    client_src = open(os.path.join(_HERE, "pihole_lists.py")).read()
    tree = ast.parse(client_src)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and \
               isinstance(body[0].value, ast.Constant) and \
               isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    code_strings = [n.value for n in ast.walk(tree)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)
                    and id(n) not in docstrings]
    api_paths = sorted({p for s in code_strings for p in re.findall(r"/api/[a-z]+", s)})
    check("CONTROL executable string literals were extracted", len(code_strings) > 5, True)
    check("CONTROL the docstring DOES mention /api/config (so the filter matters)",
          "/api/config" in client_src, True)
    check("THE PROPERTY: no executable code references /api/config",
          any("/api/config" in s for s in code_strings), False)
    check("  ...while /api/lists IS used in code (check is not vacuous)",
          any("/api/lists" in s for s in code_strings), True)
    check("every /api path in executable code is on the allow-list",
          [p for p in api_paths if p not in ("/api/auth", "/api/lists")], [])
    from modules.threat_feeds.pihole_lists import ALLOWED_PATHS
    check("the declared allow-list is exactly auth+lists",
          sorted(ALLOWED_PATHS), ["/api/auth", "/api/lists"])

    # ── 5. behaviour against a seeded Pi-hole ───────────────────────────────
    print("\nbehaviour: it adds its own and cannot remove the operator's")
    mod = M.Module({"name": "threat_feeds"})
    fake = FakePihole(OPERATOR_LISTS)
    mod._client = lambda: fake
    mod.validate = lambda key, config=None: {"domains": 3, "cidrs": 0, "considered": 3}

    ours, theirs = mod._partition()
    check("CONTROL starts with 0 managed", len(ours), 0)
    check("CONTROL sees all 5 operator lists", len(theirs), 5)

    # `threatfox` is NOT in the operator seed -> the clean add path.
    res = mod.apply_feeds(["threatfox"])
    check("applying a feed reports ok", res[0]["ok"], True)
    check("exactly one list was added", len(fake.added), 1)
    check("it was tagged as ours", F.is_ours(fake.added[0]["comment"]), True)

    ours, theirs = mod._partition()
    check("now 1 managed", len(ours), 1)
    check("operator lists still 5", len(theirs), 5)

    # Re-applying must not duplicate.
    res2 = mod.apply_feeds(["threatfox"])
    check("re-applying is a no-op", res2[0].get("skipped"), "already applied")
    check("CONTROL still only one add call", len(fake.added), 1)

    # ⛔ THE COLLISION CASE, and it is the LIVE state of the real Pi-hole:
    # `urlhaus` is a default catalogue feed AND the operator already has that
    # exact URL, untagged. It must be left alone -- neither duplicated nor
    # adopted by writing our tag onto their row.
    res_c = mod.apply_feeds(["urlhaus"])
    check("THE PROPERTY: a URL the operator already has is SKIPPED",
          "already present" in (res_c[0].get("skipped") or ""), True)
    check("  ...and explicitly NOT adopted",
          "not adopted" in (res_c[0].get("skipped") or ""), True)
    check("CONTROL no second add call was made", len(fake.added), 1)
    check("CONTROL it did not become managed", len(mod._partition()[0]), 1)

    # An excluded feed is refused even if asked for by name.
    res3 = mod.apply_feeds(["spamhaus_drop"])
    check("THE PROPERTY: an excluded feed is refused by name", res3[0]["ok"], False)
    check("CONTROL nothing was added for it", len(fake.added), 1)

    out = mod.remove_all()
    check("THE PROPERTY: removal removed only OUR list", fake.removed,
          ["https://threatfox.abuse.ch/downloads/hostfile/"])
    check("  ...verified clean by read-back", out["verified_clean"], True)
    check("THE PROPERTY: all 5 operator lists survived",
          len(mod._partition()[1]), 5)
    check("  ...and the module says so explicitly",
          out["untouched_unchanged"], True)
    # The seeded operator list whose URL is IDENTICAL to a catalogue feed is the
    # sharpest case: removal must key on the TAG, not the address.
    survivors = [r["address"] for r in fake.lists]
    check("THE PROPERTY: the operator's own urlhaus list (same URL, untagged) survived",
          "https://urlhaus.abuse.ch/downloads/hostfile/" in survivors, True)

    # ── 6. registry completeness ────────────────────────────────────────────
    print("\nregistry completeness (a missing entry 404s and reads as 'no route')")
    routes = mod.get_routes()
    declared = {"module_threat_feeds_%s" % fn.__name__ for _, fn, _ in routes}
    check("CONTROL routes are declared at all", len(routes), 3)
    missing = sorted(e for e in declared if e not in R.ROUTE_MINIMUMS)
    check("every declared route has a ROUTE_MINIMUMS entry", missing, [])
    stale = sorted(e for e in R.ROUTE_MINIMUMS
                   if e.startswith("module_threat_feeds_") and e not in declared)
    check("no ROUTE_MINIMUMS entry names a route we do not declare", stale, [])
    check("both writes are admin-gated",
          sorted({R.ROUTE_MINIMUMS["module_threat_feeds_api_apply"][0],
                  R.ROUTE_MINIMUMS["module_threat_feeds_api_remove_all"][0]}), ["admin"])
    check("the write routes are POST-only",
          sorted(o["methods"][0] for r, f, o in routes if "api_status" not in f.__name__),
          ["POST", "POST"])

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
