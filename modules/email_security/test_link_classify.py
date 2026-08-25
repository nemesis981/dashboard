"""Stage 4 step 2 -- link population analysis, and PROOF it never fetches.

THE SAFETY PROPERTY IS THE POINT OF THIS SUITE, not a side check. link_classify
exists so a real mailbox can be characterised without firing tracking pixels,
burning one-time tokens, or consuming magic-links. If it ever gains a network
call the output looks IDENTICAL -- same dicts, same counts -- while the
consequences are irreversible and land on the mailbox owner's real accounts.

So the property is proven TWICE, by two independent instruments:
  STATIC  -- walk the module's AST for any networking import (§1).
  RUNTIME -- blow up socket.socket and run the whole API against it (§2).
Either alone is a single point of failure: the AST scan cannot see a lazily
imported client reached through a string, and the socket block cannot see code
that never runs during the test. Together they are hard to defeat by accident.

NO NETWORK, NO MAILBOX, NO CREDENTIALS. Every URL below is fabricated.
"""
import ast
import os
import socket
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import link_classify as lc                                      # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


_NET_MODULES = {
    "socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx",
    "aiohttp", "ftplib", "telnetlib", "smtplib", "imaplib", "poplib",
    "asyncio", "selectors", "webbrowser", "xmlrpc", "subprocess",
}
# urllib.parse is pure string manipulation and is the ONLY urllib member
# permitted -- named explicitly so the allowance cannot silently widen to
# urllib.request, which is a real HTTP client.
_ALLOWED = {("urllib", "parse")}


def _network_imports(path):
    """Every networking import in one file. Empty list == none."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in _NET_MODULES:
                    found.append("import %s (line %d)" % (a.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root not in _NET_MODULES:
                continue
            parts = tuple((node.module or "").split("."))
            if parts in _ALLOWED or (len(parts) == 1 and
                                     all((parts[0], a.name) in _ALLOWED
                                         for a in node.names)):
                continue
            found.append("from %s import ... (line %d)"
                         % (node.module, node.lineno))
    return found


print("-- 1. STATIC: no networking imports in link_classify.py --")
_target = os.path.join(_HERE, "link_classify.py")
found = _network_imports(_target)
check("link_classify.py imports nothing that can reach the network",
      found == [], found)

# CONTROL: the scanner must be able to FAIL, or the pass above proves nothing.
import tempfile                                                 # noqa: E402
_probe = os.path.join(tempfile.mkdtemp(), "probe.py")
open(_probe, "w").write("import requests\nfrom urllib.request import urlopen\n")
check("CONTROL: the scanner DETECTS a networking import when one exists",
      len(_network_imports(_probe)) == 2, _network_imports(_probe))
open(_probe, "w").write("from urllib.parse import urlsplit\n")
check("CONTROL: ...and does NOT flag urllib.parse (pure string work)",
      _network_imports(_probe) == [], _network_imports(_probe))

print("\n-- 2. RUNTIME: the whole API runs with sockets disabled --")
_real_socket = socket.socket


def _explode(*a, **k):
    raise AssertionError("link_classify attempted to open a socket")


URLS = [
    "https://example.com/article/how-to-bake-bread",
    "https://example.com/unsubscribe?u=abc123&email=x%40example.com",
    "https://cdn.example.net/assets/logo.png",
    "https://example.org/r/aG9sZDEyMzQ1Njc4OQ",
    "http://198.51.100.7/login?token=deadbeefcafe1234",
    "https://user:pw@example.com:8443/confirm",
    "not a url at all",
    "https://example.com/docs/getting-started-guide",
]

socket.socket = _explode
try:
    prof = lc.profile(URLS)
    facts_all = [lc.classify_url(u) for u in URLS]
    risks_all = [lc.side_effect_risk(f) for f in facts_all]
    check("profile()/classify_url()/side_effect_risk() ran with sockets dead",
          True)
except AssertionError as exc:
    check("profile()/classify_url()/side_effect_risk() ran with sockets dead",
          False, str(exc))
finally:
    socket.socket = _real_socket

# CONTROL: prove the socket trap actually fires, or §2 is vacuous.
socket.socket = _explode
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _trap_works = False
except AssertionError:
    _trap_works = True
finally:
    socket.socket = _real_socket
check("CONTROL: the socket trap DOES fire when something opens one", _trap_works)

print("\n-- 3. Structural facts are read correctly --")
f = lc.classify_url("https://example.com/unsubscribe?u=abc123&email=x%40example.com")
check("action path detected", f["action_path"] == "unsubscribe", f["action_path"])
check("stateful params detected", f["stateful_params"] == ["email", "u"],
      f["stateful_params"])
check("tld read", f["tld"] == "com", f["tld"])

f2 = lc.classify_url("http://198.51.100.7/login?token=deadbeefcafe1234")
check("IP host detected", f2["is_ip_host"] is True)
check("...and no TLD invented for it", f2["tld"] is None, f2["tld"])

f3 = lc.classify_url("https://user:pw@example.com:8443/confirm")
check("userinfo detected", f3["has_userinfo"] is True)
check("non-default port detected", f3["has_port"] is True)

f4 = lc.classify_url("https://cdn.example.net/assets/logo.png")
check("static extension detected", f4["static_ext"] == "png", f4["static_ext"])

print("\n-- 4. Opaque segments need MIXING, not just length --")
check("a long human slug is NOT opaque",
      lc.classify_url("https://example.com/docs/getting-started-guide")
      ["opaque_segments"] == 0)
check("a long mixed token IS opaque",
      lc.classify_url("https://example.org/r/aG9sZDEyMzQ1Njc4OQ")
      ["opaque_segments"] == 1)
check("...otherwise every slug would count and the distribution is meaningless",
      lc.classify_url("https://example.com/article/how-to-bake-bread")
      ["opaque_segments"] == 0)

print("\n-- 5. Risk is descriptive, and UNKNOWN is never 'low' --")
check("action path -> high",
      lc.side_effect_risk(lc.classify_url(
          "https://example.com/unsubscribe?u=1")) == "high")
check("stateful param -> high",
      lc.side_effect_risk(lc.classify_url(
          "https://example.com/x?token=abc")) == "high")
check("plain static asset -> low",
      lc.side_effect_risk(lc.classify_url(
          "https://cdn.example.net/assets/logo.png")) == "low")
bad = lc.classify_url("not a url at all")
check("unparseable/hostless URL is NOT rated low",
      lc.side_effect_risk(bad) != "low", lc.side_effect_risk(bad))

print("\n-- 6. profile(): explicit zeros, never an empty dict --")
empty = lc.profile([])
check("empty corpus returns a full structure", empty["n_urls"] == 0
      and empty["risk"] == {"low": 0, "medium": 0, "high": 0}, empty)
check("...so 'no links' is distinguishable from 'never ran'",
      "risk" in empty and "tlds" in empty)
check("counts every url", prof["n_urls"] == len(URLS), prof["n_urls"])
check("finds the unsubscribe", prof["with_action_path"] >= 1)
check("finds the IP host", prof["ip_hosts"] == 1, prof["ip_hosts"])
check("finds the userinfo host", prof["userinfo_hosts"] == 1)
check("counts unique hosts", prof["hosts_unique"] >= 4, prof["hosts_unique"])

print("\n-- 7. MUTATION: prove §1 would catch a real regression --")
_mut = os.path.join(tempfile.mkdtemp(), "link_classify_mutant.py")
src = open(_target, encoding="utf-8").read().replace(
    "import re\n", "import re\nimport requests  # injected\n", 1)
open(_mut, "w").write(src)
check("MUTANT (a requests import added) is DETECTED -> §1 is a real check",
      len(_network_imports(_mut)) == 1, _network_imports(_mut))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
