"""Tests for listening_ports -- the port-exposure collector's PURE core.

Pins the three pure pieces: the exposure classifier, the normaliser, and the stable
dedup key. The psutil enumeration itself is a thin impure wrapper (exercised against a
real host, not here) -- but its SAFETY contract (never raises) is asserted.

⛔ THE CLASSIFIER IS THE LOAD-BEARING PART, and string comparison is the wrong tool.
`ip == "127.0.0.1"` misclassifies 127.0.1.1 -- a real, commonly-used loopback address
(Debian/Ubuntu put the system hostname there) -- as externally exposed, manufacturing a
false "your service is reachable from the network" alert. The whole 127.0.0.0/8 block
is loopback, which is why the implementation uses ipaddress and why the case below
exists.

⚠ ATTRIBUTION IS ASSERTED AS AN EXPLICIT STATE, NOT AN EMPTY STRING.
Measured non-root on a real host: 9 of 26 TCP listeners had a pid attributed. Blank
process names are therefore the NORMAL case, not an error case, and "could not
attribute" must stay distinguishable from "no process" all the way to the UI.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import listening_ports as L  # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 52


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def test_classify_exposure():
    print("\n[exposure: objective property of the bind address, not a judgment]")
    check("0.0.0.0 is all-interfaces", L.classify_exposure("0.0.0.0"), L.EXPOSURE_ALL)
    check(":: is all-interfaces", L.classify_exposure("::"), L.EXPOSURE_ALL)
    check("127.0.0.1 is loopback", L.classify_exposure("127.0.0.1"), L.EXPOSURE_LOOPBACK)
    check("::1 is loopback", L.classify_exposure("::1"), L.EXPOSURE_LOOPBACK)
    # The case a string comparison gets wrong -- see module docstring.
    check("127.0.1.1 is loopback (whole /8, not just .0.1)",
          L.classify_exposure("127.0.1.1"), L.EXPOSURE_LOOPBACK)
    check("127.255.255.254 is loopback (top of the /8)",
          L.classify_exposure("127.255.255.254"), L.EXPOSURE_LOOPBACK)
    check("a real LAN address is specific",
          L.classify_exposure("192.0.2.10"), L.EXPOSURE_SPECIFIC)
    check("a real v6 address is specific",
          L.classify_exposure("2001:db8::1"), L.EXPOSURE_SPECIFIC)
    print("  -- multicast is a group JOIN, not an exposed service --")
    check("224.0.0.251 (mDNS) is multicast",
          L.classify_exposure("224.0.0.251"), L.EXPOSURE_MULTICAST)
    check("239.255.255.250 (WS-Discovery) is multicast",
          L.classify_exposure("239.255.255.250"), L.EXPOSURE_MULTICAST)
    check("ff02::c is multicast", L.classify_exposure("ff02::c"), L.EXPOSURE_MULTICAST)
    check("multicast is NOT reported as specific",
          L.classify_exposure("224.0.0.251") != L.EXPOSURE_SPECIFIC, True)
    print("  -- an unparseable address must NOT get a plausible default --")
    check("garbage is unknown", L.classify_exposure("not-an-ip"), L.EXPOSURE_UNKNOWN)
    check("empty is unknown", L.classify_exposure(""), L.EXPOSURE_UNKNOWN)
    check("None is unknown (no crash)", L.classify_exposure(None), L.EXPOSURE_UNKNOWN)
    check("whitespace is tolerated", L.classify_exposure("  127.0.0.1 "),
          L.EXPOSURE_LOOPBACK)


def test_structured_port():
    print("\n[normaliser: stable shape, explicit attribution]")
    ev = L.structured_port({"proto": "TCP", "address": "0.0.0.0", "port": 80,
                            "pid": 1234, "process": "nginx"})
    check("proto lowercased", ev["proto"], "tcp")
    check("address preserved", ev["address"], "0.0.0.0")
    check("port stays an int", ev["port"], 80)
    check("exposure derived", ev["exposure"], L.EXPOSURE_ALL)
    check("pid preserved", ev["pid"], 1234)
    check("process preserved", ev["process"], "nginx")
    check("attribution ok when named", ev["attribution"], L.ATTR_OK)

    print("  -- the MAJORITY case: socket visible, owner withheld --")
    un = L.structured_port({"proto": "tcp", "address": "0.0.0.0", "port": 53,
                            "pid": None, "process": None})
    check("process is empty string, never None", un["process"], "")
    check("attribution says unattributed, NOT ok", un["attribution"], L.ATTR_DENIED)
    check("unattributed still classifies exposure", un["exposure"], L.EXPOSURE_ALL)
    check("pid None survives as None", un["pid"], None)

    print("  -- missing text fields never become None --")
    empty = L.structured_port({})
    check("proto empty string", empty["proto"], "")
    check("address empty string", empty["address"], "")
    check("port None (absent is not 0)", empty["port"], None)
    check("exposure unknown, not a guess", empty["exposure"], L.EXPOSURE_UNKNOWN)
    check("attribution unattributed", empty["attribution"], L.ATTR_DENIED)


def test_stable_key():
    print("\n[dedup key: the SOCKET, not the process instance]")
    a = L.structured_port({"proto": "tcp", "address": "0.0.0.0", "port": 80,
                           "pid": 100, "process": "nginx"})
    # Same socket, service restarted: new pid, different resolved name.
    b = L.structured_port({"proto": "tcp", "address": "0.0.0.0", "port": 80,
                           "pid": 999, "process": ""})
    check("key ignores pid and process (restart is not a new listener)",
          L.stable_key(a), L.stable_key(b))
    check("key shape", L.stable_key(a), "listen:tcp:0.0.0.0:80")

    diff_port = L.structured_port({"proto": "tcp", "address": "0.0.0.0", "port": 443})
    diff_addr = L.structured_port({"proto": "tcp", "address": "127.0.0.1", "port": 80})
    diff_prot = L.structured_port({"proto": "udp", "address": "0.0.0.0", "port": 80})
    check("different port -> different key",
          L.stable_key(a) != L.stable_key(diff_port), True)
    check("different address -> different key (loopback is not the same socket)",
          L.stable_key(a) != L.stable_key(diff_addr), True)
    check("different proto -> different key (tcp/80 is not udp/80)",
          L.stable_key(a) != L.stable_key(diff_prot), True)
    check("key never empty even with nothing known",
          L.stable_key(L.structured_port({})), "listen:?:?:?")
    check("port 0 is not treated as absent",
          L.stable_key(L.structured_port({"proto": "tcp", "address": "::", "port": 0})),
          "listen:tcp::::0")


def test_dedupe():
    print("\n[dedupe: one row per socket, attributed owner wins]")
    # Process names are PLACEHOLDERS (svc-alpha/svc-beta); the shapes are real, taken
    # from a live host -- four membership rows for one multicast socket, and one UDP
    # port owned by two processes where only one was attributable. The real names are
    # ordinary desktop software and do not belong in a public repo (Rule 8).
    mk = lambda pid, proc: L.structured_port(
        {"proto": "udp", "address": "224.0.0.251", "port": 5353,
         "pid": pid, "process": proc})
    # The measured multicast case: one socket, four identical membership rows.
    four = [mk(4001, "svc-alpha") for _ in range(4)]
    check("four identical membership rows collapse to one", len(L._dedupe(four)), 1)
    check("the survivor keeps its owner", L._dedupe(four)[0]["process"], "svc-alpha")

    # The measured shared-port case: unattributed row first, real owner second.
    shared = [mk(None, None), mk(4002, "svc-beta")]
    out = L._dedupe(shared)
    check("shared port collapses to one row", len(out), 1)
    check("the ATTRIBUTED owner wins, not merely the first seen",
          out[0]["process"], "svc-beta")
    # Order must not decide the outcome -- the same input reversed must agree.
    check("and wins regardless of input order",
          L._dedupe(list(reversed(shared)))[0]["process"], "svc-beta")

    # Distinct sockets must NOT be collapsed -- the control proving dedupe is not
    # blanket-yes (a dedupe that merges everything would pass every check above).
    distinct = [L.structured_port({"proto": "tcp", "address": "0.0.0.0", "port": 80}),
                L.structured_port({"proto": "tcp", "address": "0.0.0.0", "port": 443}),
                L.structured_port({"proto": "udp", "address": "0.0.0.0", "port": 80})]
    check("three distinct sockets survive as three", len(L._dedupe(distinct)), 3)
    check("empty input stays empty", L._dedupe([]), [])


def test_list_is_safe_and_real():
    print("\n[enumeration: never raises, and genuinely discriminates]")
    got = L.list_listening_ports()
    check("returns a list", isinstance(got, list), True)
    ok_shape = all(isinstance(e, dict) and "exposure" in e and "attribution" in e
                   for e in got)
    check("every entry is a structured event", ok_shape, True)
    protos = {e["proto"] for e in got}
    check("protos are only tcp/udp", protos <= {"tcp", "udp"}, True)
    exposures = {e["exposure"] for e in got}
    check("exposures are all known classes",
          exposures <= {L.EXPOSURE_ALL, L.EXPOSURE_LOOPBACK, L.EXPOSURE_SPECIFIC,
                        L.EXPOSURE_MULTICAST, L.EXPOSURE_UNKNOWN}, True)
    check("keys are unique per socket", len({L.stable_key(e) for e in got}), len(got))
    # Liveness control: a host with zero listening sockets is implausible here, and an
    # empty list would make every assertion above vacuously true.
    check("the instrument actually saw sockets (not a vacuous pass)", len(got) > 0, True)


if __name__ == "__main__":
    print("=" * 74)
    print("listening_ports — port-exposure collector (pure core)")
    print("=" * 74)
    test_classify_exposure()
    test_structured_port()
    test_stable_key()
    test_dedupe()
    test_list_is_safe_and_real()
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
