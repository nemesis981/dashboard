#!/usr/bin/env python3
"""Local-port connection watch — visibility layer, NOT the access-control gate.

The properties worth testing are mostly about what it must NOT do:

  * it must not treat "on my subnet" as "mine" -- that is the assumption an
    intruder on the LAN benefits from;
  * it must not report the appliance's own loopback traffic, or the real signal
    drowns in nginx->dashboard proxy connections;
  * it must not report the same source every scan interval forever;
  * a scan that COULD NOT RUN must raise, never return "nothing found" -- those
    read identically to a caller and only one of them is reassuring.

Run: python3 alert_manager/test_local_port_watch.py
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.environ.get("NEMESIS_ROOT", "/opt/nemesis"),
                                "alert_manager"))

import local_port_watch as W                                       # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def raises(fn, exc=W.LocalPortWatchError):
    try:
        fn()
    except exc:
        return True
    except Exception:                                              # noqa: BLE001
        return False
    return False


def fresh_db(devices=(), agents=()):
    path = os.path.join(tempfile.mkdtemp(prefix="lpw-"), "t.db")
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, ip TEXT)")
    c.execute("CREATE TABLE agent_devices (device_id TEXT, ip_address TEXT)")
    c.executemany("INSERT INTO devices (ip) VALUES (?)", [(d,) for d in devices])
    c.executemany("INSERT INTO agent_devices (device_id, ip_address) VALUES (?,?)",
                  [("d%d" % i, a) for i, a in enumerate(agents)])
    c.commit()
    return c


def conns(*triples):
    """(remote_ip, local_port, status) tuples, as psutil would yield them."""
    return list(triples)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== BOTH inventories are consulted, not just one ==")

c = fresh_db(devices=["192.0.2.10"], agents=["198.51.100.20"])
known = W.known_addresses(c)
check("a scanned device is known", "192.0.2.10" in known)
check("an enrolled agent is known", "198.51.100.20" in known)
check("something in NEITHER is unknown", "203.0.113.99" not in known)
check("  CONTROL: the known set is not simply everything", len(known) == 2, str(known))

# A missing table must RAISE. Silently skipping it would turn every device it
# contained into a false "unknown" -- a flood of findings that reads as an attack.
c2 = sqlite3.connect(":memory:")
c2.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, ip TEXT)")
check("a missing inventory table RAISES (never a silently smaller known set)",
      raises(lambda: W.known_addresses(c2)))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== 'On my subnet' is NOT 'mine' ==")

c = fresh_db(devices=["192.0.2.10"])
known = W.known_addresses(c)
check("a KNOWN private address classifies known",
      W.classify("192.0.2.10", known) == "known")
check("an UNKNOWN private address on the same subnet is UNKNOWN",
      W.classify("192.0.2.11", known) == "unknown",
      "treating LAN membership as identity is what an intruder relies on")
check("a public address is unknown too", W.classify("203.0.113.5", known) == "unknown")


# ═══════════════════════════════════════════════════════════════════════════
print("\n== LOOPBACK is excluded, or the real signal drowns ==")

c = fresh_db(devices=["192.0.2.10"])
r = W.scan(c, _probe=conns(("127.0.0.1", 443, "ESTABLISHED"),
                           ("::1", 443, "ESTABLISHED"),
                           ("192.0.2.10", 443, "ESTABLISHED")))
check("loopback v4 is not reported", not any(f["ip"] == "127.0.0.1" for f in r["unknown"]))
check("loopback v6 is not reported", not any(f["ip"] == "::1" for f in r["unknown"]))
check("  ...and the known device is counted, not flagged",
      r["known"] == 1 and r["unknown"] == [], repr(r))

# Only watched ports, and only established connections.
W.reset_suppression()
r = W.scan(c, _probe=conns(("203.0.113.7", 22, "ESTABLISHED"),
                           ("203.0.113.8", 443, "SYN_SENT"),
                           ("203.0.113.9", 443, "ESTABLISHED")))
got = sorted(f["ip"] for f in r["unknown"])
check("an unwatched port (22) is ignored", "203.0.113.7" not in got)
check("a non-established connection is ignored", "203.0.113.8" not in got)
check("an established connection on a watched port IS reported",
      got == ["203.0.113.9"], repr(got))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== REPEAT SUPPRESSION: one finding, not one per scan ==")

W.reset_suppression()
probe = conns(("203.0.113.50", 443, "ESTABLISHED"))
r1 = W.scan(c, now=1000, _probe=probe)
r2 = W.scan(c, now=1010, _probe=probe)
r3 = W.scan(c, now=1000 + W.REPEAT_SUPPRESS_S + 1, _probe=probe)
check("first sighting is reported", len(r1["unknown"]) == 1)
check("an immediate re-scan is SUPPRESSED, not re-reported",
      r2["unknown"] == [] and r2["suppressed"] == 1, repr(r2))
check("after the window it reports again (not suppressed forever)",
      len(r3["unknown"]) == 1, repr(r3))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== A SCAN THAT COULD NOT RUN MUST RAISE, NOT RETURN 'NOTHING' ==")

def _boom(**_kw):
    raise W.LocalPortWatchError("simulated: no privilege to enumerate sockets")

_real = W.current_connections
W.current_connections = _boom
try:
    check("an unusable connection table RAISES", raises(lambda: W.scan(c)))
finally:
    W.current_connections = _real
check("  CONTROL: restored, and a real scan returns a result dict",
      isinstance(W.scan(c, _probe=[]), dict))

r = W.scan(c, _probe=[])
check("'nothing found' is an EMPTY LIST, distinguishable from a failure",
      r["unknown"] == [] and r["checked"] == 0, repr(r))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE FINDING SAYS WHAT IT DOES AND DOESN'T PROVE ==")

W.reset_suppression()
r = W.scan(c, _probe=conns(("203.0.113.77", 80, "ESTABLISHED")))
f = r["unknown"][0]
check("the finding names the source and port",
      f["ip"] == "203.0.113.77" and f["port"] == 80)
check("  ...and says explicitly it is visibility, not a block",
      "VISIBILITY signal, not a block" in f["detail"])
check("  ...and warns the inventory is incomplete by nature",
      "incomplete by nature" in f["detail"],
      "an operator reading this in a ticket must not over-read it")

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
