"""drift_watch poller. Pure, no DB, no filesystem."""
import io, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drift_watch as W

_f=[]; _n=0
EXPECTED=14
def check(l,g,w):
    global _n; _n+=1; ok=g==w
    print("  %-62s %s"%(l,"PASS" if ok else "FAIL got=%r want=%r"%(g,w)))
    if not ok: _f.append(l)

def mk(payload):
    def opener(p, *a, **k): return io.StringIO(json.dumps(payload))
    return opener

OKP={"verdict":"ok","findings":[],"checked_at":"t"}
BAD={"verdict":"drifted","findings":["mode is 2"],"checked_at":"t"}
BAD2={"verdict":"drifted","findings":["anti-spoof missing"],"checked_at":"t"}

print("\n[a healthy fact file files nothing]")
filed,sig = W.poll_once(None, opener=mk(OKP), ticket_fn=lambda **k: None)
check("nothing filed", filed, 0); check("signature recorded", sig is not None, True)

print("\n[drift files exactly one ticket, then dedups]")
seen=[]
filed,sig = W.poll_once(None, opener=mk(BAD), ticket_fn=lambda **k: seen.append(k))
check("one ticket filed", filed, 1)
check("...with the finding in the body", "mode is 2" in seen[0]["body"], True)
check("...at HIGH", seen[0]["severity"], "HIGH")
check("...and says it is drift, not tamper detection",
      "not tamper" in seen[0]["body"], True)
filed2,sig2 = W.poll_once(sig, opener=mk(BAD), ticket_fn=lambda **k: seen.append(k))
check("identical finding does NOT re-ticket", filed2, 0)
check("a DIFFERENT finding does",
      W.poll_once(sig, opener=mk(BAD2), ticket_fn=lambda **k: None)[0], 1)

print("\n[an absent or unreadable fact file is not 'no drift']")
def boom(*a, **k): raise OSError("nope")
check("unreadable -> files nothing", W.poll_once("s", opener=boom)[0], 0)
check("...and KEEPS the prior signature", W.poll_once("s", opener=boom)[1], "s")
check("malformed json -> None", W.read_fact(opener=lambda *a,**k: io.StringIO("{")), None)
check("json without a verdict -> None",
      W.read_fact(opener=lambda *a,**k: io.StringIO('{"x":1}')), None)

print("\n[a ticket failure retries rather than losing the finding]")
def fails(**k): raise RuntimeError("db down")
filed3,sig3 = W.poll_once("prev", opener=mk(BAD), ticket_fn=fails)
check("nothing filed", filed3, 0)
check("signature NOT advanced, so it retries", sig3, "prev")

print()
if _n!=EXPECTED: print("SUITE DRIFT: ran %d expected %d"%(_n,EXPECTED)); sys.exit(1)
if _f: print("FAILED (%d)"%len(_f)); sys.exit(1)
print("ALL PASS (%d checks)"%_n)
