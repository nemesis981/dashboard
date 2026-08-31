#!/usr/bin/env python3
"""`_gw_collect`: a failed READ is named, an absent thing is answered.

Run: python3 alert_manager/test_fwd_gw_collect.py

TWO OPPOSITE MISTAKES, AND THIS FILE EXISTS BECAUSE I MADE THE SECOND ONE
WHILE FIXING THE FIRST.

  1. THE ORIGINAL BUG. Every failed read fell back to a value that happens to
     BE the pass condition when disabling -- unreadable drop-in -> "", so
     "not persisted"; unreadable env -> {}, so "not configured"; failed nft ->
     empty stdout, so "SNAT absent". Three read failures, three confident
     "successfully disabled" verdicts about a box nobody had measured.

  2. THE OVER-CORRECTION. Treating every non-zero nft exit as unmeasured looks
     like the careful fix and is not: nft exits NON-ZERO for a chain that does
     not exist, which is the NORMAL state whenever the gateway is disabled. It
     would have made every correct disable fail verification and roll back.
     Caught before shipping, by asking what nft actually returns rather than
     assuming rc!=0 meant failure.

So the rule is not "check the return code" and not "ignore it" -- it is that
"there is no such chain" and "I could not ask" are DIFFERENT ANSWERS, and only
the second is unmeasured. The original code ignored rc entirely, which was
right for nft and wrong for sysctl.

No root, no live nft: subprocess.run is scripted so each case is exact.
"""
import sys
import types

sys.path.insert(0, "/opt/nemesis/alert_manager")
sys.path.insert(0, "/opt/nemesis")

import subprocess                                             # noqa: E402
import nemesis_fwd as F                                       # noqa: E402

EXPECTED_CHECKS = 12
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 40:
        g, w = g[:37] + "...", w[:37] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def _r(rc, out="", err=""):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def collect_with(nft=None, sysctl=None, env_path="/nonexistent/nemesis.env"):
    """Run the real _gw_collect against a scripted environment."""
    real_run, real_env = subprocess.run, F.NEMESIS_ENV_PATH

    def fake(cmd, **kw):
        if cmd[0] == F.NFT_BIN:
            if isinstance(nft, Exception):
                raise nft
            return nft
        if cmd[0] == F.SYSCTL_BIN:
            if isinstance(sysctl, Exception):
                raise sysctl
            return sysctl if sysctl is not None else _r(0, "0\n")
        return real_run(cmd, **kw)

    subprocess.run, F.NEMESIS_ENV_PATH = fake, env_path
    try:
        return F._gw_collect()
    finally:
        subprocess.run, F.NEMESIS_ENV_PATH = real_run, real_env


def snat_unmeasured(st):
    return [u for u in st["unmeasured"] if "SNAT" in u]


def main():
    print("\n1. THE OVER-CORRECTION GUARD: an absent chain is an ANSWER")
    # If this ever regresses, every correct `disable` fails verification and
    # rolls back. It is the most important check in the file.
    st = collect_with(nft=_r(1, "", "Error: No such file or directory\n"))
    check("absent chain -> snat False", st["snat"], False)
    check("absent chain -> NOT unmeasured", snat_unmeasured(st), [])

    print("\n2. present chains are read correctly")
    st = collect_with(nft=_r(0, "chain gateway_snat { masquerade }"))
    check("masquerade present -> True", st["snat"], True)
    check("...and measured", snat_unmeasured(st), [])
    st = collect_with(nft=_r(0, "chain gateway_snat { }"))
    check("chain present without masquerade -> False", st["snat"], False)
    check("...and still measured", snat_unmeasured(st), [])

    print("\n3. THE ORIGINAL BUG: a real failure IS unmeasured")
    st = collect_with(nft=_r(1, "", "Operation not permitted (you must be root)\n"))
    check("permission denied -> unmeasured", len(snat_unmeasured(st)), 1)
    check("...and names the cause",
          "not permitted" in snat_unmeasured(st)[0], True)
    st = collect_with(nft=FileNotFoundError("no nft"))
    check("missing nft binary -> unmeasured", len(snat_unmeasured(st)), 1)

    print("\n4. sysctl: rc IS checked here (unlike nft, and for a reason)")
    # There is no "absent" answer for `sysctl -n net.ipv4.ip_forward`; a
    # non-zero exit means the question was not answered.
    st = collect_with(nft=_r(0, ""), sysctl=_r(1, "", "unknown key"))
    check("sysctl failure -> unmeasured",
          any("live forwarding" in u for u in st["unmeasured"]), True)
    st = collect_with(nft=_r(0, ""), sysctl=FileNotFoundError("no sysctl"))
    check("missing sysctl binary is caught, not raised out",
          any("live forwarding" in u for u in st["unmeasured"]), True)

    print("\n5. CONTROL: a fully healthy collect names NOTHING")
    # Without this the checks above could pass while everything is always
    # unmeasured, which would break the feature outright.
    st = collect_with(nft=_r(0, "chain gateway_snat { masquerade }"),
                      sysctl=_r(0, "1\n"))
    check("healthy collect -> unmeasured is empty", st["unmeasured"], [])

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
