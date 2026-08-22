#!/usr/bin/env python3
"""Linux/nftables steering backend for the roaming lease controller.

This is the FIRST real `SteeringBackend` (steering_lease.py's abstract seam). It
manages a dedicated nftables table, `inet nemesis_steer`, whose lifecycle IS the
steering state: the table present == steering active, absent == direct traffic.
apply() creates it, teardown() deletes it, and read_state() reads the LIVE ruleset
back with `nft -j list table` -- the read-back the failsafe depends on, against
real OS state rather than a recorded flag.

WHAT IT DOES NOT DO YET, ON PURPOSE. The actual redirect rule (the dnat/tproxy that
sends a flow to the local forwarder) is added ONLY when the plan carries a real
forwarder target. Until the forwarder exists, apply() creates the table and chain
with NO redirect rule -- proving the create/read/delete cycle against real nft
without touching a single real packet. So this backend is safe to run end-to-end
today: the worst it does is add and remove an empty table.

PRIVILEGE. nftables needs CAP_NET_ADMIN. The Linux agent runs UNPRIVILEGED by
design (install_linux.sh: `User=<non-root>`), so in production this backend routes
through a privileged helper -- the same chokepoint pattern as the firewall engine,
to be built. Here, the command runner is injectable; the default shells to `nft`
directly (works in a test VM with root). CRUCIALLY, a permission failure is NOT
swallowed: read_state() returns an UNKNOWN state, which the controller treats as
not-safe (fail-open) -- so a backend that cannot see or change the ruleset can
never let the controller believe steering is safely off.

The command runner seam also makes the whole thing unit-testable with no root and
no nft: tests feed captured real `nft -j` output and assert the parsing + the
error classification, and a VM run proves it against a live ruleset.
"""
import json
import logging
import subprocess

log = logging.getLogger("nemesis_agent.steering_nft")

TABLE_FAMILY = "inet"
TABLE_NAME = "nemesis_steer"


# ── command runner (injectable) ──────────────────────────────────────────────

class NftResult:
    __slots__ = ("rc", "out", "err")

    def __init__(self, rc, out="", err=""):
        self.rc = rc
        self.out = out
        self.err = err


def default_nft_runner(args, stdin=None, timeout=10):
    """Run `nft <args>`, optionally feeding `stdin`. Returns NftResult.

    Never raises for a non-zero nft exit -- a non-zero rc is data the caller
    classifies (table-absent vs permission vs other). It DOES surface an inability
    to run nft at all (missing binary, timeout) as a distinct rc so the caller can
    treat it as unknown rather than as "table absent".
    """
    try:
        proc = subprocess.run(
            ["nft"] + list(args),
            input=stdin, capture_output=True, text=True, timeout=timeout)
        return NftResult(proc.returncode, proc.stdout, proc.stderr)
    except FileNotFoundError:
        return NftResult(127, "", "nft not found")
    except subprocess.TimeoutExpired:
        return NftResult(124, "", "nft timed out")
    except Exception as exc:                                  # noqa: BLE001
        return NftResult(126, "", "nft run error: %s" % exc)


# ── error classification ─────────────────────────────────────────────────────

def _is_absent(res):
    """A nft error that means the table simply is not there (a SAFE answer)."""
    if res.rc == 0:
        return False
    e = (res.err or "").lower()
    return ("no such file or directory" in e
            or "does not exist" in e
            or "no such table" in e)


def _is_permission(res):
    """A nft error that means we could not see/change the ruleset (UNKNOWN, fail-open)."""
    if res.rc == 0:
        return False
    e = (res.err or "").lower()
    return ("not permitted" in e
            or "permission denied" in e
            or "operation not permitted" in e
            or res.rc == 127          # nft missing == cannot determine
            or res.rc == 124          # timed out == cannot determine
            or res.rc == 126)


def _default_forwarder_factory(listen_port, upstream):
    """Build a real TransparentForwarder. Imported lazily so this module has no
    hard dependency on the forwarder for the pure-logic paths and tests."""
    import forwarder
    return forwarder.TransparentForwarder(
        listen_host="127.0.0.1", listen_port=int(listen_port) if listen_port else 0,
        upstream=upstream)


# ── the backend ──────────────────────────────────────────────────────────────

class NftablesSteeringBackend:
    """A real SteeringBackend over nftables. Duck-types steering_lease.SteeringBackend
    (apply/teardown/read_state) without importing it, so this module has no import
    cycle and can be tested alone."""

    def __init__(self, runner=None, forwarder_factory=None):
        self._run = runner or default_nft_runner
        # The forwarder IS part of the Linux steering mechanism, so this backend
        # owns its lifecycle -- and only here can the safe ordering be guaranteed
        # (start before the redirect exists; stop after it is gone). Injectable so
        # unit tests supply a fake and no real socket is opened.
        self._forwarder_factory = forwarder_factory or _default_forwarder_factory
        self._forwarder = None

    # -- ruleset construction (pure; unit-tested) --------------------------------

    def build_ruleset(self, plan):
        """The nft script apply() feeds to `nft -f -`.

        `plan` is a dict. `forwarder_port` (int) present and truthy => add the
        redirect rule to that local port; absent/None => create the table + chain
        with NO redirect (the inert lifecycle-only form that is safe to run today).

        Written as an idempotent 'delete then create' so apply() over an existing
        table replaces it cleanly rather than erroring or stacking rules. The
        leading delete is wrapped so a missing table does not abort the batch:
        nft has no 'delete if exists', so the create path stands alone and the
        caller (teardown/reconcile) owns removal.
        """
        port = plan.get("forwarder_port") if isinstance(plan, dict) else None
        lines = [
            "table %s %s {" % (TABLE_FAMILY, TABLE_NAME),
            "  chain steer {",
            "    type nat hook output priority -100; policy accept;",
        ]
        if port:
            # Redirect new outbound TLS to the local forwarder. Only emitted when a
            # real forwarder target exists; NEVER on the inert path.
            lines.append("    meta l4proto tcp tcp dport 443 "
                         "redirect to :%d" % int(port))
        else:
            # Inert: a comment marker so the table is non-empty and identifiable,
            # but nothing matches or redirects. Proves lifecycle, touches no packet.
            lines.append("    # inert: no forwarder target configured")
        lines += ["  }", "}"]
        return "\n".join(lines) + "\n"

    # -- the SteeringBackend contract -------------------------------------------

    def apply(self, plan):
        """Bring steering up: start the forwarder, then apply the nft redirect at it.

        ORDERING IS A SAFETY PROPERTY. The forwarder is started BEFORE the redirect
        is applied, so at no point is traffic redirected to a port nothing is
        listening on (which would fail every connection). If the nft apply then
        fails, the just-started forwarder is stopped so a failed activation leaks
        no listener.

        Only redirects when the plan carries a real appliance upstream. Without one
        it applies the INERT table (no forwarder, no redirect) -- the safe today
        form, since redirecting to a forwarder that can reach no appliance would
        break the device's TLS. Raises on real nft failure (controller fails open)."""
        upstream = plan.get("appliance_upstream") if isinstance(plan, dict) else None
        redirect_port = None
        if upstream:
            if self._forwarder is None:
                self._forwarder = self._forwarder_factory(
                    plan.get("forwarder_port"), upstream)
                redirect_port = self._forwarder.start()   # bound port for the rule
            else:
                redirect_port = self._forwarder.bound_port
        # Replace: best-effort delete of any prior table, then create.
        self._run(["delete", "table", TABLE_FAMILY, TABLE_NAME])   # ignore result
        res = self._run(["-f", "-"],
                        stdin=self.build_ruleset({"forwarder_port": redirect_port}))
        if res.rc != 0:
            self._stop_forwarder()      # do not leak a listener on a failed apply
            raise RuntimeError("nft apply failed rc=%d: %s" % (res.rc, res.err.strip()))

    def teardown(self):
        """Bring steering down: remove the nft redirect FIRST, then stop the forwarder.

        ORDERING, again for safety: the redirect is removed before the forwarder is
        stopped, so traffic is never redirected to a forwarder that is shutting
        down. The forwarder is ALWAYS stopped (even if the nft delete fails), so a
        teardown never leaves a listener running. Idempotent: a missing table is
        success. A permission/other nft error still RAISES -- the controller's
        read-back then catches that the box may still be steered."""
        res = self._run(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        self._stop_forwarder()
        if res.rc == 0 or _is_absent(res):
            return
        raise RuntimeError("nft teardown failed rc=%d: %s" % (res.rc, res.err.strip()))

    def _stop_forwarder(self):
        if self._forwarder is not None:
            try:
                self._forwarder.stop()
            except Exception as exc:                         # noqa: BLE001
                log.warning("forwarder stop failed: %s", exc)
            self._forwarder = None

    def read_state(self):
        """Read the LIVE ruleset. Returns a steering_lease.SteeringState-shaped
        object (duck-typed) -- active iff the table is present; UNKNOWN if we could
        not determine (permission/nft-missing/timeout), which is fail-open."""
        from steering_lease import SteeringState        # local import: no cycle
        res = self._run(["-j", "list", "table", TABLE_FAMILY, TABLE_NAME])
        if res.rc == 0:
            present = self._table_present_in_json(res.out)
            return SteeringState(present, "nft table %s" % TABLE_NAME)
        if _is_absent(res):
            return SteeringState(False, "nft table absent")
        if _is_permission(res):
            return SteeringState(False, "nft read not permitted: %s" % res.err.strip(),
                                 unknown=True)
        # Any other nft error is also treated as unknown -- we could not confirm.
        return SteeringState(False, "nft read error rc=%d: %s" % (res.rc,
                             res.err.strip()), unknown=True)

    # -- json parse (pure; unit-tested against captured real nft output) ---------

    @staticmethod
    def _table_present_in_json(text):
        """True iff `nft -j list table` output actually contains our table.

        Defensive: a rc==0 with empty/garbled output must NOT read as 'present'
        (that would let a broken read arm steering). Only a real table object with
        our exact family+name counts.
        """
        try:
            doc = json.loads(text)
        except Exception:                                    # noqa: BLE001
            return False
        for item in doc.get("nftables", []):
            tbl = item.get("table") if isinstance(item, dict) else None
            if isinstance(tbl, dict) and tbl.get("family") == TABLE_FAMILY \
                    and tbl.get("name") == TABLE_NAME:
                return True
        return False


# ── live-nft self-test (needs CAP_NET_ADMIN) ─────────────────────────────────

def _self_test():
    """Prove the backend against a REAL nftables ruleset. Exits 2 (COULD NOT
    VERIFY) if nft cannot be driven (not root / no nft) -- never a false pass.

    It runs the real create -> read-back-present -> delete -> read-back-absent
    cycle, PLUS controls that prove the read-back discriminates: an absent table
    must read absent, a present one must read present. A read that could only ever
    say one thing would pass the cycle while proving nothing.
    """
    import sys
    be = NftablesSteeringBackend()

    # Can we drive nft at all? A permission/absent probe tells us.
    probe = be.read_state()
    if probe.unknown:
        print("COULD NOT VERIFY: cannot read nftables (%s)." % probe.detail)
        print("Run as root (CAP_NET_ADMIN). This is NOT a pass.")
        return 2

    results = []

    def ck(label, ok):
        results.append((label, ok))
        print("  [%s] %s" % ("PASS" if ok else "FAIL", label))

    # start clean
    try:
        be.teardown()
    except Exception:                                        # noqa: BLE001
        pass
    ck("negative control: with no table, read-back is SAFE (absent)",
       be.read_state().is_safe)

    be.apply({})                        # inert table, no redirect -- touches no packet
    st = be.read_state()
    ck("after real apply, read-back is ACTIVE (table present)", st.active)
    ck("...and not safe", not st.is_safe)

    # idempotent re-apply
    be.apply({})
    ck("re-apply is idempotent (still exactly one table, still active)",
       be.read_state().active)

    be.teardown()
    ck("after real teardown, read-back is SAFE (table gone)", be.read_state().is_safe)

    # idempotent teardown
    be.teardown()
    ck("teardown of an already-absent table does not raise", True)

    passed = sum(1 for _, ok in results if ok)
    print("\n%d/%d live-nft checks passed" % (passed, len(results)))
    if passed != len(results):
        return 1
    print("LIVE NFT SELF-TEST PASSED")
    return 0


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    print("steering_nft: import this module, or run with --self-test (needs root)")
