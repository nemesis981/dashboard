#!/usr/bin/env python3
"""WebAuthn RP identity — per-install derivation, and the pin that protects it.

THE PROPERTY THAT MATTERS MOST is not that derivation works. It is that the RP ID
CANNOT SILENTLY CHANGE. WebAuthn binds credentials to it, the two-authenticator
floor means there is no appliance-side override, and the failure presents as an
ordinary signature mismatch -- so a silent change is an unrecoverable admin set
discovered at the worst possible moment.

Also proven: an IP literal is refused on every path in, because that refusal is
the entire reason the appliance's bare-IP server_name had to go.

Run: python3 core/test_rp_identity.py
"""
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")

_TMP = tempfile.mkdtemp(prefix="rpid-")
os.environ["NEMESIS_RP_ID_FILE"] = os.path.join(_TMP, "rp_id")
os.environ.pop("NEMESIS_RP_ID", None)

from core import rp_identity as R                                  # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def raises(fn, exc=R.RpIdentityError):
    try:
        fn()
    except exc:
        return True
    except Exception:                                              # noqa: BLE001
        return False
    return False


def reset():
    try:
        os.remove(R.RP_ID_FILE)
    except FileNotFoundError:
        pass


def status(dnsname, certs=None):
    d = {"Self": {"DNSName": dnsname}}
    if certs is not None:
        d["CertDomains"] = certs
    return json.dumps(d)


HOST = "appliance-alpha.tailnet-example.ts.net"


# ═══════════════════════════════════════════════════════════════════════════
print("\n== DERIVED PER INSTALL, from LIVE tailnet identity ==")

check("derives this host's MagicDNS name",
      R.derive_rp_id(status(HOST + ".", [HOST])) == HOST)
check("  a trailing dot is normalised away",
      R.derive_rp_id(status(HOST + ".", [HOST])) == HOST)
check("  case is normalised",
      R.derive_rp_id(status(HOST.upper() + ".", [HOST])) == HOST)
check("a DIFFERENT host derives a DIFFERENT RP ID (not a shared constant)",
      R.derive_rp_id(status("appliance-beta.tailnet-example.ts.net.",
                            ["appliance-beta.tailnet-example.ts.net"]))
      == "appliance-beta.tailnet-example.ts.net")

# The full hostname, NOT the tailnet suffix -- one credential must not work
# across every appliance on the tailnet.
check("uses the FULL hostname, not the tailnet suffix",
      R.derive_rp_id(status(HOST + ".", [HOST])) != "tailnet-example.ts.net")

check("a name outside CertDomains is REFUSED (it could not serve a secure context)",
      raises(lambda: R.derive_rp_id(status(HOST + ".", ["other.tailnet-example.ts.net"]))))
check("  ...but no CertDomains at all is tolerated (not yet enabled)",
      R.derive_rp_id(status(HOST + ".")) == HOST)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== AN IP CAN NEVER BE AN RP ID (the reason bare-IP server_name had to go) ==")

for bad, why in (
        ("192.168.4.69", "an IPv4 literal"),
        ("100.89.223.30", "a tailnet IPv4"),
        ("fd7a:115c:a1e0::b138:df1f", "an IPv6 literal"),
        ("localhost", "a single-label hostname"),
        ("https://appliance.tailnet-example.ts.net", "a URL rather than a domain"),
        ("appliance.tailnet-example.ts.net:443", "a host:port"),
        ("appliance.tailnet-example.ts.net/path", "a path"),
        ("", "an empty string"),
):
    check("refuses %s" % why, raises(lambda b=bad: R.derive_rp_id(status(b))))

# The env override must get EXACTLY the same scrutiny -- otherwise it becomes a
# way to smuggle in the very values derivation rejects.
reset()
os.environ["NEMESIS_RP_ID"] = "192.168.4.69"
check("the env override CANNOT smuggle in an IP either", raises(R.rp_id))
os.environ["NEMESIS_RP_ID"] = "appliance-env.tailnet-example.ts.net"
check("  CONTROL: a valid env override IS accepted",
      R.rp_id() == "appliance-env.tailnet-example.ts.net")
os.environ.pop("NEMESIS_RP_ID", None)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE PIN: silent change is impossible ==")

reset()
check("nothing is pinned on a fresh appliance", R.pinned_rp_id() is None)
check("pinning returns the value", R.pin_rp_id(HOST) == HOST)
check("  ...and it reads back", R.pinned_rp_id() == HOST)
check("re-pinning the SAME value is a no-op, not an error", R.pin_rp_id(HOST) == HOST)

check("pinning a DIFFERENT value RAISES", raises(lambda: R.pin_rp_id("other.tailnet-example.ts.net")))
check("  ...and the original pin is untouched", R.pinned_rp_id() == HOST)

# The load-bearing one: the pin WINS over live derivation. A renamed host must not
# silently invalidate every credential.
check("rp_id() returns the PIN even when live derivation would differ",
      R.rp_id() == HOST)

pinned, live, drifted = R.check_drift()
check("check_drift reports the pin without auto-correcting", pinned == HOST)
check("  ...and reports, never rebinds (pin unchanged)", R.pinned_rp_id() == HOST)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== REBIND: possible, but never by accident ==")

check("rebind WITHOUT the acknowledgement is refused",
      raises(lambda: R.rebind("newname.tailnet-example.ts.net")))
check("  ...and the pin is unchanged", R.pinned_rp_id() == HOST)
check("rebind refuses an invalid value even WITH the acknowledgement",
      raises(lambda: R.rebind("192.168.4.69",
                              i_understand_this_invalidates_all_authenticators=True)))
check("rebind WITH the acknowledgement and a valid value works",
      R.rebind("newname.tailnet-example.ts.net",
               i_understand_this_invalidates_all_authenticators=True)
      == "newname.tailnet-example.ts.net")
check("  ...and it took effect", R.pinned_rp_id() == "newname.tailnet-example.ts.net")


# ═══════════════════════════════════════════════════════════════════════════
print("\n== FAIL-CLOSED READS ==")

reset()
with open(R.RP_ID_FILE, "w", encoding="utf-8") as fh:
    fh.write("   \n")
check("an EMPTY pin file raises (never reads as un-provisioned)", raises(R.pinned_rp_id))
with open(R.RP_ID_FILE, "w", encoding="utf-8") as fh:
    fh.write("192.168.4.69\n")
check("a pin file containing an IP raises", raises(R.pinned_rp_id))
reset()
check("  CONTROL: absent file returns None, which is a real state",
      R.pinned_rp_id() is None)

# No tailscale on this path -> raise, never guess a hostname.
check("derivation with no tailscale output raises rather than guessing",
      raises(lambda: R.derive_rp_id("not json at all")))
check("derivation with an empty Self raises",
      raises(lambda: R.derive_rp_id(json.dumps({"Self": {}}))))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== HASH AND ORIGIN MATCH WHAT WEBAUTHN COMPUTES ==")

reset()
R.pin_rp_id(HOST)
check("rp_id_hash is SHA-256 of the RP ID STRING (per spec)",
      R.rp_id_hash() == hashlib.sha256(HOST.encode()).digest())
check("  ...32 bytes, as the authenticator record requires",
      len(R.rp_id_hash()) == 32)
check("  ...and differs for a different RP ID",
      R.rp_id_hash("other.tailnet-example.ts.net") != R.rp_id_hash(HOST))
check("origin is https, always", R.origin() == "https://" + HOST)
check("  an http origin is never produced", not R.origin().startswith("http://"))

# It must slot straight into a registration record without conversion.
try:
    from core.admin_approval_pairing import build_registration
    from core import admin_approval as aap
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    n = priv.public_key().public_numbers()
    rec = build_registration(
        authenticator_id="phone-1", user_id="admin-1", mode=aap.MODE_WEBAUTHN,
        cose_alg=aap.COSE_ES256,
        public_key={1: 2, 3: aap.COSE_ES256, -1: 1,
                    -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")},
        rp_id_hash=R.rp_id_hash())
    check("rp_id_hash() is accepted by build_registration unmodified",
          rec["rp_id_hash"] == R.rp_id_hash())
except Exception as exc:                                           # noqa: BLE001
    check("rp_id_hash() is accepted by build_registration unmodified", False, repr(exc))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
