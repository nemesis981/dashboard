#!/usr/bin/env python3
"""WebAuthn Relying Party identity for THIS appliance (ADR 0026 §D3 / D6).

WHY THIS IS NOT A CONSTANT
--------------------------
The RP ID is the domain WebAuthn credentials are bound to. Every appliance --
this one, and every future customer install -- must use ITS OWN tailnet identity.
A hardcoded value would mean every appliance shared one RP ID, so a credential
registered against one would be presented to another, and the "which appliance
did this human authorise" question would have no answer. Before this module the
only RP ID anywhere in the repo was `RP_ID = "nemesis.local"` in four test files.

So it is DERIVED, per install, from the live Tailscale MagicDNS name of the host
it runs on, and never read from a config file a deploy could copy between boxes.

⚠ CHANGING THE RP ID INVALIDATES EVERY REGISTERED AUTHENTICATOR. PERMANENTLY.
-----------------------------------------------------------------------------
WebAuthn binds a credential to the RP ID it was created under. Change the RP ID
and every phone that was ever paired stops verifying -- not with a helpful error,
but as an ordinary signature failure. With `MIN_AUTHENTICATORS_FOR_UNLOCK = 2`
and no appliance-side override by design, that is an unrecoverable admin set: the
operator would have to re-enroll from scratch.

That is why this module PINS the value on first use and REFUSES to return a
different one afterwards. A silent change is the failure mode; a loud refusal is
the recovery. `rebind()` exists for the deliberate case and says plainly what it
costs.

WHY THE FULL HOSTNAME, NOT THE TAILNET SUFFIX
---------------------------------------------
`stage0-tls-proof.tailnet-example.ts.net`, not `tailnet-example.ts.net`. The suffix would be
a legal RP ID and would let one credential work across every host on the tailnet
-- which is precisely what should NOT happen. Each appliance is its own relying
party, so a phone paired to one cannot approve actions on another.
"""

import hashlib
import json
import os
import re
import subprocess

__all__ = ["RpIdentityError", "derive_rp_id", "rp_id", "rp_id_hash", "origin",
           "pinned_rp_id", "pin_rp_id", "rebind", "RP_ID_FILE"]

#: Where the pinned value lives. Beside the other appliance identity material.
RP_ID_FILE = os.environ.get("NEMESIS_RP_ID_FILE", "/var/lib/nemesis/rp_id")

#: Escape hatch for TESTS and for an install that is not on a tailnet yet. It is
#: read ONLY when nothing is pinned, and it is validated exactly as strictly as a
#: derived value -- it cannot be used to smuggle in an IP or a bare hostname.
_ENV_OVERRIDE = "NEMESIS_RP_ID"

#: A registrable domain: at least one dot, no scheme, no port, no path, no
#: trailing dot, and NOT an IP literal. WebAuthn forbids an IP address as an RP
#: ID outright, which is the whole reason the appliance's bare-IP `server_name`
#: had to go.
_VALID = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
                    r"(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class RpIdentityError(RuntimeError):
    """No usable RP ID. Raised, never defaulted.

    There is no sensible fallback. Guessing a hostname, or quietly using an IP,
    produces credentials bound to the wrong relying party -- and the damage is
    only discovered when a phone that should work does not. Failing here means
    WebAuthn is unavailable, which is visible and recoverable.
    """


def _validate(candidate, source):
    """Return a normalised RP ID or raise. Shared by every path in, deliberately:
    a value from the environment gets exactly the scrutiny a derived one does."""
    if not candidate or not isinstance(candidate, str):
        raise RpIdentityError("%s produced no RP ID" % source)
    v = candidate.strip().rstrip(".").lower()
    if "://" in v or "/" in v or ":" in v:
        raise RpIdentityError(
            "%s produced %r -- an RP ID is a bare domain, with no scheme, port "
            "or path" % (source, candidate))
    if _IPV4.match(v) or v.count(":") or v.startswith("["):
        raise RpIdentityError(
            "%s produced %r -- an IP address can NEVER be a valid RP ID "
            "(WebAuthn requires a domain)" % (source, candidate))
    if "." not in v:
        raise RpIdentityError(
            "%s produced %r -- a single-label hostname is not a registrable "
            "domain and browsers will reject it" % (source, candidate))
    if not _VALID.match(v):
        raise RpIdentityError("%s produced %r, which is not a valid domain"
                              % (source, candidate))
    return v


def derive_rp_id(_status_json=None):
    """This host's MagicDNS name, from LIVE Tailscale state. Raises if unavailable.

    Reads `tailscale status --json` rather than a config value, so the answer is
    this machine's actual identity and cannot be inherited by copying a deploy
    from one appliance to another -- which is exactly how every install would
    otherwise end up sharing one RP ID.

    `_status_json` is for tests only.
    """
    if _status_json is None:
        try:
            out = subprocess.run(["tailscale", "status", "--json"],
                                 capture_output=True, text=True, timeout=15)
        except FileNotFoundError:
            raise RpIdentityError(
                "tailscale is not installed, so this host has no MagicDNS "
                "identity to derive an RP ID from")
        except Exception as exc:                                   # noqa: BLE001
            raise RpIdentityError("could not run tailscale status: %s" % exc)
        if out.returncode != 0:
            raise RpIdentityError("tailscale status failed (rc=%d): %s"
                                  % (out.returncode, (out.stderr or "")[:120]))
        _status_json = out.stdout
    try:
        data = json.loads(_status_json)
    except Exception as exc:                                       # noqa: BLE001
        raise RpIdentityError("tailscale status was not JSON: %s" % exc)

    self_node = data.get("Self") or {}
    name = self_node.get("DNSName") or ""
    rp = _validate(name, "tailscale Self.DNSName")

    # Cross-check against CertDomains where present. A name we cannot get a
    # certificate for cannot serve a secure context, and WebAuthn needs one --
    # so an RP ID outside CertDomains is a configuration that will fail later,
    # in a browser, with a TLS error rather than anything naming this.
    certs = data.get("CertDomains") or []
    if certs and rp not in [c.strip().rstrip(".").lower() for c in certs]:
        raise RpIdentityError(
            "derived RP ID %r is not in this node's CertDomains %r -- it could "
            "not be served over a secure context, which WebAuthn requires"
            % (rp, certs))
    return rp


def pinned_rp_id():
    """The pinned RP ID, or None if this appliance has never pinned one.

    None means "not yet pinned" and nothing else. An unreadable or malformed pin
    RAISES, so a damaged file can never read as an un-provisioned appliance --
    those need opposite responses.
    """
    try:
        with open(RP_ID_FILE, encoding="utf-8") as fh:
            raw = fh.read().strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RpIdentityError("pinned RP ID at %s is unreadable: %s"
                              % (RP_ID_FILE, exc))
    if not raw:
        raise RpIdentityError("pinned RP ID at %s is empty" % RP_ID_FILE)
    return _validate(raw, "the pinned RP ID file")


def pin_rp_id(value):
    """Pin `value` as this appliance's RP ID. Idempotent; never silently changes.

    Writing the same value again is a no-op. Writing a DIFFERENT one raises --
    see the module docstring for why that is the whole point rather than an
    inconvenience. Use `rebind()` when the change is genuinely intended.
    """
    rp = _validate(value, "pin_rp_id")
    existing = pinned_rp_id()
    if existing is not None:
        if existing != rp:
            raise RpIdentityError(
                "this appliance is already pinned to RP ID %r; refusing to "
                "change it to %r, which would invalidate EVERY registered "
                "authenticator. Use rebind() if that is genuinely intended."
                % (existing, rp))
        return rp
    os.makedirs(os.path.dirname(RP_ID_FILE), exist_ok=True)
    tmp = RP_ID_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(rp + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, RP_ID_FILE)
    return rp


def rebind(new_value, i_understand_this_invalidates_all_authenticators=False):
    """Deliberately change the RP ID. Requires the keyword to be passed True.

    The argument is spelled out rather than being a terse `force=` because the
    consequence is not recoverable from the appliance side: every paired phone
    stops verifying, and the two-authenticator floor means there is no key left
    to authorise a repair. Re-enrollment is the only route back.
    """
    if not i_understand_this_invalidates_all_authenticators:
        raise RpIdentityError(
            "rebind() refused: changing the RP ID invalidates every registered "
            "authenticator permanently. Pass "
            "i_understand_this_invalidates_all_authenticators=True if that is "
            "genuinely intended.")
    rp = _validate(new_value, "rebind")
    os.makedirs(os.path.dirname(RP_ID_FILE), exist_ok=True)
    tmp = RP_ID_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(rp + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, RP_ID_FILE)
    return rp


def rp_id():
    """This appliance's RP ID. Pins on first use; raises if none can be had.

    Order matters: the PIN wins over live derivation. If the host's MagicDNS name
    changes after credentials exist, the pinned value keeps them working and the
    mismatch is surfaced by `check_drift()` rather than silently breaking every
    phone the moment someone renames a machine.
    """
    pinned = pinned_rp_id()
    if pinned is not None:
        return pinned
    env = os.environ.get(_ENV_OVERRIDE)
    if env:
        return pin_rp_id(env)
    return pin_rp_id(derive_rp_id())


def check_drift():
    """(pinned, live, drifted) — has this host's identity moved away from the pin?

    Reported, never auto-corrected. Auto-correcting would be the silent
    invalidation this module exists to prevent; the operator needs to see it and
    decide, because the answer is usually "fix the hostname", not "rebind".
    """
    pinned = pinned_rp_id()
    if pinned is None:
        return (None, None, False)
    try:
        live = derive_rp_id()
    except RpIdentityError:
        return (pinned, None, False)
    return (pinned, live, pinned != live)


def rp_id_hash(value=None):
    """SHA-256 of the RP ID — what WebAuthn puts in `authenticatorData`.

    Hashes the RP ID STRING, per the WebAuthn spec, which is what an
    authenticator computes independently. Anything else here produces a binding
    check that fails for reasons no error message will explain.
    """
    return hashlib.sha256((value or rp_id()).encode("utf-8")).digest()


def origin(value=None):
    """The https origin credentials are created against. Always https: an RP ID
    is only usable from a secure context, so an http origin is never correct."""
    return "https://" + (value or rp_id())
