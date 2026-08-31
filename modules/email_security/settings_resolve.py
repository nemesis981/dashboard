"""Decide WHICH IMAP settings an enrollment actually connects with.

THE THREE SOURCES, IN PRECEDENCE ORDER
    Tier 1  a known provider  -- its built-in settings, and nothing else is
                                 consulted. Picking "Gmail" must connect to
                                 Gmail; a discovered or typed host must not be
                                 able to redirect it.
    Tier 2  autodiscovery     -- settings found admin-side at mint time and
                                 carried on the enrollment row.
    Tier 3  manual entry      -- what the account owner typed, when nothing
                                 else knows.

WHY TIER 1 IGNORES THE OTHER TWO RATHER THAN MERGING WITH THEM. If a known
provider's host could be overridden by a value arriving with the request, then
"Gmail" would be a label on a field an attacker controls, and the owner would
type their Google app password into a form that connects somewhere else. The
built-in entry wins outright. That is also why `resolve()` takes the provider
key first and only looks further when it is not a connectable provider.

⚠ THE MANUAL PATH IS REACHED FROM AN UNAUTHENTICATED PAGE, AND THAT IS THE
WHOLE REASON THE GUARDS BELOW EXIST. /email/enroll is a hand-placed
_AUTH_EXEMPT route; anyone holding a valid single-use code can drive it. A host
field with no constraints would let that caller aim this appliance's outbound
IMAP connection at an address of their choosing -- an internal service, a
loopback port -- and learn from the timing or the error whether it answered.
That is a port-scanning primitive with credentials attached, not merely an odd
configuration. So manual settings are constrained to:

  * a literal loopback / private / link-local / reserved address is REFUSED,
  * the port must be one of the two standard IMAP ports,
  * the TLS mode must be one of the two this codebase implements.

RESIDUAL, STATED RATHER THAN GLOSSED: a manual HOSTNAME that resolves to a
private address is NOT blocked here, because blocking it needs a DNS lookup and
this code path must not perform one -- that would hand back the exact
attacker-chosen-lookup primitive the admin-side autodiscovery split exists to
prevent (see views.api_enroll_create). The literal-address check catches the
direct attempt; the name-based one is not closed here and is recorded in
PUNCHLIST rather than left implied.

Proton is the reason `loopback_only` is a PROVIDER property and not a global
ban: Bridge legitimately listens on 127.0.0.1. That is reachable only by
choosing the Proton entry, whose host is built in and not caller-supplied.
"""
from __future__ import annotations

import ipaddress
import re

from . import providers

#: Standard IMAP ports. 993 = implicit TLS, 143 = STARTTLS. Deliberately not a
#: free integer: an arbitrary port is the difference between "configure my
#: mail" and "probe this network for me".
ALLOWED_MANUAL_PORTS = (143, 993)

#: The sentinel provider key meaning "not one of the known providers".
CUSTOM = "custom"

#: Conservative hostname shape. Not a full RFC 1123 implementation -- it only
#: has to reject what should never reach a socket.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


class SettingsError(ValueError):
    """Manual/discovered settings that must not be connected to.

    Carries text written FOR THE ACCOUNT OWNER: this surfaces on the enrollment
    page, and "invalid input" tells a household member nothing they can act on.
    """


def _reject_special_address(host: str):
    """Refuse a literal IP that must never be an enrollment target.

    Name resolution is deliberately NOT performed -- see the module header.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return                      # a name, not a literal; nothing to check here
    if (ip.is_loopback or ip.is_private or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        raise SettingsError(
            "That mail server address points back into this network rather "
            "than out to a mail provider, so it cannot be used here. Enter "
            "the server name your provider gave you, such as "
            "imap.example.com.")


def validate_manual(host, port, tls_mode) -> dict:
    """Validate owner-supplied connection settings. Raises SettingsError.

    Every message is written to be actionable by a non-expert, because this is
    rendered on the page they are already stuck on.
    """
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        raise SettingsError("Enter the IMAP server name from your email "
                            "provider, such as imap.example.com.")
    if len(host) > 253:
        raise SettingsError("That server name is too long to be valid.")

    _reject_special_address(host)
    # A literal PUBLIC IP is allowed through; only names are shape-checked,
    # since an address will not match a hostname pattern.
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False
    if not is_literal and not _HOSTNAME_RE.match(host):
        raise SettingsError(
            "That does not look like a mail server name. It should look like "
            "imap.example.com.")

    try:
        port = int(str(port).strip())
    except (TypeError, ValueError):
        raise SettingsError("The port must be a number -- usually 993.") from None
    if port not in ALLOWED_MANUAL_PORTS:
        raise SettingsError(
            "Nemesis connects on port 993 (secure) or 143 (upgraded to secure). "
            "Your provider's instructions will say which to use.")

    tls_mode = (tls_mode or "").strip().lower()
    if tls_mode not in (providers.TLS_IMPLICIT, providers.TLS_STARTTLS):
        raise SettingsError("Choose how the connection is secured: SSL/TLS "
                            "(usually port 993) or STARTTLS (usually port 143).")

    return {"imap_host": host, "imap_port": port, "tls_mode": tls_mode,
            "loopback_only": False, "allow_self_signed": False}


def from_discovery(disc: dict) -> dict:
    """Connection settings from a stored autodiscovery result.

    ⚠ VALIDATED THE SAME WAY AS MANUAL ENTRY, deliberately. These came from a
    third party's DNS or from Mozilla's ISPDB -- they are not this appliance's
    own data, and a domain publishing an SRV record pointing at loopback is a
    thing a domain can simply do. Trusting them because "we looked them up
    ourselves" would be trusting the lookup, not the answer.
    """
    if not disc or not disc.get("disc_host"):
        raise SettingsError("No settings were detected for that address.")
    return validate_manual(disc.get("disc_host"), disc.get("disc_port"),
                           disc.get("disc_tls"))


def resolve(provider, *, discovery=None, manual=None) -> dict:
    """The settings this enrollment will connect with, plus how they were chosen.

    Returns a dict with the connection keys plus `source` -- "provider",
    "discovered" or "manual" -- which the caller records and shows, so a mailbox
    that later fails to connect can be traced to WHERE its host came from.
    """
    if providers.is_connectable(provider):
        p = providers.get(provider)
        return {"imap_host": p["imap_host"], "imap_port": p["imap_port"],
                "tls_mode": p["tls_mode"],
                "loopback_only": p["loopback_only"],
                "allow_self_signed": p["allow_self_signed"],
                "source": "provider", "provider": provider}

    if provider != CUSTOM:
        # An unknown key is not silently treated as custom: that would turn a
        # typo -- or a stale form value naming a provider that has since been
        # removed -- into a manual connection to whatever else was posted.
        raise SettingsError("Choose one of the listed email providers, or "
                            "choose Other and enter your server settings.")

    if manual:
        out = validate_manual(manual.get("imap_host"), manual.get("imap_port"),
                              manual.get("tls_mode"))
        out.update(source="manual", provider=CUSTOM)
        return out

    out = from_discovery(discovery)
    out.update(source="discovered", provider=CUSTOM)
    return out
