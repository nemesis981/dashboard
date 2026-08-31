"""Per-provider IMAP facts. ADR 0028 D11.5 Option C + the Proton transport work.

ONE TABLE, TWO CONSUMERS, AND THAT IS THE WHOLE REASON THIS FILE EXISTS
    The enrollment page needs a provider's human walkthrough and its connection
    settings; the IMAP client needs its TLS mode and error advice. Those were
    going to be two hardcoded lists that drift -- the same defect shape as a
    credential key regex written out twice. They are one table here, and the
    module that renders and the module that connects both read it.

WHY THIS IS NOT "GENERALISING THE CLIENT", WHICH imap_idle.py EXPLICITLY REFUSES
    imap_idle's header refuses to become a provider-agnostic IMAP client, and it
    is right to: the deferral of Outlook.com exists because that needs XOAUTH2
    and a registered Microsoft OAuth app, which is exactly the cost ADR 0028 D1
    picked IMAP to avoid. A `provider=` argument that grows an OAuth branch would
    reverse that deferral by refactoring rather than by decision.

    This table does NOT do that. Every entry here authenticates with a plain
    username + app-password LOGIN over TLS. What varies is the transport shape
    (implicit TLS vs STARTTLS) and whether the endpoint is loopback -- mechanical
    facts about where to connect, not different authentication models. An entry
    requiring OAuth would NOT belong here; it would still be a real decision.

TLS MODES
    "implicit"  -- TLS from the first byte (IMAPS, the :993 style). Gmail.
    "starttls"  -- plaintext connect, then upgrade via STARTTLS. Proton Bridge's
                   default on :1143.

LOOPBACK AND SELF-SIGNED CERTIFICATES
    `allow_self_signed` is permitted ONLY where `loopback_only` is also true, and
    that pairing is ENFORCED by _validate() below rather than merely documented.
    Accepting a self-signed certificate is defensible for 127.0.0.1, where there
    is no man-in-the-middle position to occupy, and indefensible for a remote
    host, where it removes the only thing authenticating the server. A future
    entry that sets one without the other fails at import.
"""
from __future__ import annotations

#: TLS transport modes. Not booleans: "not implicit" and "starttls" would be the
#: same value today and stop being so the moment a third mode appears.
TLS_IMPLICIT = "implicit"
TLS_STARTTLS = "starttls"

GMAIL = "gmail"
PROTON = "proton"

#: The default when an enrollment does not say. Gmail, because it is the only
#: provider whose path is proven end to end.
DEFAULT_PROVIDER = GMAIL

PROVIDERS = {
    GMAIL: {
        "key": GMAIL,
        "label": "Gmail",
        "imap_host": "imap.gmail.com",
        "imap_port": 993,
        "tls_mode": TLS_IMPLICIT,
        "loopback_only": False,
        "allow_self_signed": False,
        #: Shown on the enrollment page. Plain language: the reader is a
        #: household member, not an administrator.
        "steps": [
            "Sign in to your Google Account and open the Security page.",
            "Turn on 2-Step Verification if it is not already on. App passwords "
            "cannot be created without it.",
            "Open the App passwords page and create one. Google shows you a "
            "16-character code.",
            "Paste that code below. It is not your normal Google password.",
        ],
        "credential_label": "16-character app password from Google",
        #: Advice shown when the provider rejects the credential. Provider-aware
        #: on purpose: telling a Proton user to check Gmail settings, which the
        #: old hardcoded string did, is actively wrong guidance.
        "auth_help": ("Check that the app password was copied correctly, that "
                      "2-Step Verification is still enabled, and that IMAP is "
                      "turned on in Gmail settings."),
    },
    PROTON: {
        "key": PROTON,
        "label": "Proton Mail",
        # Proton exposes NO public IMAP. Proton Mail Bridge runs on the user's
        # own machine and presents IMAP on loopback -- so this host is correct
        # only where Bridge is actually running.
        "imap_host": "127.0.0.1",
        "imap_port": 1143,
        # Bridge's default on 1143 is STARTTLS, not implicit TLS. Connecting with
        # IMAP4_SSL here fails during the handshake.
        "tls_mode": TLS_STARTTLS,
        "loopback_only": True,
        # Bridge presents a SELF-SIGNED certificate for 127.0.0.1 that is in no
        # CA store. Permitted here, and only here, because the connection cannot
        # leave the machine -- see this module's header.
        "allow_self_signed": True,
        "steps": [
            "Install Proton Mail Bridge on this machine and sign in to it with "
            "your Proton account.",
            "Bridge must stay running for mail to be scanned. It is what turns "
            "your Proton mailbox into something this appliance can read.",
            "In Bridge, open Settings and find the mailbox details for your "
            "account.",
            "Copy the password Bridge shows there and paste it below. It is "
            "generated by Bridge and is NOT your Proton account password.",
        ],
        "credential_label": "password shown by Proton Mail Bridge",
        "auth_help": ("Check that Proton Mail Bridge is running and signed in, "
                      "and that the password was copied from Bridge's own "
                      "settings page. It is not your Proton account password."),
    },
}


def _validate():
    """Fail at IMPORT if an entry contradicts the loopback/self-signed rule.

    A misconfigured entry must not be discoverable only when someone happens to
    enrol that provider -- by then it is a live connection accepting an
    unverifiable certificate against a remote host. Import time is the last
    moment this can fail harmlessly.
    """
    for key, p in PROVIDERS.items():
        if p["tls_mode"] not in (TLS_IMPLICIT, TLS_STARTTLS):
            raise RuntimeError(
                "provider %r has unknown tls_mode %r" % (key, p["tls_mode"]))
        if p["allow_self_signed"] and not p["loopback_only"]:
            raise RuntimeError(
                "provider %r permits a self-signed certificate without being "
                "loopback-only. Accepting an unverifiable certificate against a "
                "remote host removes the only thing authenticating the server."
                % key)
        if p["loopback_only"] and p["imap_host"] not in ("127.0.0.1", "::1",
                                                         "localhost"):
            raise RuntimeError(
                "provider %r is marked loopback_only but its host %r is not "
                "loopback" % (key, p["imap_host"]))


_validate()


def is_known(provider) -> bool:
    return isinstance(provider, str) and provider in PROVIDERS


def get(provider: str) -> dict:
    """The provider record. Raises on an unknown key -- never falls back.

    A silent fallback to Gmail would connect a Proton enrollment to
    imap.gmail.com with the user's Bridge password, fail authentication, and
    report it as a bad app password. Fail loudly instead.
    """
    if not is_known(provider):
        raise KeyError(
            "unknown email provider %r (known: %s)"
            % (provider, ", ".join(sorted(PROVIDERS))))
    return PROVIDERS[provider]


def choices():
    """(key, label) pairs for rendering a chooser, in a stable order."""
    return [(k, PROVIDERS[k]["label"]) for k in sorted(PROVIDERS)]


def auth_help(provider) -> str:
    """Provider-appropriate advice for an authentication failure.

    Falls back to generic text for an unknown provider rather than raising: this
    is called on an error path, and an exception thrown while explaining an error
    replaces a useful message with a stack trace.
    """
    try:
        return get(provider)["auth_help"]
    except KeyError:
        return ("Check that the app password was copied correctly and is still "
                "valid with your email provider.")
