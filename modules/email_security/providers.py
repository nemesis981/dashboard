"""Per-provider IMAP facts. ADR 0028 D11.5 Option C + the Proton transport work.

ONE TABLE, TWO CONSUMERS, AND THAT IS THE WHOLE REASON THIS FILE EXISTS
    The enrollment page needs a provider's instructions link and its connection
    settings; the IMAP client needs its TLS mode and error advice. Those were
    going to be two hardcoded lists that drift -- the same defect shape as a
    credential key regex written out twice. They are one table here, and the
    module that renders and the module that connects both read it.

    THE WALKTHROUGH IS A LINK, NOT A COPY. Hand-written `steps` arrays lived
    here until 2026-08-31 and were removed with the Tier 0-3 rewrite: a
    restated walkthrough silently rots the first time a provider moves a
    button, and a wrong walkthrough is worse than a link because the reader
    trusts it and then cannot find the screen it describes. Each entry carries
    `doc_url` + `doc_label` (naming the provider, so it stays searchable when
    the URL eventually breaks) and DOC_VERIFIED records when they were last
    confirmed reachable. Do not reintroduce prose steps alongside the links.

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
YAHOO = "yahoo"
ICLOUD = "icloud"
FASTMAIL = "fastmail"
HOTMAIL = "hotmail"

#: The default when an enrollment does not say. Gmail, because it is the only
#: provider whose path is proven end to end.
DEFAULT_PROVIDER = GMAIL

#: Date every `doc_url` below was last confirmed to return HTTP 200.
#:
#: WHY A DATE AND NOT JUST A URL. Provider documentation *content* stays current;
#: provider documentation *URLs* do not. Measured while building this table: a
#: plausible-looking Proton support URL 404'd, and both the iCloud and Fastmail
#: links redirected. A dead link is worse than slightly stale text, because the
#: reader is mid-enrollment and has nowhere to go. So each link carries the
#: provider NAME as well (searchable when the URL eventually breaks), and
#: test_provider_links.py re-checks them when a network is available.
DOC_VERIFIED = "2026-08-31"

#: Tier 0 of the enrollment walkthrough: what is about to happen, in plain
#: language, BEFORE the reader is asked to choose anything.
#:
#: This exists because the reader is a household member who was sent a link, not
#: an administrator who chose to configure a mail client. The first thing they
#: need is not a provider list -- it is to know what an app password is, that it
#: is not their normal password, and that nobody else will see it.
TIER0_INTRO = [
    ("What this does",
     "Nemesis will read this mailbox to look for phishing and malicious "
     "attachments. It reads mail already delivered to you; it does not send "
     "anything and does not change your mail."),
    ("What you will need",
     "An app password from your email provider. That is a separate password "
     "you create for one program -- it is NOT the password you normally sign "
     "in with, and it can be revoked on its own without changing your real "
     "password."),
    ("Who sees it",
     "The app password is stored on this appliance only. It is never shown to "
     "whoever sent you this link, and scanning stays switched OFF until an "
     "administrator turns it on."),
]

PROVIDERS = {
    GMAIL: {
        "key": GMAIL,
        "label": "Gmail",
        "supported": True,
        #: Link to the PROVIDER'S OWN instructions rather than restating them
        #: here. Their content stays current; a copy here would silently rot the
        #: first time Google moves a button, and a wrong walkthrough is worse
        #: than a link because the reader trusts it and then cannot find the
        #: screen it describes.
        "doc_url": "https://support.google.com/accounts/answer/185833",
        "doc_label": "Google's instructions for creating an app password",
        "imap_host": "imap.gmail.com",
        "imap_port": 993,
        "tls_mode": TLS_IMPLICIT,
        "loopback_only": False,
        "allow_self_signed": False,
        "credential_label": "16-character app password from Google",
        #: The authserv-id fast_check requires the topmost
        #: Authentication-Results header to carry before it will read that
        #: header's verdicts. Confirmed for Gmail.
        "authserv_id": "mx.google.com",
        #: Google displays app passwords in four groups of four, so a pasted
        #: value carries spaces that are not part of the secret.
        "strip_inner_whitespace": True,
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
        "supported": True,
        "doc_url": "https://proton.me/support/bridge",
        "doc_label": "Proton's Bridge setup guide",
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
        "credential_label": "password shown by Proton Mail Bridge",
        #: ⚠ DELIBERATELY A VALUE THAT CANNOT MATCH, NOT None, AND NOT A GUESS.
        #:
        #: Proton's real authserv-id has NOT been confirmed against a real
        #: message, and the two tempting alternatives are both wrong:
        #:
        #:   None  -- fast_check SKIPS the identity check entirely when this is
        #:            falsy and sets header_trusted=True, so every
        #:            Authentication-Results header would be believed, including
        #:            a forged one inserted by a sender. That is the dangerous
        #:            direction and the exact thing that function warns about.
        #:   a guess -- a wrong-but-plausible id fails the same way if it happens
        #:            to match something an attacker can also produce.
        #:
        #: `.invalid` is RFC 2606 reserved and can never be a real authserv-id,
        #: so this ALWAYS mismatches: verdicts are not read, header_trusted stays
        #: False, and the auth facts are recorded as unknown rather than invented.
        #:
        #: AND THE FAILURE CARRIES ITS OWN FIX. The mismatch is recorded as
        #: `authserv_id_mismatch:<the actual id>`, so the first real Proton
        #: message scanned writes Proton's true authserv-id into
        #: email_message_verdicts.auth_problems. Read it there, confirm it, and
        #: replace this value -- at which point Proton's auth verdicts become
        #: trustworthy. Until then they are correctly treated as unverified.
        "authserv_id": "proton-authserv-id-unconfirmed.invalid",
        #: Bridge shows a single unbroken token. Stripping inner whitespace is a
        #: Gmail-display accommodation and must not be applied blindly: if a
        #: Bridge password ever did contain a space, silently removing it would
        #: fail as a wrong password with nothing pointing at the real cause.
        "strip_inner_whitespace": False,
        "auth_help": ("Check that Proton Mail Bridge is running and signed in, "
                      "and that the password was copied from Bridge's own "
                      "settings page. It is not your Proton account password."),
    },
    YAHOO: {
        "key": YAHOO,
        "label": "Yahoo Mail",
        "supported": True,
        "doc_url": "https://help.yahoo.com/kb/SLN15241.html",
        "doc_label": "Yahoo's instructions for generating an app password",
        "imap_host": "imap.mail.yahoo.com",
        "imap_port": 993,
        "tls_mode": TLS_IMPLICIT,
        "loopback_only": False,
        "allow_self_signed": False,
        "credential_label": "app password from Yahoo",
        #: UNCONFIRMED -- see _unconfirmed_authserv() for why this is a value
        #: that can never match rather than None or a guess.
        "authserv_id": None,          # replaced by _unconfirmed_authserv below
        #: CONSERVATIVE DEFAULT, not a measurement. Only Gmail is confirmed to
        #: display app passwords in space-separated groups. Stripping inner
        #: whitespace that a provider actually considers part of the secret
        #: fails as "wrong password" with nothing pointing at the real cause, so
        #: the safe direction for an unconfirmed provider is to change nothing.
        "strip_inner_whitespace": False,
        "auth_help": ("Check that the app password was copied correctly and "
                      "that IMAP access is still enabled in your Yahoo account "
                      "security settings."),
    },
    ICLOUD: {
        "key": ICLOUD,
        "label": "iCloud Mail",
        "supported": True,
        "doc_url": "https://support.apple.com/102654",
        "doc_label": "Apple's instructions for app-specific passwords",
        "imap_host": "imap.mail.me.com",
        "imap_port": 993,
        "tls_mode": TLS_IMPLICIT,
        "loopback_only": False,
        "allow_self_signed": False,
        "credential_label": "app-specific password from Apple",
        "authserv_id": None,
        #: Apple displays these as four hyphen-separated groups. Hyphens are not
        #: whitespace, so they survive regardless -- and they are part of what
        #: Apple accepts, so they must.
        "strip_inner_whitespace": False,
        "auth_help": ("Check that the app-specific password was copied "
                      "correctly and that two-factor authentication is still "
                      "enabled on your Apple Account -- app-specific passwords "
                      "cannot be created or used without it."),
    },
    FASTMAIL: {
        "key": FASTMAIL,
        "label": "Fastmail",
        "supported": True,
        "doc_url": "https://www.fastmail.help/hc/en-us/articles/360058752854",
        "doc_label": "Fastmail's instructions for creating an app password",
        "imap_host": "imap.fastmail.com",
        "imap_port": 993,
        "tls_mode": TLS_IMPLICIT,
        "loopback_only": False,
        "allow_self_signed": False,
        "credential_label": "app password from Fastmail",
        "authserv_id": None,
        "strip_inner_whitespace": False,
        "auth_help": ("Check that the app password was copied correctly and "
                      "that it was created with IMAP access enabled -- "
                      "Fastmail app passwords are scoped per protocol."),
    },
    #: ⚠ PRESENT AND DELIBERATELY NOT CONNECTABLE. Read the reason before
    #: "finishing" this entry by adding IMAP settings to it.
    #:
    #: Personal Outlook.com/Hotmail IMAP is OAuth2-ONLY. This was MEASURED, not
    #: assumed: outlook.com advertises OAuth2 on all three of its discovery
    #: sources and `password-cleartext` on none of them. There is no app
    #: password to paste, so every field this table uses to make a connection is
    #: absent by design -- not omitted, not TODO.
    #:
    #: It appears in the UI anyway because SILENCE READS AS AN OVERSIGHT. A
    #: household member with a Hotmail address who finds no Hotmail option
    #: assumes the product is broken or that they picked the wrong link; one who
    #: finds a Hotmail option that says plainly "Microsoft sign-in is not
    #: supported yet" has been answered.
    #:
    #: MAKING IT WORK IS A DECISION, NOT A CHORE. It needs XOAUTH2 and a
    #: registered Microsoft OAuth application -- exactly the cost ADR 0028 D1
    #: chose IMAP to avoid, and D11.5's deferral. Adding settings here would
    #: reverse that deferral by refactoring instead of by decision.
    HOTMAIL: {
        "key": HOTMAIL,
        "label": "Outlook.com / Hotmail",
        "supported": False,
        "doc_url": ("https://support.microsoft.com/en-us/office/pop-imap-and-"
                    "smtp-settings-for-outlook-com-d088b986-291d-42b8-9564-"
                    "9c414e2aa040"),
        "doc_label": "Microsoft's Outlook.com mail settings reference",
        "unsupported_reason": (
            "Microsoft accounts sign in with a Microsoft prompt rather than an "
            "app password, and Nemesis does not support that yet. There is "
            "nothing you can paste here that will work. Gmail, Proton Mail, "
            "Yahoo, iCloud and Fastmail are supported today."),
    },
}


def _unconfirmed_authserv(key: str) -> str:
    """A value that can NEVER be a real authserv-id, for a provider whose real
    one has not been confirmed against an actual message.

    THE TWO TEMPTING ALTERNATIVES ARE BOTH WRONG, and this mirrors the reasoning
    written out in full on the PROTON entry above:

      None    -- `fast_check` SKIPS the identity check when this is falsy and
                 sets header_trusted=True, so EVERY Authentication-Results
                 header would be believed, including one forged by a sender.
                 That is the dangerous direction.
      a guess -- a wrong-but-plausible id fails the same way the moment it
                 matches something an attacker can also produce.

    `.invalid` is RFC 2606 reserved, so this always mismatches: verdicts are not
    read, header_trusted stays False, and the auth facts are recorded as unknown
    rather than invented.

    AND THE FAILURE CARRIES ITS OWN FIX, exactly as Proton's does: the mismatch
    is recorded as `authserv_id_mismatch:<actual id>`, so the first real message
    scanned for this provider writes its true authserv-id into
    `email_message_verdicts.auth_problems`. Read it there, confirm it, and
    replace this call with the literal.
    """
    return "%s-authserv-id-unconfirmed.invalid" % key


for _k, _p in PROVIDERS.items():
    if _p.get("supported") and _p.get("authserv_id") is None:
        _p["authserv_id"] = _unconfirmed_authserv(_k)
del _k, _p


def _validate():
    """Fail at IMPORT if an entry contradicts the loopback/self-signed rule.

    A misconfigured entry must not be discoverable only when someone happens to
    enrol that provider -- by then it is a live connection accepting an
    unverifiable certificate against a remote host. Import time is the last
    moment this can fail harmlessly.
    """
    for key, p in PROVIDERS.items():
        # Every entry, connectable or not, must carry a link that names its
        # provider -- the link IS the walkthrough now that the hand-written
        # `steps` arrays are gone, so an entry without one has no instructions
        # at all rather than merely terse ones.
        if not p.get("doc_url", "").startswith("https://"):
            raise RuntimeError(
                "provider %r has no https doc_url. The provider's own page is "
                "the walkthrough; an entry without one leaves the account "
                "owner with nothing to follow." % key)
        if not p.get("doc_label"):
            raise RuntimeError("provider %r has no doc_label" % key)

        if not p.get("supported"):
            # ⛔ AN UNSUPPORTED ENTRY MUST CARRY NO CONNECTION SETTINGS.
            # Defence in depth, not tidiness: `is_connectable()` already gates
            # the enrollment route, but if a future change ever got past that
            # gate, there must be nothing here to connect TO. Absent settings
            # fail as a KeyError at the point of use rather than silently
            # dialling a plausible-looking host.
            leaked = [f for f in ("imap_host", "imap_port", "tls_mode")
                      if f in p]
            if leaked:
                raise RuntimeError(
                    "provider %r is marked unsupported but carries connection "
                    "settings %s. An unsupported entry must have nothing to "
                    "connect to." % (key, leaked))
            if not p.get("unsupported_reason"):
                raise RuntimeError(
                    "provider %r is unsupported but does not say why. The UI "
                    "shows this text; without it the entry reads as broken "
                    "rather than as an honest limitation." % key)
            continue

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


def is_connectable(provider) -> bool:
    """True only for a provider this appliance can actually authenticate to.

    DISTINCT FROM `is_known()` ON PURPOSE, and the enrollment route must gate on
    THIS one. `is_known("hotmail")` is True -- the entry exists so the UI can
    explain itself -- but there is no app password that will work and no
    connection settings to use. Gating on `is_known` would accept a credential
    for a mailbox that can never be read, store it, and fail later as an
    authentication error, which reads as "you typed it wrong".
    """
    return is_known(provider) and bool(PROVIDERS[provider].get("supported"))


def choices():
    """(key, label) pairs for a CONNECTABLE provider chooser, stable order.

    Unsupported entries are excluded here rather than filtered by each caller:
    every existing consumer of this function is asking "what can I connect to"
    (imap_idle's TLS-mode conformance test among them), and an entry with no
    tls_mode would break them. The UI that needs to SHOW the honest unsupported
    entry asks `display_choices()` instead.
    """
    return [(k, PROVIDERS[k]["label"]) for k in sorted(PROVIDERS)
            if PROVIDERS[k].get("supported")]


def display_choices():
    """(key, label, supported) for every entry, connectable or not.

    For the enrollment page, which shows unsupported providers deliberately --
    see the HOTMAIL entry for why silence reads as an oversight. Supported
    entries sort first so the working options are not buried.
    """
    return [(k, PROVIDERS[k]["label"], bool(PROVIDERS[k].get("supported")))
            for k in sorted(PROVIDERS,
                            key=lambda k: (not PROVIDERS[k].get("supported"), k))]


def doc_link(provider) -> tuple:
    """(url, label) for a provider's own instructions, or (None, None).

    Never raises: this is rendered on a page the account owner is already
    looking at, and an exception while showing them where to get help replaces
    the help with a stack trace.
    """
    try:
        p = get(provider)
    except KeyError:
        return (None, None)
    return (p.get("doc_url"), p.get("doc_label"))


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
