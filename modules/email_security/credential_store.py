"""Resolve an email account's app password. ADR 0028 D11.5 Option C.

WHERE THE SECRET LIVES, AND WHY NOT IN /etc/nemesis.env
    `/etc/nemesis-email-secrets.env` (0640 root:nemesis), a SEPARATE file from
    the core secrets file (operator decision, 2026-08-31).

    /etc/nemesis.env holds core system secrets an admin sets once at install
    time. Email app passwords arrive by a LOWER-TRUST path -- a single-use
    enrollment link completed by a household member who has no dashboard login --
    and the set of them grows unboundedly with the number of mailboxes.

    Sharing one file would force a choice between two bad options: routine,
    expected enrollment writes polluting the change-monitoring / file-integrity
    signal on the file holding the high-value secrets, or excluding part of that
    file from monitoring to compensate. Separating them keeps any write to
    nemesis.env exceptional and therefore worth alerting on.

WHY NOT `os.environ`, WHICH WOULD HAVE BEEN LESS CODE
    This file is deliberately NOT listed as a systemd `EnvironmentFile`. A
    freshly enrolled mailbox has to be usable immediately, and inheriting the
    file as process environment would mean a newly written credential is
    invisible until seven services are restarted -- so an enrollment would appear
    to succeed and then silently not scan anything until the next reboot.

    Reading the file at CALL TIME costs one small read per connection attempt and
    removes that entire failure mode.

THIS MODULE NEVER WRITES. The dashboard cannot write this file (it runs as
    nemesis-dash, which is in group `nemesis` and therefore has read but not
    write). Writes go through `nemesis_fwd`'s `write_email_secret` op, which
    validates and consumes an enrollment code first. That asymmetry is the point:
    reading is cheap and local, writing requires proof.

A FAILED READ IS AN EXPLICIT FAILURE, NEVER A DEFAULT
    Every function here raises rather than returning "" or None for a missing or
    unreadable credential. An empty-string password would be handed to
    `IMAP4.login()`, rejected by the provider, and surface as `ImapAuthError` --
    reporting "your app password is wrong" for what is actually "no credential
    was ever stored". That is this project's standing "a default that means
    something" defect, and it would send whoever debugs it to the wrong place.

NOTHING HERE LOGS A SECRET. Log lines carry key NAMES and counts only, matching
    the discipline `nemesis_fwd` applies on the write side.
"""
from __future__ import annotations

import logging
import os
import re

log = logging.getLogger("nemesis.email_security.credentials")

#: Must match nemesis_fwd.EMAIL_SECRETS_PATH. Same env override, so a test or a
#: non-standard install moves both halves together.
SECRETS_PATH = os.environ.get("NEMESIS_EMAIL_SECRETS_PATH",
                              "/etc/nemesis-email-secrets.env")

#: Must match nemesis_fwd.EMAIL_SECRET_KEY_RE EXACTLY -- the writer enforces this
#: shape, so a reader that accepted a wider one would look up keys that can never
#: have been written. `test_credential_store.py` asserts the two are identical
#: rather than trusting this comment to stay true.
CREDENTIAL_REF_RE = re.compile(r"^EMAIL_SEC_APPPW_[0-9]{1,3}$")

#: Upper bound implied by the three-digit key shape above.
MAX_SLOT = 999


class CredentialError(RuntimeError):
    """Base: this module could not produce a credential. Never swallowed."""


class CredentialUnavailable(CredentialError):
    """The store could not be read at all -- absent, unreadable, permission.

    DISTINCT from CredentialMissing on purpose. "The file is unreadable" and
    "this mailbox has no stored password" have different fixes: one is a
    deployment/permissions problem affecting every mailbox, the other is an
    incomplete enrollment affecting one. Collapsing them would send whoever
    debugs it to the wrong half of the system.
    """


class CredentialMissing(CredentialError):
    """The store was read fine, but holds no entry for this credential_ref."""


def slot_ref(n: int) -> str:
    """Slot number -> credential_ref. Raises on anything the writer would refuse.

    Validating HERE means an exhausted sequence fails loudly at allocation time
    rather than producing a key the privileged writer silently rejects later,
    when the enrollment code has already been spent.
    """
    if not isinstance(n, int) or isinstance(n, bool) or n < 0 or n > MAX_SLOT:
        raise CredentialError(
            "credential slot %r is outside the writable range 0-%d; the "
            "credential keyspace is exhausted and the key shape must be widened "
            "in BOTH nemesis_fwd.EMAIL_SECRET_KEY_RE and this module"
            % (n, MAX_SLOT))
    return "EMAIL_SEC_APPPW_%d" % n


def is_valid_ref(ref) -> bool:
    """True when `ref` is a key the privileged writer would accept."""
    return isinstance(ref, str) and bool(CREDENTIAL_REF_RE.match(ref))


def _parse(text: str) -> dict:
    """KEY=VALUE lines -> dict. Comments and blanks ignored.

    Deliberately tolerant of surrounding whitespace and of `export KEY=`, both of
    which a human editing this file by hand may reasonably produce. Values are
    taken VERBATIM after the first `=` -- an app password may legitimately
    contain `=` and spaces, so splitting on all of them would corrupt it.

    Surrounding single or double quotes are stripped, because a human writing the
    file by hand is likely to add them and a literal quote character is not
    something any provider's app password format uses.
    """
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key, _, value = s.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        out[key] = value
    return out


def load_all(path: str | None = None) -> dict:
    """Every credential in the store. Raises CredentialUnavailable on any failure.

    A missing FILE raises rather than returning {}. An empty mapping would be a
    legal-looking answer meaning "no mailbox has a credential", which is
    indistinguishable from "the store is not deployed" to every caller -- the
    failed-read-as-default shape this module's header refuses.
    """
    p = path or SECRETS_PATH
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return _parse(fh.read())
    except FileNotFoundError as exc:
        raise CredentialUnavailable(
            "email credential store %s does not exist; no mailbox has completed "
            "enrollment yet, or the store was removed" % p) from exc
    except PermissionError as exc:
        raise CredentialUnavailable(
            "email credential store %s is not readable by this process; it is "
            "0640 root:nemesis and the reader must be in group 'nemesis'" % p) from exc
    except OSError as exc:
        raise CredentialUnavailable(
            "email credential store %s could not be read: %s" % (p, exc)) from exc
    except (UnicodeDecodeError, ValueError) as exc:
        # ⚠ A DECODE ERROR IS *NOT* AN OSError, so it escaped every handler above
        # and surfaced to the caller as a bare ValueError. Reachable: one
        # non-UTF-8 byte anywhere in the file -- a hand-edited entry, a password
        # pasted from a latin-1 source -- and the caller reported "could not
        # verify the stored credential" for ONE mailbox when the real state is
        # "the store is unreadable, every mailbox is affected". That is exactly
        # the misdirection the Unavailable/Missing split exists to prevent, so
        # it belongs on this side of it.
        raise CredentialUnavailable(
            "email credential store %s is not valid UTF-8 and cannot be parsed: "
            "%s" % (p, exc)) from exc


def get_secret(credential_ref: str, path: str | None = None) -> str:
    """The app password named by `credential_ref`.

    Raises CredentialError (bad ref), CredentialUnavailable (store unreadable),
    or CredentialMissing (no such entry). Never returns "" -- see the header.
    """
    if not is_valid_ref(credential_ref):
        raise CredentialError(
            "credential_ref %r is not a valid slot name; expected "
            "EMAIL_SEC_APPPW_<0-999>" % (credential_ref,))

    entries = load_all(path)
    value = entries.get(credential_ref)
    if not value:
        # Present-but-empty is treated as missing, deliberately. An empty value
        # would otherwise be handed to IMAP login and misreported as a wrong
        # password. The privileged writer already refuses to write one, so this
        # is defence against a hand-edited file, not against our own writer.
        raise CredentialMissing(
            "no app password stored for %s. The mailbox row exists but its "
            "enrollment never completed, or the store was edited by hand."
            % credential_ref)
    return value


def has_secret(credential_ref: str, path: str | None = None) -> bool:
    """True when a usable credential exists. Swallows MISSING, not UNAVAILABLE.

    ⚠ THE ASYMMETRY IS THE POINT. "This mailbox has no credential" is a real,
    expected state a status card should render calmly. "The store cannot be read
    at all" is a deployment fault affecting every mailbox, and returning False
    for it would render as `not configured` on every account -- a deployment
    failure disguised as an empty configuration, which is exactly the false
    reassurance `Module.status()` is written to avoid.
    """
    try:
        get_secret(credential_ref, path)
        return True
    except CredentialMissing:
        return False
