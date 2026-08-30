"""Sender RECURRENCE tokens for the D4 personal baseline -- never sender identity.

WHY A HASH AND NOT THE ADDRESS
    `imap_idle`'s PRIVACY contract is explicit: "Nothing here logs, prints, or
    stores subjects, bodies, senders, or any message content." That is a
    deliberate commitment and D4 does not get to quietly reverse it.

    D4 does not actually need the address. Its question is "has this account
    corresponded with this party before, and how often" -- an EQUIVALENCE
    RELATION, which a hash preserves exactly. Storing the address would retain
    strictly more than the feature requires.

    Precedent in this module: `email_attachment_detonations.name_hash` already
    stores a hash rather than the filename, for the same reason.

WHY THIS ONE IS SALTED WHEN `name_hash` IS NOT -- a deliberate divergence
    An unsalted hash is only privacy-preserving when the input space is large.
    Filenames are varied; EMAIL ADDRESSES ARE NOT. An attacker holding the DB can
    hash a contact list, a breach dump, or "firstname.lastname@<common domain>"
    and recover senders from an unsalted digest in seconds. The digest would then
    be the address, wearing a costume.

    A per-install salt held OUTSIDE the database defeats that: the DB alone no
    longer yields the mapping, and hashes are not comparable between installs.

FAIL CLOSED, NEVER FALL BACK TO UNSALTED
    With no salt configured, `sender_token()` returns None and the column stays
    NULL. It NEVER degrades to an unsalted digest. An unsalted fallback would be a
    privacy REGRESSION presented as the feature working -- exactly the shape of
    "a default that means something" this project treats as a defect.

    NULL therefore means "unknown", never "a sender not seen before". The baseline
    must not read absence as novelty.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re

log = logging.getLogger("nemesis.email_security.sender_id")

#: Read from the process environment, which systemd populates from
#: /etc/nemesis.env (mode 640 root:nemesis) -- the project's documented location
#: for secrets. Deliberately NOT stored in alerts.db: a salt sitting beside the
#: hashes it protects protects nothing.
SALT_ENV_VAR = "EMAIL_SENDER_SALT"

#: Truncation. 16 hex chars = 64 bits, matching the sibling `name_hash` length.
#: Ample for equivalence within one mailbox's correspondents, and it retains less
#: than a full digest would.
TOKEN_HEX = 16

_ANGLE = re.compile(r"<([^>]*)>")
_warned = False


def normalise_sender(raw: str | None) -> str | None:
    """`'Alice Example <A.Example@Gmail.COM>'` -> `'a.example@gmail.com'`.

    Returns None when there is no usable address. Normalisation must happen
    BEFORE hashing or the same correspondent yields different tokens depending on
    how their client formatted the header -- which would silently inflate the
    apparent number of distinct senders and make every one of them look new.
    """
    if not raw or not isinstance(raw, str):
        return None
    m = _ANGLE.search(raw)
    addr = (m.group(1) if m else raw).strip().strip("<>").strip()
    # A display name may contain an @; require the LAST @ to have both sides.
    if addr.count("@") < 1:
        return None
    local, _, domain = addr.rpartition("@")
    local, domain = local.strip(), domain.strip()
    if not local or not domain or " " in addr:
        return None
    # Domain is case-insensitive per RFC 5321. The local part technically is not,
    # but every mainstream provider treats it case-insensitively, and a baseline
    # that split one correspondent in two on capitalisation would be worse than
    # the theoretical over-merge this risks.
    return "%s@%s" % (local.lower(), domain.lower())


def install_salt() -> str | None:
    """The per-install salt, or None if unset. Warns ONCE, never repeatedly."""
    global _warned
    salt = (os.environ.get(SALT_ENV_VAR) or "").strip()
    if salt:
        return salt
    if not _warned:
        _warned = True
        log.warning(
            "%s is not set: sender_hash will be NULL and the D4 sender baseline "
            "will not build. NOT falling back to an unsalted digest -- that would "
            "be reversible against an address list.", SALT_ENV_VAR)
    return None


def sender_token(raw: str | None, salt: str | None = None) -> str | None:
    """Salted, truncated recurrence token for a From header, or None.

    None on: no salt, no header, or an unparseable address. All three are
    "unknown" and must be treated identically by the caller.
    """
    salt = salt if salt is not None else install_salt()
    if not salt:
        return None
    addr = normalise_sender(raw)
    if not addr:
        return None
    # HMAC rather than sha256(salt + addr): keyed construction, no length-extension
    # question, and it states the intent -- the salt is a KEY, not a prefix.
    return hmac.new(salt.encode("utf-8"),
                    addr.encode("utf-8"),
                    hashlib.sha256).hexdigest()[:TOKEN_HEX]
