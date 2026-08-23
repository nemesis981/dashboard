"""Structured prompt allowlist — NPFA v1 (Nemesis Prompt Field Allowlist).

REFERENCE IMPLEMENTATION of the spec in
`docs/architecture/0025-structured-prompt-allowlist.md`. The SPEC is normative,
not this file: the field kinds, their validation rules, and the enforcement
boundary are defined there in language-agnostic terms so a future non-Python
implementation reimplements rather than reverse-engineers. Keep the two in step;
if they ever disagree, the spec wins and this file is the bug.

WHY THIS EXISTS
---------------
Pseudonymization scrubs what it can RECOGNISE — addresses, and device names the
deployment knows. It cannot recognise a name in arbitrary text, so any prompt
assembled from free-form strings carries an open-ended, undetectable leak. The
answer is not a better scrubber; it is to make unrecognised content structurally
unable to enter a machine-generated prompt in the first place.

So: a machine-generated prompt is built ONLY from declared fields, each with a
declared KIND, and each kind is either safe by construction (a literal authored
in source, a number, a member of a finite enum) or scrubbed by type downstream
(an address, a device name). There is deliberately NO free-text kind. A value
that does not fit a kind cannot be sent, rather than being sent and hoped about.

THE ONE EXEMPTION, NARROW AND MARKED
------------------------------------
The follow-up chat surface (`ai_engine.ask_followup`) exists so an operator can
type a question — often pasted command output — and have the model reason about
it. That is not silent disclosure: a human is deliberately composing a message,
in a chat widget, with a visible cost estimate. An allowlist cannot express
"whatever the operator decided to type", so forcing one there would delete the
feature rather than tighten it.

That path therefore passes `free_text_reason=` to `analyze()`. It is ONE marked
caller, not a general escape hatch, and the chokepoint still scrubs addresses and
known device names from what was typed. The residual — an UNKNOWN name inside
text the operator chose to type and send — is real, is disclosed in the product's
privacy notice, and is inherent to any chat feature.
"""

import ipaddress
import re

SPEC_VERSION = "NPFA/1"

# ── Field kinds ──────────────────────────────────────────────────────────────
# Each kind is a promise about what a value can contain. The promise is enforced
# by `_VALIDATORS` below, at build time, before any text exists to be sent.
LITERAL = "literal"          # fixed text authored in source; never runtime data
ENUM = "enum"                # must be a member of a declared finite set
NUMBER = "number"            # int/float
TIMESTAMP = "timestamp"      # epoch seconds or ISO-8601
ADDRESS = "address"          # IPv4/IPv6/MAC -- scrubbed downstream by the chokepoint
DEVICE_NAME = "device_name"  # a device/host name -- scrubbed downstream
DOMAIN = "domain"            # DNS name -- STRUCTURAL disclosure, see spec §5
BASENAME = "basename"        # file basename ONLY; path separators rejected
HASH = "hash"                # hex digest
IDENTIFIER = "identifier"    # bounded machine token (rule id, incident id)
LABEL = "label"              # bounded hardware/metadata label -- NOT scrubbed

KINDS = frozenset({LITERAL, ENUM, NUMBER, TIMESTAMP, ADDRESS, DEVICE_NAME,
                   DOMAIN, BASENAME, HASH, IDENTIFIER, LABEL})

#: LABEL vs DEVICE_NAME -- the distinction is WHOSE identifier it is, and it
#: decides whether the chokepoint scrubs the value:
#:   DEVICE_NAME  names a thing in THIS household ("Reception-Laptop") -> scrubbed
#:   LABEL        names a piece of hardware or a vendor string ("Package id 0",
#:                "coretemp-isa-0000", "Composite") -> not scrubbed, because it
#:                identifies a chip model, not a person, and is identical across
#:                every deployment with the same hardware.
#: Both are bounded and single-line; the kinds differ in MEANING, not shape, and
#: getting that wrong is a privacy decision, so they are deliberately separate
#: rather than one permissive "short string" kind.

#: Hard ceiling per field. Bounds a runaway value long before it reaches a
#: token budget, and makes "somebody passed a whole log line as an IDENTIFIER"
#: fail loudly at build time instead of silently costing money.
MAX_FIELD_CHARS = 512


class PromptFieldError(ValueError):
    """A field violated its declared kind. Raised at BUILD time, never at send
    time, so a bad prompt cannot exist as a string in the first place."""


class BuiltPrompt(str):
    """A prompt assembled only from validated, declared fields.

    A `str` SUBCLASS deliberately, for two reasons:
      * every existing consumer that treats a prompt as text keeps working;
      * the type IS the proof. `isinstance(p, BuiltPrompt)` cannot be satisfied
        by a hand-assembled string, and any str operation on one (concatenation,
        .format, slicing) returns a plain `str` -- so tampering downgrades it and
        the enforcement point rejects it. That property is tested directly.
    """
    __slots__ = ()


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
_HASH_RE = re.compile(r"^[0-9A-Fa-f]{8,128}$")
_IDENT_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-_]{1,63}"
                        r"(?:\.(?!-)[A-Za-z0-9\-_]{1,63})*\.?$")
#: A device name is the one kind whose CONTENT is unconstrained by shape -- names
#: legitimately contain spaces, apostrophes and unicode. It is bounded in LENGTH
#: and rejected if it contains newlines, because a multi-line "name" is not a
#: name, it is free text arriving under a name's label. That check is what stops
#: this kind becoming the escape hatch the whole mechanism exists to prevent.
_NEWLINE_RE = re.compile(r"[\r\n]")


def _v_literal(value, spec):
    if not isinstance(value, str):
        raise PromptFieldError("LITERAL must be str, got %s" % type(value).__name__)
    return value


def _v_enum(value, spec):
    allowed = spec.get("allowed")
    if not allowed:
        raise PromptFieldError("ENUM field declares no allowed set")
    if value not in allowed:
        raise PromptFieldError(
            "ENUM value %r is not one of %s" % (value, sorted(allowed)))
    return str(value)


def _v_number(value, spec):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PromptFieldError("NUMBER must be int/float, got %r" % (value,))
    fmt = spec.get("fmt")
    return (fmt % value) if fmt else str(value)


def _v_timestamp(value, spec):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str) and len(value) <= 64 and not _NEWLINE_RE.search(value):
        return value
    raise PromptFieldError("TIMESTAMP must be epoch seconds or a short ISO string")


def _v_address(value, spec):
    text = str(value)
    if _MAC_RE.match(text):
        return text
    try:
        ipaddress.ip_address(text)
    except ValueError:
        raise PromptFieldError("ADDRESS %r is neither an IP nor a MAC" % (text,))
    return text


def _v_device_name(value, spec):
    text = str(value)
    if not text.strip():
        raise PromptFieldError("DEVICE_NAME is empty")
    if _NEWLINE_RE.search(text):
        raise PromptFieldError(
            "DEVICE_NAME contains a newline — that is free text wearing a name's "
            "label, and is exactly what this allowlist exists to refuse")
    return text


def _v_domain(value, spec):
    text = str(value).strip()
    if _DOMAIN_RE.match(text):
        return text
    try:                       # a bare IP is a legitimate 'domain_or_ip' value
        ipaddress.ip_address(text)
        return text
    except ValueError:
        raise PromptFieldError("DOMAIN %r is not a valid DNS name or IP" % (text,))


def _v_basename(value, spec):
    text = str(value)
    if "/" in text or "\\" in text:
        raise PromptFieldError(
            "BASENAME %r contains a path separator — a full path routinely "
            "carries a real username (/home/<user>/...)" % (text,))
    if not text or _NEWLINE_RE.search(text):
        raise PromptFieldError("BASENAME is empty or multi-line")
    return text


def _v_hash(value, spec):
    text = str(value)
    if not _HASH_RE.match(text):
        raise PromptFieldError("HASH %r is not a hex digest" % (text,))
    return text


def _v_label(value, spec):
    text = str(value)
    if not text.strip():
        raise PromptFieldError("LABEL is empty")
    if _NEWLINE_RE.search(text):
        raise PromptFieldError("LABEL contains a newline — free text under a label")
    return text


def _v_identifier(value, spec):
    text = str(value)
    if not _IDENT_RE.match(text):
        raise PromptFieldError(
            "IDENTIFIER %r is not a bounded machine token" % (text,))
    return text


_VALIDATORS = {
    LITERAL: _v_literal, ENUM: _v_enum, NUMBER: _v_number,
    TIMESTAMP: _v_timestamp, ADDRESS: _v_address, DEVICE_NAME: _v_device_name,
    DOMAIN: _v_domain, BASENAME: _v_basename, HASH: _v_hash,
    IDENTIFIER: _v_identifier, LABEL: _v_label,
}


def render_field(kind, value, **spec):
    """Validate one value against one kind. Returns the renderable text.

    RAISES on violation -- it never substitutes a placeholder. A placeholder
    would be a legal-looking value standing in for a rejected one, which is the
    failed-read-as-default shape this codebase forbids: the caller could not tell
    a scrubbed field from a real one.
    """
    if kind not in KINDS:
        raise PromptFieldError("unknown field kind %r (spec %s)" % (kind, SPEC_VERSION))
    text = _VALIDATORS[kind](value, spec)
    if len(text) > MAX_FIELD_CHARS:
        raise PromptFieldError(
            "field of kind %s is %d chars; the ceiling is %d"
            % (kind, len(text), MAX_FIELD_CHARS))
    return text


def build(parts):
    """Assemble a BuiltPrompt from an ordered sequence of declared parts.

    Each part is either:
      * a plain `str`  -> LITERAL text authored in source, or
      * a tuple `(label, kind, value)` / `(label, kind, value, spec_dict)`.

    `label` may be None to emit the value with no "Label: " prefix.

    EVERY runtime value must arrive as a tuple with a kind. A caller that
    pre-formats a runtime value into one of the plain strings defeats the whole
    mechanism -- which is why `build()` is not the only defence: `analyze()`
    requires the BuiltPrompt TYPE, and the four machine-generated builders are
    the only things that call this. The spec's §6 conformance list is what keeps
    that set closed.
    """
    out = []
    for part in parts:
        if isinstance(part, str):
            out.append(part)
            continue
        if not isinstance(part, (tuple, list)) or len(part) not in (3, 4):
            raise PromptFieldError(
                "part must be a literal str or a (label, kind, value[, spec]) "
                "tuple, got %r" % (type(part).__name__,))
        label, kind, value = part[0], part[1], part[2]
        spec = part[3] if len(part) == 4 else {}
        text = render_field(kind, value, **spec)
        out.append("%s: %s" % (label, text) if label else text)
    return BuiltPrompt("\n".join(out))
