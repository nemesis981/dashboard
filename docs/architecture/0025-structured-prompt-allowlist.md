# ADR 0025 — Structured prompt allowlist (NPFA/1)

**Status:** Accepted, implemented 2026-08-23
**Supersedes:** nothing. **Related:** ADR 0006 (Data Manager), the pseudonymization
chokepoint in `ai_engine.analyze()`.

> **This document is NORMATIVE.** `alert_manager/prompt_fields.py` is *a* reference
> implementation, not the definition. The spec is written in language-agnostic terms
> so a future non-Python implementation (V3 is expected to be compiled) reimplements
> it rather than reverse-engineering Python. Where the two disagree, the spec wins
> and the implementation is the bug.

---

## 1. Problem

Pseudonymization scrubs what it can **recognise**: network addresses (pattern-detectable)
and device names the deployment knows (supplied from its own tables). It cannot recognise
an identifier inside arbitrary text — there is no pattern for "a name".

So any prompt assembled by interpolating runtime values into a free-form template carries
an open-ended, undetectable disclosure. Better scrubbing cannot close this; the scrubber
is not the weak part. The only way to close it is to make unrecognised content
**structurally unable to enter** a machine-generated prompt.

## 2. Decision

A machine-generated prompt is assembled **only** from declared fields, each carrying a
declared **kind**. Every kind is either

- **safe by construction** — literal text authored in source, a number, a member of a
  finite enumeration; or
- **scrubbed by type downstream** — an address or a device name, which the
  pseudonymization chokepoint tokenizes.

There is deliberately **no free-text kind**. A value that does not fit a kind is
**rejected at build time**, before any sendable string exists.

## 3. Field kinds

| Kind | Accepts | Rejects | Scrubbed downstream |
|---|---|---|---|
| `literal` | text authored in source | non-string | no |
| `enum` | a member of a declared finite set | anything outside it; a missing set | no |
| `number` | integer or real (not boolean) | strings, booleans | no |
| `timestamp` | epoch seconds, or an ISO-8601 string ≤64 chars | multi-line, over-long | no |
| `address` | IPv4, IPv6, or MAC | anything not parseable as one | **yes** |
| `device_name` | bounded single-line name of a thing in THIS deployment | multi-line, empty | **yes** |
| `domain` | DNS name, or a bare IP | malformed names | no — see §5 |
| `basename` | a file basename | any value containing `/` or `\` | no |
| `hash` | hex digest, 8–128 chars | non-hex | no |
| `identifier` | bounded machine token `[A-Za-z0-9._:-]{1,64}` | spaces, punctuation, over-long | no |
| `label` | bounded single-line hardware/vendor/metadata string | multi-line, empty | no |

**Universal rule:** every rendered field is at most **512 characters**. A longer value is
rejected, not truncated.

### 3.1 `label` vs `device_name` — a privacy decision, not a shape one

Both are bounded single-line strings; they are separate kinds because they differ in
**whose identifier** the value is, and that decides whether it gets scrubbed:

- `device_name` names something in **this household** (`Reception-Laptop`) → scrubbed.
- `label` names **hardware or a vendor string** (`Package id 0`, `coretemp-isa-0000`,
  `Composite`) → not scrubbed: it identifies a chip model, not a person, and is identical
  across every deployment with the same hardware.

Collapsing them into one permissive "short string" kind would silently reclassify
household identifiers as hardware metadata. Implementations **must** keep them distinct.

## 4. Enforcement boundary

The outbound chokepoint (one function, through which every model call passes) **must**
reject any prompt that was not produced by the allowlist builder.

The reference implementation carries this proof as a **type** (`BuiltPrompt`, a string
subtype). The essential property is not the type system but this:

> **Tampering must downgrade the proof.** Any ordinary string operation on a built prompt
> — concatenation, slicing, formatting, substitution, case change — must yield a value the
> boundary rejects.

You cannot inspect a finished string and determine which parts were runtime data. The
proof therefore has to travel from where that knowledge exists (assembly) to where it is
needed (the wire). An implementation in a language without string subtyping **must**
achieve the same property by other means — a wrapper struct carrying the field list, a
tagged union, or an authenticated token over the assembled parts. A boolean flag alongside
a plain string is **not** conformant: it does not downgrade under tampering.

Rejection is **fail-closed**: no call is made, and the refusal names the spec version.

### 4.1 What this defends against — stated plainly

The proof defends against **accident**, not against hostile code running in-process. Any
code inside the process can construct the proof type directly; nothing here prevents that,
and nothing could, short of a capability system. What it does prevent is the realistic
failure: a developer adding a field to a prompt, or writing a new prompt-producing surface,
and interpolating a value that turns out to carry an identifier. That is how the gap this
ADR closes actually arose, and it is the failure mode a type catches every time.

Test suites legitimately construct the type directly when exercising a different guard —
the allowlist has its own suite, and forcing every unrelated test through `build()` would
measure the wrong thing.

## 5. Disclosures that are structural, not gaps

Two values are disclosed and **cannot** be pseudonymized without removing the feature that
needs them, because in each case **the identifier IS the question**:

- **`domain`** — asking whether a domain is suspicious requires naming it.
- **the address sent to IP-reputation services** — a reputation lookup cannot be performed
  against a token. (Scope is public addresses only: private, loopback, link-local, and this
  appliance's own public addresses are refused before any call.)

These are permanent characteristics of the feature set, not open work. They are disclosed
in the product privacy notice as such and must not be described as pending.

## 6. Conformance

An implementation conforms when:

1. Every kind in §3 validates as specified, and rejects rather than substituting a
   placeholder. A placeholder is a legal-looking value standing in for a rejected one, and
   the caller cannot distinguish it from real data.
2. The boundary (§4) refuses unstructured prompts, and tampering downgrades the proof.
3. **Exactly one** caller may bypass the boundary — the operator-authored chat surface
   (§7) — and it must pass an explicit, non-empty reason that is logged.
4. Every machine-generated prompt builder assembles via the allowlist. In this codebase
   that set is closed and currently comprises five: anomaly incident analysis, community
   queue assessment, malware Layer C verdict, dashboard alert analysis, and hardware
   sensor discovery.
5. A conformance test asserts (3) by counting production callers, and (4) by source
   inspection. Both are asserted in `alert_manager/test_prompt_allowlist.py`.

## 7. The single exemption

The follow-up chat exists so an operator can type a question — frequently pasted command
output — and have the model reason about it. No allowlist can express "whatever the
operator decided to type"; requiring one there would delete the feature rather than
constrain it.

This is **consented** disclosure, not silent disclosure: a human is composing a message, in
a chat widget, with a visible cost estimate. The chokepoint still scrubs addresses and known
device names from what was typed.

**Residual, stated plainly:** an *unknown* name inside text the operator chose to send is
not scrubbed. It is disclosed in the privacy notice. It is inherent to having a chat
feature at all.

## 8. Consequences

- Adding a field to a prompt now requires choosing a kind. That friction is the point:
  the choice between `label` and `device_name` is a privacy decision, and it is now
  impossible to make it by accident.
- A new prompt-producing surface must build via the allowlist or it cannot send. The
  failure is loud and immediate rather than a silent leak.
- The kind table is a wire contract. Adding a kind is a spec change with a version bump,
  not a local edit.
