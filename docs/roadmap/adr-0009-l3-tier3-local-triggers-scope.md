# ADR 0009 — Tier 3 client-side local triggers (scope, not estimate)

**Status:** scoping doc (read-only analysis; no code changed). Captured 2026-07-25, same
session as [tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md)
and [adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md). Named
**Tier 3** in the [ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) §0/§7 —
a short, fixed, **always-on** list of local, immediate agent actions that fire in milliseconds,
without a server round-trip, to interrupt ransomware/malware that got past Tiers 1 and 2 before
damage becomes irreversible.

> **This is a LIVING LIST, NOT A LOCKED SPEC.** Which triggers below ship, get tuned, or get
> dropped is **TO BE DECIDED DURING BUILD/TESTING**, not resolved now. Keep the full candidate
> list — do not pre-filter based on today's confidence guesses.

## 1. Why a local trigger is necessary

Ransomware's most damaging actions — shadow-copy/backup deletion, mass file encryption —
typically happen in a tight window after a payload executes, often preceded by anti-recovery
steps (deleting Volume Shadow Copies, disabling backup services) specifically so the victim
can't roll back once encryption starts. By the time agent telemetry reaches the server and a
verdict returns, the window has usually already closed. **This is the one case in the whole L3
design where "sensor only, judgment is server-side" cannot hold literally** — a server
round-trip is simply too slow to matter.

## 2. The ADR 0009 §3 exception — resolved, not a numbering error to repeat

**Correction for the record:** the source design-capture session referred to this conflict as
being with "ADR 0011." That's inaccurate — ADR 0011 is the Enrollment Security Model and
contains no sensor-only language at all. **The actual hard principle lives in the [ADR 0009
addendum §3](../architecture/0009-security-inspection-proxy.md)** ("the agent is a sensor and
enforcement point ONLY"), which is what Tier 3 actually conflicts with and is amended against.
This doc and the ADR 0009 addendum are the authoritative pair — treat any reference to "ADR
0011" for this exception as a mis-numbering.

The conflict itself is real: a canary-file-touch or shadow-copy-deletion trigger that blocks a
process locally, without waiting for a server verdict, is the agent making a local
classification. Two ways to resolve it were considered:

- **Option A — narrow, explicit exception.** ADR 0009's principle is amended to state that the
  agent may act unilaterally ONLY on a short, fixed, pre-approved list of near-zero-false-
  positive triggers (§3 below). Nothing else is ever judged locally.
- **Option B — reword the principle.** Restate the sensor-only language to distinguish
  "investigating/judging ambiguous traffic" (always server-side) from "executing a fixed,
  pre-defined emergency stop on an unambiguous signal" (locally permitted).

**RESOLVED 2026-07-25: both apply, gated by the Tier 2/3 toggle state — not an either/or.**
Since Tier 2/3 are user-facing toggles rather than one fixed mode: when a deployment has Tier 3
toggled OFF, the agent remains a pure telemetry sensor/enforcement point exactly as ADR 0009 §3
currently states — no change to that case. When Tier 3 is toggled ON, the agent may act
unilaterally ONLY on the enumerated trigger list below (Option A's structure) — nothing else is
ever judged locally. Option B's framing (distinguishing "judging ambiguous traffic" from
"executing an unambiguous emergency stop") is the *doctrine* explaining why the exception is
safe; Option A's concrete enumerated list is the *auditable implementation* of it. **This
question is resolved — not left open** (unlike most of this document).

## 3. The initial trigger list (Option A's enumerated exceptions)

This list is deliberately short and each entry must be near-zero-false-positive before it's
added.

1. **Shadow-copy/backup deletion attempt** — e.g., a process invoking `vssadmin delete shadows`,
   disabling Windows backup services, or bulk-deleting/encrypting files in known backup/NAS
   share locations. Almost no legitimate software does this; it is one of the highest-confidence
   ransomware indicators that exists, and it typically precedes mass encryption.
2. **Canary/decoy file touch** — a small number of fake files planted in common locations
   (Documents, Desktop, common share paths) that no legitimate process ever touches. Any
   write/rename/encrypt event on one is a near-certain signal, and it fires during the early
   files of a mass-encryption sweep rather than after all of them.
3. **Mass file-operation behavioral pattern** — a process opening/rewriting/renaming a large
   number of files across multiple directories in a short window, especially with high-entropy
   output. **Higher potential false-positive rate than 1 or 2** (legitimate bulk operations —
   backup software, media re-encoding, archive extraction — can look similar). **TBD — to be
   decided during build/testing whether this makes the enforced list.** Keep it in the
   candidate set regardless of today's confidence guess about it.

**Explicitly NOT in scope for local action:** process lineage anomalies (unusual parent process
spawning a child) are a real signal but are judgment calls, not unambiguous triggers — these
stay server-side and feed the Tier 1 behavioral trigger engine
([adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md)), not the
local trigger list.

## 4. What the local action actually does

On trigger: **block/freeze the responsible process and the specific write immediately, alert,
and hand off to the server for confirmation and forensics AFTER the fact.** The server does not
authorize the block in real time — it can only confirm, escalate, or (rare) clear a false
positive after the fact. This preserves "all judgment is server-side" for every case except the
enumerated triggers, where the server's role shifts from real-time authorizer to after-the-fact
investigator.

## 5. New dependencies (added 2026-08-04) — this doc still covers more ground than it did

This remains a living list. These four items don't resolve anything above — they change what
the eventual trigger list has to account for, and are recorded here so they aren't rediscovered
independently later.

1. **The QUIC/HTTP-3 decision changes Tier 3's burden directly.** Tier 2 — including its hybrid
   inline/mirror gate — does not prevent an undetected zero-day payload from reaching its
   destination on a clean-looking first chunk; Tier 3 is the named backstop for exactly that case
   (§4 above). If QUIC traffic were left unblocked, HTTP/3 bypasses Tier 2 entirely and
   correspondingly more load falls on Tier 3 as the only remaining catch layer for that traffic.
   Blocking QUIC (see
   [tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md), Piece K)
   narrows that back down. The QUIC decision should be settled before finalising this doc's
   trigger list, since it changes the threat surface the list is written against.
2. **Ownership needs resolving against the memory-injection detection work.** Both this doc and
   `memory-injection-detection-design.md` cover adjacent ground — a payload that executes locally
   after getting past Tiers 1/2 — with two different documents and two different statuses (this
   one a live, always-on living list; that one paused/capture-only). Which one owns the
   executing-payload case needs deciding before either resumes in earnest, or this list risks
   being built against paused scaffolding while the other doc's scope quietly covers the same
   ground from a different angle.
3. **Depends on the agent observation-layer foundation, and hard-depends on agent integrity
   attestation specifically.** A Tier 3 trigger's entire value is that it fires on a signal the
   agent itself observed — but if the agent's own code has been replaced, that signal is exactly
   as trustworthy as the agent that's reporting it, which today is not trustworthy at all: there
   is no agent self-integrity check anywhere in the product. A local trigger whose signal comes
   from a potentially-replaced agent inherits that problem wholesale, not partially.
4. **New threat-model entry: an activity-gated UDP grant is a plausible C2 channel.** (See the new
   UDP policy scoping doc.) It opens on demand, closes on idle so it leaves less residue than an
   always-open port, and blends with ordinary game traffic — properties that make it attractive
   to an attacker, not just to a legitimate application. Recording this here, in the threat model
   this list is scoped against, rather than letting it be discovered independently once that
   feature exists.

## Open items (TBD during build/testing, not blocking gates)
1. **Trigger #3 (mass file-operation pattern):** keep/tune/drop — decided empirically during
   build and testing, not here. See §3 above.
2. **No target hardware baseline exists yet** — same open item as the ADR 0009 addendum and the
   Tier 2 (TLS) scoping doc; a local trigger's latency/resource budget on the actual target
   hardware isn't measurable without one.

These are intentionally left open in this document — testing during the build may drive the
answers rather than a decision made in advance.

## Cross-references
[ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) §0 (names this **Tier 3**)
and §3 (the sensor-only principle this doc's §2 amends, with the narrow exception stated there
too — this doc is the detailed backing for that amendment, not a duplicate of it),
[adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md) (Tier 1 — where
process-lineage anomalies and other ambiguous signals stay, per §3 above),
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) (Tier 2 — a
separate, toggleable tier; Tier 3 is always-on regardless of Tier 2's state; Piece K there is the
QUIC dependency named in §5.1),
[memory-injection-detection-design.md](memory-injection-detection-design.md) (the ownership
question in §5.2 — adjacent ground, two docs, needs resolving),
[agent-rebuild-config-driven.md](agent-rebuild-config-driven.md) (the agent integrity
attestation + observation-layer foundation §5.3 hard-depends on).
