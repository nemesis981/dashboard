# ADR 0026 — RBAC Learning Gate (per-capability delegated authorization)

- **Status:** **Accepted, 2026-08-23. Partially implemented, 2026-08-23.** Resolves the four
  decisions the roadmap left open so a build could start.
  **Landed:** D1 (`sub_admin` rank inserted into `roles.py`, proven additive by
  recomputing all 2,700 pre-existing (role, endpoint, method) answers against the frozen
  3-role ordering — zero differences, pinned in the import-time canary) and D2
  (`CAPABILITY_ROUTES` declared with `push_and_run`/`firewall_change`/`approve_enrollment`
  all still empty, `may_with_unlocks()`, `assert_capabilities_sane()`), the
  `user_capability_unlocks` schema (§5), the hand-authored quiz engine (D4) with one real
  quiz (`push_and_run`), and the unlock read/write/invalidation lifecycle
  (`alert_manager/{roles,capabilities,quizzes}.py`).
  **Not yet landed:** D3 (the admin companion-app key-pair and inner-envelope signing),
  any UI (no quiz-taking page, no unlock display, no settings route), and — as a direct
  consequence of D2's capabilities all still being empty — no capability currently grants
  anything and this ADR's code so far changes **no live behavior**. The private build spec
  (`docs/roadmap/rbac-learning-gate-build-spec.md`, held per the Rule 10 split below — a
  public reader following this sentence's original wording would find nothing) sequences
  what remains.
- **Date:** 2026-08-23
- **Graduates:** `docs/roadmap/dashboard-roles-access-control.md` (the design of record,
  which names this ADR as its own next step) and
  `docs/roadmap/diagnostics-and-access-master-plan.md` §5.
- **Extends:** [0007 — Device-User Relationship Model](0007-device-user-model.md) — this is
  its dashboard-role dimension.
- **Depends on:** [0001 — database/module architecture](0001-database-and-module-architecture.md)
  (prefix ownership, canonical DDL); [0006 — Data Manager](0006-data-manager.md) (all writes,
  actor seam); [0004 — scan-task orchestration](0004-scan-task-orchestration.md) Stage 1 step 2
  (`nemesis_agent/tasks.py`, the existing server→agent envelope signing).
- **Related:** [0011 — enrollment security](0011-enrollment-security-model.md) (considered as
  the key-pair source and **rejected** — see D3); `docs/roadmap/ai-generated-tutorial-walkthrough.md`
  (a later content source for D4, deliberately **not** a build dependency);
  [0027 — agent attestation manifest format](0027-agent-attestation-manifest-format.md),
  whose **`attested` does not mean `trusted`** principle this ADR follows: D3 claims
  hardware backing for the *key* only, never trustworthiness of the device holding it, and
  names a fully compromised phone as explicitly **not** closed.
- **Rule 8:** placeholders only. No real accounts, hosts, or keys.

> **Rule 10 — disclosure decision RESOLVED (operator, 2026-08-23).** This ADR describes a
> plausibly novel mechanism (earning individual security capabilities through a training
> gate, which the roadmap itself identifies as a commercial differentiator) and contains
> explicit honest-limitation language about what the approval layer does *not* defend
> against (D3, "What this does and does not protect against").
>
> **The split:** this ADR — general architecture, tier structure, the existence of the
> capability, and the honest limitations — publishes **public**. The normative wire protocol
> specification and the build spec are held **private until the build lands and is verified**;
> publishing them is revisited once built and mutation-tested, not before.
>
> This is a source-visibility question only and is **never** a feature-availability or
> pricing gate.

---

## 1. Problem

`alert_manager/roles.py` shipped 2026-08-22 with a flat, linear model: `viewonly` < `user`
< `admin`, enforced for every request by a `before_request` gate. It works and is
independently verified, but it has exactly one lever — a single rank per account.

The product needs **delegation without full trust**: a small-business owner adds an
assistant manager who needs genuine daily-ops access, but should not be able to break
things on day one. The roadmap's answer is a middle tier that **earns** dangerous
capabilities one at a time by completing that capability's training.

Four things were left explicitly unspecified, and each one blocked a build. This ADR
resolves all four.

---

## 2. What already exists (verified against code 2026-08-23, not assumed)

| Thing | State |
|---|---|
| `roles.py` linear model + 135-entry registry | **Shipped.** Pure decision layer — no Flask, no DB, no I/O; 48-case canary asserted at import |
| `before_request` enforcement covering every live endpoint | **Shipped.** A decorator-only design would miss the module-registered routes, which cannot be decorated from `dashboard.py` |
| `users.role` column, `'admin'|'user'|'viewonly'` | **Shipped**, DEFAULT `'admin'` for pre-RBAC installs |
| `assert_registry_complete()` (missing AND phantom entries) | **Shipped** |
| Server→agent envelope signing, per-device pinned anchor, fails closed, rotation | **Shipped** — `nemesis_agent/tasks.py` |
| `keyprotect` TPM-backed key storage (Linux tpm2-tools, Windows CNG/PCP) | **Shipped** `fdda6f5` |
| `push_and_run`, `firewall_change`, `approve_enrollment` capabilities | **Do not exist** — zero occurrences repo-wide |
| Any quiz or tutorial mechanic | **Does not exist** — `quiz` appears only in two roadmap docs |

The last two rows are why this had to be a spec before it could be a build.

---

## 3. The decisions

### D1 — Tier semantics: INSERT a rank, keep `may()` I/O-free

**Decision.** `ROLES` becomes `(viewonly, user, sub_admin, admin)` — a fourth value
inserted between `user` and `admin`, not a replacement of the shipped three. The roadmap's
"USER" tier maps onto the shipped `viewonly` + `user` pair, which is a finer-grained
decomposition of the same idea; the roadmap explicitly permits "or an equivalent".

A `sub_admin` is **exactly `user`, plus whatever capabilities they have unlocked.** The
base rank grants nothing an ordinary `user` lacks. All elevation is per-capability.

**The signature question, and why the answer matters.** Today `may(role, endpoint, method)`
is a pure function of role. Capability unlocks are per-*user*, so the obvious move is to
have `may()` read them — which would put a DB read inside `roles.py` and destroy the
property that makes it trustworthy: it currently has no I/O, so its 48-case canary can run
at import in the production path.

Instead, unlocks are **passed in**:

```
may(role, endpoint, method)                     # unchanged; "can this ROLE alone do it?"
may_with_unlocks(role, unlocks, endpoint, method)  # unlocks = an explicit frozenset
```

The gate reads unlocks from the DB and hands them in. `roles.py` stays a pure decision
layer, stays canary-testable at import, and the DB read stays in the one place that
already does I/O. **Do not "simplify" this later by having roles.py fetch its own unlocks.**

**Fail-closed, in four directions** (each must be pinned by a mutation test):
- unknown endpoint → `admin` (already true; unchanged)
- unparseable role → **raise**, never default (already true; `users.role` DEFAULTs to
  `'admin'`, so any fallback promotes a corrupt row to superuser)
- unknown capability name → **raise**, never "not unlocked". A typo'd capability that reads
  as merely-locked is the `_AUTH_EXEMPT` failure mode again: it looks like coverage and
  protects nothing
- unlock row present but unparseable (bad timestamp, bad version) → **treat as not
  unlocked, and log loudly.** Deny is the safe direction here, unlike role parsing, because
  the failure removes access rather than granting it

### D2 — Capability→route mapping: named endpoint sets, declared once, asserted

**Decision.** A capability is a **named set of endpoints**, declared beside
`ROUTE_MINIMUMS` in `roles.py`:

```
CAPABILITY_ROUTES = {
    "push_and_run":       frozenset(),   # declared, not yet built
    "firewall_change":    frozenset(),
    "approve_enrollment": frozenset(),
}
```

Four rules, all mechanically checked:

1. **An endpoint belongs to at most ONE capability.** Two capabilities covering the same
   route makes "which unlock applies" unanswerable the moment they disagree.
2. **Every endpoint named by a capability must exist**, checked by extending
   `assert_registry_complete()`. This is the phantom-entry rule that already exists for
   `ROUTE_MINIMUMS`, applied to the same failure in a new place.
3. **A capability may only name endpoints whose unsafe minimum is `admin`.** A capability
   that elevates to something a `user` already has is decoration, and a reader would
   reasonably assume it was doing something.
4. **An EMPTY capability is legal and means "declared but not built yet"** — which is the
   honest state of all three today. It must be *visibly* distinguished in the UI from a
   built one, or the product offers training that unlocks nothing. `capability_state()`
   returns `DECLARED` vs `BUILT` and the UI must render them differently.

Starting all three empty is deliberate: it records the roadmap's intent without inventing
route names for features that do not exist. Each fills in when its feature is built.

### D3 — Key-pair mechanism: a COMPANION APP holds the admin key; the phone approves

**Decision (operator, 2026-08-23). The admin private key lives in a companion app on the
operator's phone. The appliance never holds it.** A dangerous action raises an approval
request; the phone displays what is being approved; the operator authenticates locally; the
phone signs; the appliance verifies. **Mint a new admin key pair. Do NOT reuse ADR 0011's
enrollment keys.**

This supersedes the earlier appliance-held proposal and **closes** the appliance-compromise
limitation that shape carried: an attacker with root on the appliance can no longer sign as
the admin, because there is nothing there to sign with.

ADR 0011's keypair is generated *on the installing machine* and, in that ADR's own words,
is "post-enrollment identity, **not** enrollment authorization." It answers **which
device**. The gate needs to answer **which human authorized this specific action.** Reusing
it would be a category error that reads as reuse.

`tasks.py`'s existing signing is likewise the right *transport* and the wrong *subject*: its
per-device pinned anchor proves **the server** to the agent. It does not distinguish an
action a genuine admin ordered from one the server was tricked into sending.

So the layers compose rather than compete — **two signatures answering two questions**:

- **Outer envelope — existing `tasks.py` server key:** "did this come from the real server?"
- **Inner authorization — companion-app admin key:** "did a specific, capability-unlocked
  human approve this exact action, just now, on their own device?"

The agent verifies the outer signature as it does today; the inner one is verified
server-side at the gate and recorded for attribution.

**The wire protocol is specified separately and normatively** — signature scheme,
byte-level message format, and ordered verification steps, defined without reference to any
implementation language. That specification is **held privately until the build lands and
is verified** (Rule 10 decision, 2026-08-23); publishing it is revisited once it is built
and mutation-tested, not before. See D5 for why the separation exists at all.

#### Push is a hint, never a channel of authority

The push notification carries **no authorization payload and no trust**. It is a wake-up
hint. The companion fetches the actual request from the appliance over an authenticated
channel and verifies it independently.

Three things follow, and all three are requirements:
- The push payload **must not** contain the action detail — it lands on a lock screen.
- A dropped, delayed, or duplicated push must never change the outcome; the companion
  **must** also work by polling.
- Because push is non-authoritative, **platform push differences degrade gracefully**
  rather than breaking the protocol. This is what makes the platform sequencing in D6
  possible at all.

#### The three hardening requirements (operator-mandated; core, not optional)

**H1 — Context display AND number matching. These defend different things; both are
required.**

*Context display* answers "do I understand what I am approving?" The companion renders the
actual action — `Disable malware_detection on <device>?` — never a bare "Approve?".

*Number matching* answers "did I initiate this?" The appliance displays a short code; the
companion offers several and the operator must pick the matching one. An attacker who can
trigger a request cannot tell the operator which number to tap. Context display alone does
not stop a reflexive approval of a genuine-looking request the operator did not start.

*Honest limitation:* the platform biometric dialog cannot render arbitrary application
text, so context and number matching are drawn by **our** UI. A fully compromised phone
could therefore display one action while the operator signs another. What survives that
attack is the protocol itself: the signature covers the real action, so the appliance can
always prove *what was actually authorized* — a display-integrity failure, not a protocol
break. Do not describe H1 as more than this.

**H2 — Rate limiting, lockout, and burst alerting (MFA-fatigue / push-bombing defence).**

A burst of approval requests **must itself raise an alert**, not merely queue. Three
non-obvious requirements:

- **The alert must not travel on the channel being flooded.** Alerting about push-bombing
  with more pushes is useless. It routes through the notification path as **CRITICAL**,
  which `alert_manager/notify.py:route()` already guarantees is never deferred into a
  digest, plus a dashboard banner.
- **Throttle request CREATION, never approval of an already-pending request.** A lockout
  that blocks the operator from approving hands an attacker a denial of admin capability
  by spamming. Rate-limit the initiating side; leave the human's side unimpeded.
- **Lockout is time-bounded and clearable from the appliance console.** A permanent lock
  is an unrecoverable brick, which is a worse failure than the one it prevents.

Pending requests expire on a short TTL so a stale queue cannot be approved later.

**H3 — Per-approval user verification, enforced by the KEY, not by the UI.**

Every individual approval requires a fresh biometric/PIN — not one app unlock covering a
session. The requirement must be a property of the key material (WebAuthn
`userVerification: "required"`; Android Keystore per-use authentication, **not** a
time-windowed validity duration), so a compromised app cannot simply skip the prompt.

**The appliance MUST independently verify the user-verification flag on every signature
and reject one that lacks it.** A UV requirement the server does not check is a UV
requirement that does not exist — the client would be free to omit it and nothing would
notice. This is the same standing principle as the canary rule: a check that cannot fail
is not a check.

#### Pairing, and the circular dependency it would otherwise create

Registering a companion is done from an already-authenticated admin session with console
access. **Companion pairing is explicitly NOT itself a capability requiring companion
approval** — that would deadlock a fresh install, where no companion exists yet to approve
the pairing of the first companion. Call this out in the build; it is exactly the kind of
circularity that is discovered at integration time.

**At least two authenticators must be registered before any capability can be unlocked.**
A single registered phone is a silent single point of failure: lose it and every
capability becomes permanently unreachable. A console-based break-glass path exists and is
audit-logged loudly.

#### What this does and does not protect against

Closes: stolen session cookie, CSRF, compromised browser, **and — unlike the earlier
appliance-held proposal — full appliance compromise**, since the signing key is not on the
appliance at all.

Does not close: a fully compromised *phone* (see H1's limitation), and coercion of the
operator. Both are out of scope and must not be claimed otherwise.

### D5 — The appliance-side protocol is specified language-agnostically

**Decision (operator standing principle, 2026-08-23).** The approval protocol's signature
scheme, message format, and verification logic are specified as a **versioned wire
contract**, independent of any server implementation language — not as "whatever the Python
happens to do." That contract is a separate document, currently held privately pending
build verification (see D3).

**Why this is a design constraint and not documentation polish.** V3 is expected to move
off Python to a compiled language. Anything solidified correctly now is work V3 does not
redo; anything left implicit becomes a redesign under new constraints, and a protocol
redesign silently invalidates every already-paired companion in the field.

Two concrete consequences, both load-bearing:

- **Nothing signs JSON.** Canonical-JSON is a well-known cross-language trap — key
  ordering, number formatting, and unicode escaping all differ between implementations, so
  a signature produced by one language fails to verify in another for reasons that are
  invisible in the source. The signed payload is an explicit length-prefixed byte encoding
  with a domain-separation prefix and fixed-width big-endian integers.
- **Algorithms are named by COSE identifier** (RFC 9052), not by library-specific names, so
  the verifier selects on a stable numeric constant that means the same thing in every
  language.

It is kept as a standalone protocol document rather than folded into this ADR deliberately:
an ADR records *why a decision was made*, while that is a *contract a reimplementation must
match byte for byte*. Conflating the two is how the contract quietly acquires Python-shaped
assumptions. Its eventual home is `docs/protocol/`, once the Rule 10 hold is lifted.

### D6 — Platform sequencing: PWA/WebAuthn first, native Android next, iOS free

**Decision.** The protocol is platform-agnostic by construction (D5). For shippable v1,
build the **PWA + WebAuthn** approval flow first, with a native Android app as the
follow-on if richer push is wanted. iOS requires no separate track.

**Why PWA/WebAuthn rather than Android-native first**, given the operator's preference for
whichever avoids app-store gating and ships soonest:

- **No app-store gating on any platform** — neither Google Play nor the App Store is in the
  path.
- **WebAuthn satisfies H3 structurally**, not by convention: hardware-backed keys with
  per-assertion user verification, and a UV flag the appliance verifies server-side.
- **It is a published standard**, which is the cleanest possible expression of D5's
  language-agnostic requirement.
- **It unblocks iOS immediately.** Safari supports WebAuthn/passkeys **without** the Apple
  Developer Program. The Program is required for a native App Store agent, which is why the
  full Apple agent is correctly scoped to V3.0 — but that constraint **does not apply to a
  browser-based approval flow.** iOS approval need not wait for V3.0.

**Verified prerequisite — this is a real blocker, not a detail.** WebAuthn requires a
secure context, and its Relying Party ID **must be a domain name; an IP address can never
be a valid RP ID.** The appliance today is served by nginx over **plain HTTP on port 80
with a bare LAN IP as `server_name`** (verified 2026-08-23). As it stands, WebAuthn cannot
run at all.

The resolution is available and aligns with ADR 0011's existing tailnet-only posture:
Tailscale MagicDNS already provides a real hostname (`<host>.<magicdns-suffix>`), and
Tailscale can issue a publicly-trusted certificate for it. **HTTPS certificates are not
currently enabled on this tailnet** (`CertDomains` is empty, verified 2026-08-23), so the
prerequisite is: enable that feature, obtain the cert, and add a TLS server block.

**If that prerequisite is rejected, the fallback is native-Android-first**, which can pin
its own trust and sidesteps browser secure-context rules entirely — at the cost of losing
the free iOS path above. That is the trade; it should be made deliberately.

*Related observation, flagged not fixed (out of scope here):* because the dashboard is
served over cleartext HTTP today, session cookies cross the LAN unprotected — which makes
the session-theft threat this whole layer defends against **more** likely, not less.
Worth its own pass.

### D4 — Quiz mechanics: statically authored, versioned, 100%-to-pass, unlimited retakes

This is the decision that unblocks everything else, so the reasoning matters.

**The roadmap ties the quiz to the AI-tutorials plan — and that plan is unbuilt and contains
no quiz concept at all.** Read end to end, `ai-generated-tutorial-walkthrough.md` specifies
tiered walkthroughs, a `tutorial_index` table and natural-language search. No questions, no
scoring, no unlock mechanic. Waiting for it would block this indefinitely on a dependency
that would not deliver the needed piece even when built.

**The unlock is that the dependency is only load-bearing if the quiz must be *generated*.**
It does not have to be:

**Decision. v1 quizzes are statically authored per capability**, versioned, stored beside
the capability declaration — not AI-generated. The AI-tutorials system, when it exists,
becomes a **content source** that can supply questions and the accompanying tutorial; it is
explicitly **not a build dependency**.

Authoring them by hand is also the safer choice on its own merits: a generated quiz about a
dangerous capability that hallucinates a wrong "correct" answer would actively teach the
wrong thing, and the failure would be invisible — the user passes, unlocks, and holds a
confident misunderstanding of a capability that can break the network.

**Pass mark: 100%, with unlimited retakes and the reasoning shown after a wrong answer.**
Not an arbitrary bar. A partial threshold (say 80%) means someone can unlock a dangerous
capability while demonstrably not understanding one of its points — and nothing records
*which* point. Since this is a teaching device rather than an exam, and since the roadmap is
explicit that it proves competence and **not** authorization, there is no reason to allow
permanent failure: retake until every point is understood. Short sets (3–5 questions) keep
that humane.

**Versioning, and why unlocks expire.** Each quiz carries a `quiz_version`. When a
capability's behaviour changes, its quiz version bumps and **every existing unlock for that
capability is invalidated and must be re-earned.** Without this, training silently goes
stale while the UI continues to assert the user was trained — the same stale-claim failure
class this codebase has repeatedly been bitten by. `quiz_score` records the passing
attempt's score (always 100 under the above) alongside the attempt count, so the column the
roadmap specified keeps a defined meaning.

---

## 4. The critical boundary (restated, because it is the thing most likely to be misread)

**The learning gate proves COMPETENCE, not AUTHORIZATION.** A quiz stops an untrained
delegate from firing a dangerous task by accident. **It does not inconvenience an attacker
at all.** It is one layer of defence-in-depth layered *on top of* real authorization; it
never replaces it.

A dangerous action requires **ALL** of:

| | Requirement | Enforced by |
|---|---|---|
| (a) | correct **role tier** | `roles.py` + the `before_request` gate |
| (b) | **capability unlock** for that specific capability (sub-admins only) | `user_capability_unlocks` + `may_with_unlocks()` |
| (c) | **admin key-pair signature** over this exact action | D3's inner signature |
| (d) | *(agent side, separate layer)* per-device **consent** | the agent's own opt-in config |

**Missing any one → NO action.** A FULL ADMIN is ungated on (b) only; (a), (c) and (d) apply
to everyone.

---

## 5. Storage

Core-owned, unprefixed (it belongs with `users`), canonical CREATE in
`alert_manager/database.py`, guarded `PRAGMA table_info` + `ALTER` migration per ADR 0001.
All writes route through the Data Manager with the actor stamped, per ADR 0006.

```sql
user_capability_unlocks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,      -- users.id
    capability    TEXT    NOT NULL,      -- must be a key of CAPABILITY_ROUTES
    unlocked_at   TEXT    NOT NULL,
    quiz_version  TEXT    NOT NULL,      -- invalidates the unlock when it changes
    quiz_score    INTEGER NOT NULL,      -- the PASSING attempt's score
    attempts      INTEGER NOT NULL DEFAULT 1,
    granted_by    TEXT,                  -- actor seam: who/what recorded this
    UNIQUE(user_id, capability)
)
```

`UNIQUE(user_id, capability)` makes a re-earn an upsert rather than a second row, so
"is this unlocked" can never be ambiguous.

---

## 6. Build order — this is a sequencing constraint, not a preference

The roadmap's own phasing puts key-pair authorization **before** the learning gate, and the
master plan adds: *"Do NOT wire push-and-run before both exist."* That ordering holds:

1. **(done)** flat role enforcement — shipped 2026-08-22
2. **D3 admin key-pair** — mint, store via `keyprotect`, sign/verify, inner-envelope
   integration with `tasks.py`
3. **D1 + D2** — the `sub_admin` rank, `CAPABILITY_ROUTES`, `may_with_unlocks()`, the
   extended `assert_registry_complete()`, the storage above
4. **D4** — quiz authoring format, delivery UI, unlock recording, version invalidation
5. **Only then** — build an actual capability (`push_and_run` first) and populate its
   endpoint set
6. Finer admin granularity **only if a real need emerges**

Steps 2 and 3 are independent of each other and may run in parallel; step 5 depends on all
of 2–4.

---

## 7. Verification required before any of this is called done

- **Mutation tests on every fail-closed direction in D1** — a check that has never been
  seen to fail is a check that has never been tested. Each mutation must be confirmed to
  break the suite by re-injecting it.
- **A control asserting the unmutated source passes first**, so a mutant that dies of an
  unrelated import error is not counted as caught.
- **Live HTTP assertions, not just unit logic** — log in as a real `sub_admin` with and
  without an unlock and assert actual status codes. A correct table and a gate that never
  reads it would both pass a pure-logic test.
- **Route-security audit** (standing practice) on every `dashboard.py`/route/template change
  this produces, output to the private mirror.
- **`assert_registry_complete()` extended to capabilities** and run against the live
  `url_map`, not a hand-maintained list.

---

## 8. Rejected alternatives

- **Reusing ADR 0011 enrollment keys for D3** — wrong subject (device, not human). §3 D3.
- **Waiting for the AI-tutorials plan before building D4** — it is unbuilt, has no quiz
  concept, and would not supply one even when complete. §3 D4.
- **AI-generated quizzes in v1** — a hallucinated "correct" answer teaches a confident
  misunderstanding of a dangerous capability, invisibly. §3 D4.
- **Having `may()` read unlocks from the DB** — destroys `roles.py`'s I/O-free property and
  its import-time canary. §3 D1.
- **Shipping `sub_admin` now with quiz deferred** — a `sub_admin` with no unlockable
  capabilities behaves identically to `user`, so it delivers nothing while forcing all 134
  registry entries to be re-reasoned about. This is why the tier ships in step 3 and not
  before.
