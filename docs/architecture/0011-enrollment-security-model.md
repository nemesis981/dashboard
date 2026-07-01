# ADR 0011 — Enrollment Security Model

- **Status:** **ACCEPTED — BUILD-READY** (2026-06-30; all open questions Q0–Q3 resolved, D2
  resolved in [installer-unified-v1.0.6](../roadmap/installer-unified-v1.0.6.md)). Design of
  record; **no code changed by this ADR** — the build lands via the installer-roadmap prompt.
- **Date:** 2026-06-30
- **Numbering note:** the source request named this "ADR-0005," but 0005 is already
  [DNS-firewall / device-auth](0005-dns-firewall-device-auth-architecture.md). Created as
  **0011** to avoid a collision. **RESOLVED (Q0): kept standalone as 0011** — not folded into /
  superseding 0005's device-auth section.
- **Affects:** the installer-baked credentials, `/enroll` + the enrollment payload,
  `enrollment_tokens`, the install-media transport, the owner approval UX.
- **Depends on:** [0005 — device-auth](0005-dns-firewall-device-auth-architecture.md) (the
  `firewall.py` chokepoint + device-auth seam);
  [hardware-stable-identifiers](../roadmap/hardware-stable-identifiers.md) — **now BUILD-NOW**
  (Windows+Linux), the locked design powering the TOFU lock + review-card match.
- **Related:** roadmap [installer-unified-v1.0.6](../roadmap/installer-unified-v1.0.6.md)
  (the build that carries this); [0008 — impossible-travel](0008-impossible-travel-detection.md)
  (deferred geo scoring).
- **Built on by:** [0012 — enrollment trust modes](0012-enrollment-trust-modes.md) — this ADR's
  manual-approval default (`auto_approve = 0`) is the foundation 0012's four-mode system
  (MANUAL / BULK MANUAL / FLEET AUTO / VENUE AUTO) is layered on top of.
- **Evidence base:** PL-6 in `docs/audits/windows-install-doc-test-2026-06-30.md`.
- **Rule 8:** placeholders only (`<tailnet-ip>`, `<token>`, `<preauth-key>`). Baked
  credentials are per-installer secrets — out of all logs/docs/commits.

> Capture only — design of record for how a device proves it may enroll. No code.

## Problem (PL-6)

Enrollment today is a **bearer-token** model. The device keypair is generated **on the
installing machine**, so it is *post-enrollment* identity, **not** enrollment authorization.
Authorization is the **token baked into the installer** — anyone holding live media can
generate their own keypair, present the token, and enroll. Defaults compound it:
`auto_approve = 1` (no human review), and media is served over **:80 HTTP (cleartext)** with
an auth-bypass on `/install/windows/`, so the token is interceptable in transit on a LAN.

## Decision — split into IMMEDIATE / DEFERRED

### IMMEDIATE (build this window)
- **Tailnet-only media + enrollment.** Remove the cleartext `:80` install path; serve media
  and accept `/enroll` over the **tailnet only**. WireGuard then encrypts the transport —
  this alone neutralizes the in-transit token-interception risk.
- **Default enrollment = MANUAL APPROVAL (pending).** Auto-approve becomes a deferred,
  explicit opt-in.
- **Enrollment token:** single-use, **TTL cut to 1–2h**, and **bound to the device fingerprint
  via TOFU** (hardware-stable-ID, now build-now): the first machine to present the token locks
  the fingerprint, so a stolen token won't enroll a *different* machine (Q1 resolved).
- **Tailscale pre-auth key:** single-use, short-expiry, **tagged/ephemeral** (constrained
  ACL), **per-installer**, never reusable or long-lived.
- **Baked credentials = per-installer secrets.** Expired/used → **HARD FAIL, no fallback.**
  Rule-8 out of all logs/docs/commits.
- **ClamAV engine/sig policy (scan-before-trust dependency).** The box serves a **PINNED engine
  (`==` the agent's pinned engine, manual bump only, never auto-updated while pinned agents are
  attached)** and **freely-`freshclam`'d signatures** (newer-engine-reads-older-sigs is normal;
  box holds back only a sig that needs an engine newer than the pinned one — "block the serve,
  not the client"). Full rule:
  [installer-unified-v1.0.6 §D2](../roadmap/installer-unified-v1.0.6.md) **— RESOLVED.**

### Owner enrollment-review checkpoint (informed manual approval)
Before approving, the owner sees a **REVIEW CARD** aggregating signals that **mostly already
exist — this is surfacing, not new detection:**
- **ClamAV scan-before-trust result** — clean vs `pending_with_findings`; foreground it.
- **Server-observed enrolling source** — the **tailnet IP the enrollment connection arrived
  from**. Authoritative and **UNFORGEABLE** "from where."
- **Hardware-stable-ID match** — does the presented device fingerprint match the fingerprint
  the installer's token was generated FOR? **YES / partial (k/n) / NO.** A **NO** = token
  presented from a different machine than intended (stolen/copied-media signature) → flag
  prominently. (TOFU: locks on first enrollment — see [hardware-stable-identifiers](../roadmap/hardware-stable-identifiers.md).)
- **Fingerprint confidence + signal count + `is_virtual`** — strength of the fingerprint and
  whether it's a virtualized environment. **INFORMATIONAL ONLY — NEVER auto-gating.** Per the
  hardware-stable-identifiers **PRINCIPLE** (confidence modulates trust-weight, never
  protection-availability): a low-confidence or virtual device **still enrolls and is fully
  protected** — these signals only tell the owner how much to lean on manual approval + other
  signals. The two conditions (`is_virtual`; low-confidence) surface **separately**.
- **Token metadata** — TTL remaining, single-use status, when/for-whom generated.

Owner action: **APPROVE or REJECT** from the card.

### Geographic signal — decision (security + privacy)
- **TRUST signal = the SERVER-OBSERVED tailnet source IP ONLY** (client cannot forge it).
- **Client-reported geo/locale/timezone = UNTRUSTED.** An actor holding the media controls
  the machine and can spoof it; ~zero anti-theft value. **Not** a basis for trust.
- **Permitted use:** **plausibility cross-check only** — if the client-claimed region
  disagrees with the server-observed IP's implied region, surface the **disagreement** as a
  weak supplementary flag, explicitly labeled **"untrusted / informational."**
- **Privacy:** do **NOT** collect precise location (GPS / WiFi-SSID geolocation / IP-geo
  lookups) from the client — liability for the public product. Coarse locale/timezone for
  the cross-check only; **precise geo collection is avoided — RESOLVED policy (Q2)**, not a
  pending decision.

### Email / invite delivery role — addendum (2026-06-30, capture only)
**ROLE: email is a DELIVERY channel + WEAK CORROBORATION only — NEVER a trust gate.**
- **Delivery.** The dashboard can auto-send the generated installer/link to an
  admin-entered recipient address — replacing today's manual copy-link-and-send. Ties to
  parked **PL-5 / installer-email-delivery**.
- **Corroboration.** The entered recipient ("issued for `<addr>`") surfaces on the
  enrollment review card as **INFORMATIONAL** context at approval — labeled **untrusted**,
  helps catch honest mismatches, **never trust-determining on its own** (same posture as the
  geo cross-check above).
- **Trust still rides ONLY on:** server-observed tailnet IP + TOFU hardware lock + single-use
  short-TTL token + manual approval. Email going astray **cannot enroll anything silently.**
- **SPF/DKIM/DMARC:** apply to **OUTBOUND** support/notification mail (anti-spoof of our own
  domain, deliverability) — explicitly **NOT** a mechanism for verifying enrollment identity.
- **Security note:** automated delivery is **NOT a new risk surface** — it replaces the
  existing manual email path (clipboard + personal mail client) with a controlled, loggable
  one; equal-or-lower exposure.
- **PRIORITY: TIME-PERMITTING admin convenience.** Layered on a trust model that stands
  without it; the install works hand-delivered or auto-sent. Build only if the window has
  room after trip-critical pieces land; otherwise defers cleanly, **blocks nothing.**

### DEFERRED (design here, implement post-trip; SSH-home capable)
- **Keypair pinning after first enroll.**
- **Full token-to-identity binding** (beyond device fingerprint).
- **Out-of-band token delivery.**
- **Optional HTTPS** on any surviving non-tailnet path.
- **Rich geo / impossible-travel scoring** ([ADR 0008](0008-impossible-travel-detection.md)).

## Why this is enough for the trip

Manual approval + the unforgeable server-observed source IP + the scan-before-trust result
give the owner an **informed** approve/reject decision even before token-to-fingerprint
binding is fully built. Tailnet-only transport removes the cleartext interception path.
Auto-approve (the riskiest default) is off.

## Open questions (owner decisions) — ALL RESOLVED 2026-06-30

- **Q0 — ADR numbering — RESOLVED = keep standalone as 0011.** Not folded into / superseding
  0005's device-auth section; 0011 stands on its own (cross-refs 0005 for the chokepoint/seam).
- **Q1 — Token-to-device binding for a clean REMOTE box — RESOLVED = trust-on-first-use.**
  The owner generates the installer before the user's machine exists, so the fingerprint
  (now build-now, [hardware-stable-identifiers](../roadmap/hardware-stable-identifiers.md))
  **locks on first enrollment**; a later presentation of the same token from a different
  machine fails the match (review card → "NO — different machine"). Manual approval +
  unforgeable server-observed source IP is the backstop for media stolen *before* first use.
- **Q2 — Geo/privacy boundary — RESOLVED/CONFIRMED.** Shipped policy = **coarse locale/timezone
  cross-check only, NO precise-location collection**; the **server-observed tailnet IP is the
  trust signal**. Policy text is the "Geographic signal" section above (mirrors roadmap D1).
- **Q3 — Pre-auth key sourcing — RESOLVED = admin-pasted per-installer.** Key is **manually
  generated from the Tailscale console** for now; **API auto-minting is post-trip.** Acceptable
  for trip scope.

## Status / next

**ACCEPTED — BUILD-READY.** Q0–Q3 resolved; D2 (engine/sig alignment) resolved in the
installer roadmap. Next step: the build prompt referencing
[installer-unified-v1.0.6](../roadmap/installer-unified-v1.0.6.md) + this ADR as the single
authority; specify the tailnet-only serving routes (through the ADR 0005 `firewall.py`
chokepoint), the review-card data sources, and the token/pre-auth-key lifecycle.
