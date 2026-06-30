# ADR 0011 — Enrollment Security Model

- **Status:** Proposed (direction decided 2026-06-30; design captured, **no code changed**).
- **Date:** 2026-06-30
- **Numbering note:** the source request named this "ADR-0005," but 0005 is already
  [DNS-firewall / device-auth](0005-dns-firewall-device-auth-architecture.md). Created as
  **0011** to avoid a collision. *Owner decision pending:* keep as standalone 0011, or fold
  into / supersede 0005's device-auth section (see Open questions Q0).
- **Affects:** the installer-baked credentials, `/enroll` + the enrollment payload,
  `enrollment_tokens`, the install-media transport, the owner approval UX.
- **Depends on:** [0005 — device-auth](0005-dns-firewall-device-auth-architecture.md) (the
  `firewall.py` chokepoint + device-auth seam);
  [hardware-stable-identifiers](../roadmap/hardware-stable-identifiers.md) — **now BUILD-NOW**
  (Windows+Linux), the locked design powering the TOFU lock + review-card match.
- **Related:** roadmap [installer-unified-v1.0.6](../roadmap/installer-unified-v1.0.6.md)
  (the build that carries this); [0008 — impossible-travel](0008-impossible-travel-detection.md)
  (deferred geo scoring).
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

### Owner enrollment-review checkpoint (informed manual approval)
Before approving, the owner sees a **REVIEW CARD** aggregating signals that **mostly already
exist — this is surfacing, not new detection:**
- **ClamAV scan-before-trust result** — clean vs `pending_with_findings`; foreground it.
- **Server-observed enrolling source** — the **tailnet IP the enrollment connection arrived
  from**. Authoritative and **UNFORGEABLE** "from where."
- **Hardware-stable-ID match** — does the presented device fingerprint match the fingerprint
  the installer's token was generated FOR? **YES/NO.** A **NO** = token presented from a
  different machine than intended (stolen/copied-media signature) → flag prominently.
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
  the cross-check only; **precise geo deferred/avoided pending an explicit privacy decision**
  (Open question Q2).

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

## Open questions (owner decisions)

- **Q0 — ADR numbering:** standalone **0011**, or fold into/supersede 0005's device-auth
  section? (Created as 0011 to avoid collision; trivially renumbered.)
- **Q1 — Token-to-device binding for a clean REMOTE box — RESOLVED = trust-on-first-use.**
  The owner generates the installer before the user's machine exists, so the fingerprint
  (now build-now, [hardware-stable-identifiers](../roadmap/hardware-stable-identifiers.md))
  **locks on first enrollment**; a later presentation of the same token from a different
  machine fails the match (review card → "NO — different machine"). Manual approval +
  unforgeable server-observed source IP is the backstop for media stolen *before* first use.
- **Q2 — Geo/privacy boundary:** confirm "coarse locale/timezone cross-check only, no precise
  geo collection" as the shipped policy (mirrors roadmap D1).
- **Q3 — Pre-auth key sourcing:** admin-pasted per-installer now; confirm acceptable until
  API auto-minting lands post-trip.

## Status / next

Proposed. Build only after the owner resolves Q0–Q3. Next step: the build prompt referencing
[installer-unified-v1.0.6](../roadmap/installer-unified-v1.0.6.md) + this ADR as the single
authority; specify the tailnet-only serving routes (through the ADR 0005 `firewall.py`
chokepoint), the review-card data sources, and the token/pre-auth-key lifecycle.
