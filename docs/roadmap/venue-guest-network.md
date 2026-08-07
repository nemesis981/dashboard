# Roadmap stub — Venue guest network: the agent AS the credential

**Status:** parked (concept capture — what + why; do NOT build yet). Venue tier, separate
from home/SMB commercial. Depends on the mobile agent and the **venue/epidemic outbreak
detection** ([lateral-movement-outbreak-detection.md](lateral-movement-outbreak-detection.md)
Tier 2). Related: [agent rebuild](agent-rebuild-config-driven.md),
[connection-type awareness](connection-type-awareness.md),
[product thesis — agent-as-credential / 2FA](product-thesis-built-in-it-expertise.md).

> **⚠ FLAGGED TENSION (2026-07-26, not resolved) — read before building anything here.**
> [ADR 0015 — guest self-service enrollment](../architecture/0015-guest-self-service-enrollment.md)
> (new, same day) describes venue guest enrollment as **QR-code / captive-portal** self-service
> (matching standard hospitality WiFi UX), and explicitly does **not** require an installed app
> as the enrollment mechanism — an app is framed as an optional value-add (protection beyond the
> visit), not the credential itself. That is a real disagreement with **this stub's** "the app
> IS the access credential — no app = no WiFi" framing below, which this stub still describes
> unchanged. **Not reconciled yet** — pick this stub back up alongside ADR 0015 before building
> either. Also see new [ADR 0014 — deployment appliance
> model](../architecture/0014-deployment-appliance-model.md) (independent decision, same day,
> unrelated to this tension — the SMB/venue *server* deployment target, not the guest-enrollment
> mechanism) and [ADR 0016 — guest marketing capture](../architecture/0016-guest-marketing-capture.md)
> (new opt-in module, same day — captive-portal-adjacent, needs legal review before shipping).

## Concept
Replace the guest-WiFi password with the **Nemesis guest app**. The app **IS** the access
credential — **no app = no WiFi**. The Terms-of-Service disclosure shown at install is the
**informed consent** for traffic inspection. (This is the agent-as-credential idea from the
product thesis applied to a venue's guest network: enrollment is the auth.)

## Guest flow
Scan QR → install guest app → **TOS disclosure → accept** → auto-enrollment (clean scan
required) → WiFi access via the **inspection tunnel** → protection active while on-site →
agent goes **dormant when the guest leaves** → reconnects automatically on return.

## Venue benefits
- Every guest device enrolled and inspected.
- Compromised devices can't spread (outbreak detection on the guest fleet).
- No illegal-use liability (inspection + logging).
- Guest network genuinely **secure**, not just isolated.
- Usage analytics (count/timing, **not content**).

## Guest benefits
- Free, fast WiFi (the incentive).
- Malicious sites blocked automatically.
- Device protected while on-site.
- Clear TOS (no hidden monitoring).
- The app stays useful on **other** networks after the visit (the acquisition hook).

## TOS disclosure (mandatory, prominent)
> Traffic inspected for malware/malicious content while on-site. No browsing history stored.
> No data sold. Inspection active only while connected to this network.
>
> **[Install & Connect]   [Decline → cellular data only]**

## Outbreak detection
All guest devices enrolled → **lateral-movement detection active** on the guest fleet
(the venue/epidemic Tier 2 in
[lateral-movement-outbreak-detection.md](lateral-movement-outbreak-detection.md)) → a
compromised device is isolated at its **first suspicious outbound attempt** → other guests
protected → venue notified → guest suspended with a clear explanation.

## User-acquisition angle
The guest app is useful **beyond** the venue (protects on all networks), so guests keep it
installed → the community feed grows → a venue deployment becomes a **user-acquisition
funnel** → network effect: more venues → more users → better intelligence.

## Business model
- **Venue tier — separate** from the home/SMB commercial tier.
- Pricing options: per-venue flat monthly, per-device-day, or a venue add-on.
- **Auto-approve flow** (a venue can't manually approve each guest — see sequencing).
- **Lighter agent** (mobile-first, not the full desktop agent).
- **Short enrollment duration** (visit-based, not permanent).
- **New (2026-07-26) — paid custom-integration service, not required:** if [ADR 0016 — guest
  marketing capture](../architecture/0016-guest-marketing-capture.md) ships, custom per-venue
  integration work (wiring the exported guest data into a specific venue's other systems) is a
  **possible paid service** Paul could offer — but not required; the export API should be
  documented well enough that any programmer (the venue's own, or one they hire) can build the
  integration themselves. **Unconfirmed, needs a lawyer, not a settled fact:** this likely
  shifts *some* liability for downstream data handling to the venue/their programmer once data
  leaves via the documented export API — flagged as unconfirmed legal reasoning only, per ADR
  0016; do not treat as a guaranteed liability shield.

## Sequencing
- **Mobile agent (V2/V3)** — required first. **This is hurdle 1 for the venue direction as a
  whole** — nothing else in this stub can start until it clears. Platform order within it
  (operator decision, 2026-08-03):
  - **Android agent development is deferred until near a final v2.0 agent** — not picked up
    now, and not picked up early; work starts once the core (Windows/Linux) agent is close to
    its v2.0-final state, not before.
  - **Apple platform approval (Mac + iPhone) is sequenced AFTER Android is fully tested and
    working as intended — not in parallel.** Android has to actually work first; Apple work
    doesn't start alongside it as a hedge. **What "fully tested and working as intended"
    concretely means for Android:** validating the QR → install → connect **guest
    self-service enrollment flow** — [ADR 0015](../architecture/0015-guest-self-service-enrollment.md)'s
    mechanism — end-to-end on Android. Not a general platform port checked off in the
    abstract; the specific thing that has to work is the captive-portal/QR onboarding this
    stub's whole venue flow depends on. Apple sequencing waits on *that* validation
    specifically, not just "an Android build exists."
  - **Mac/iOS otherwise stay fully parked, no design effort, until then.** This sharpens (does
    not contradict) [hardware-stable-identifiers.md](hardware-stable-identifiers.md)'s existing
    "Mac = interface + type-vocabulary only (drop-in later)" / "Android/iOS = still
    parked/future" split — that doc covers hardware-fingerprint *collection* specifically; this
    is the broader mobile-agent build-and-store-approval sequencing that gates the venue
    direction overall.
- **Auto-approve flow** (venue setting) — a simple `enrollment_status` change (venue can't
  approve each guest by hand).
- **Captive portal (V2)** — the QR → install → connect flow.
- **Outbreak detection (V2, core version)** — lateral movement on the guest fleet.
- **Venue analytics dashboard (V3)** — separate from personal monitoring.
