# Roadmap stub — Venue guest network: the agent AS the credential

**Status:** parked (concept capture — what + why; do NOT build yet). Venue tier, separate
from home/SMB commercial. Depends on the mobile agent and the **venue/epidemic outbreak
detection** ([lateral-movement-outbreak-detection.md](lateral-movement-outbreak-detection.md)
Tier 2). Related: [agent rebuild](agent-rebuild-config-driven.md),
[connection-type awareness](connection-type-awareness.md),
[product thesis — agent-as-credential / 2FA](product-thesis-built-in-it-expertise.md).

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

## Sequencing
- **Mobile agent (V2/V3)** — required first.
- **Auto-approve flow** (venue setting) — a simple `enrollment_status` change (venue can't
  approve each guest by hand).
- **Captive portal (V2)** — the QR → install → connect flow.
- **Outbreak detection (V2, core version)** — lateral movement on the guest fleet.
- **Venue analytics dashboard (V3)** — separate from personal monitoring.
