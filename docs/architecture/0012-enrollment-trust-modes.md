# ADR 0012 — Enrollment Trust Modes

- **Status:** **BUILD-READY** (2026-07-01; design locked, **not yet built**). Design of record;
  **no code changed by this ADR.** Only MANUAL (the `auto_approve = 0` default) is implemented
  pre-trip — see [0011](0011-enrollment-security-model.md); the other three modes are post-trip
  build work.
- **Date:** 2026-07-01
- **Affects:** `/enroll` outcomes + `enrollment_status`, the `enrollment_tokens` model, the owner
  approval / bulk-review UX, a new auto-enroll audit log, and the trusted-vs-guest network posture
  a newly-enrolled device receives.
- **Depends on:** [0011 — enrollment security model](0011-enrollment-security-model.md) (the
  manual-approval-default + TOFU token binding this mode system builds on top of);
  [0005 — device-auth](0005-dns-firewall-device-auth-architecture.md) (the `firewall.py`
  chokepoint that enforces the trusted-vs-guest posture split).
- **Related ADRs:** [0011 — enrollment security model](0011-enrollment-security-model.md)
  (foundation); [0009 — security inspection proxy](0009-security-inspection-proxy.md) (VENUE
  guest/monitored devices are the natural consumers of the route-and-inspect verdict path);
  roadmap [venue-guest-network.md](../roadmap/venue-guest-network.md),
  [msp-central-management.md](../roadmap/msp-central-management.md).
- **Rule 8:** placeholders only (`<tailnet-ip>`, `<subnet>`, `<token>`, `<campaign-id>`,
  `<account>`). Per-installer/per-campaign credentials are secrets — out of all logs/docs/commits.

> Capture only — design of record for the enrollment *mode* system layered on ADR 0011's
> manual-approval default. No code changed here.

## Problem

ADR 0011 fixed the dangerous default: enrollment now lands **PENDING** (`auto_approve = 0`) and a
human approves each device. That is correct out-of-box, but it does not scale to two real
operator situations:

1. **Batch provisioning with no human present** — an SMB imaging 40 laptops overnight cannot sit
   and click approve on each. The pre-0011 answer was `auto_approve = 1`, a **persistent global
   toggle** — the exact hole 0011 closed. A forgotten toggle silently re-opens it.
2. **Admitting strangers' devices** — a hotel / café / event admits guest hardware nobody owns or
   controls. "Approving" these into the same trusted tier as owned devices is categorically wrong,
   yet there must be *some* unattended admit path or the venue use-case is dead on arrival.

The trap is treating both as "auto-approve." They have **opposite safety conditions** — one is
safe because you *own* the hardware, the other is safe because the network *contains* it — and
must never collapse into one flag.

## Decision — four enrollment paths, one safe default

### MANUAL — the durable default (always)
Every device lands **PENDING**; a human approves each individually via the review card
(ADR 0011). This is the out-of-box default and **is** the `auto_approve = 0` behavior. It is
**never silently overridden by a global setting.** No security warning needed — trust is granted
one human decision at a time.

### BULK MANUAL APPROVE — human present, reviews the list
A review page lists the **PENDING** devices; a human **sees the actual list** and approves
selected/all after a typed **"yes"** confirmation. The human is **present at approval time** and
looks at real devices before granting trust. This is the common SMB workflow and is **safer than
any auto mode** precisely because a person reviews the concrete list before trust is granted. No
per-mode warning needed. Grants **trusted-tier** membership.

### FLEET AUTO (SMB) — unattended, INTO THE TRUSTED tier
Unattended batch auto-approve **into the trusted tier**, for devices the operator **owns and
physically controls**. For when a human **cannot be present** at enroll time (e.g. overnight
provisioning of owned hardware).
- **Safety condition: physical / ownership control.** The operator vouches for the hardware.
- **Warning (tied to its failure mode):** *"FLEET auto-approve grants full trusted-network access
  without review. Use ONLY for devices you physically own and control. Any device presenting a
  valid campaign token during the window is trusted automatically."*

### VENUE AUTO (hotel / captive) — unattended, INTO A GUEST/MONITORED tier
Unattended batch auto-enroll **into a guest / monitored tier that is explicitly NOT trusted.**
Devices are **strangers' hardware** admitted under monitoring and network containment.
- **Safety condition: network isolation — NOT ownership.** Safety comes from the segment the
  device is dropped into (contained, inspected), not from vouching for the hardware.
- **Consumer of ADR 0009:** VENUE guests are the natural traffic for the route-and-inspect
  (decisions-not-data) verdict path — admitted, but every connection is subject to inspection.
- **Warning (tied to its failure mode):** *"VENUE auto-enroll admits UNKNOWN devices you do NOT
  control. These devices are NOT trusted. Ensure guest-network isolation is active before starting
  this campaign — containment, not ownership, is what makes this safe."*

## Design rules the modes MUST obey

1. **MANUAL is the durable default; auto is a CAMPAIGN, not a setting.** FLEET and VENUE auto are
   **NOT** persistent global toggles. They are **scoped, expiring, logged campaigns** bounded by
   **device count** and/or **time window** and/or **source subnet** (`<subnet>`). When the bound is
   hit — N devices enrolled, the window closes, or the campaign is stopped — enrollment reverts to
   MANUAL automatically. **This is the structural fix for the `auto_approve = 1` hole:** there is
   no toggle left flipped, because auto is a bounded event that ends itself, not a state that
   persists until someone remembers to turn it off.

2. **The typed-"yes" gate sits where the human actually is.**
   - **BULK MANUAL:** the gate is at approval time (a human is present to type it after seeing the
     list).
   - **FLEET / VENUE:** the gate is at **campaign setup**, not per-device — because **no human is
     present at enroll time.** The human commits to the bounded campaign (count/window/subnet + the
     per-mode warning acknowledgement) up front; individual enrollments during the window are then
     unattended by design.

3. **Trust semantics are DISTINCT outcomes, never the same flag.** FLEET grants **trusted-tier**
   membership; VENUE grants **monitored-guest** access only. These are **different enrollment
   states / posture assignments**, not one shared `approved` boolean. A VENUE device must never be
   representable as "approved into trusted" by any code path — the guest state is a first-class,
   distinct outcome that the `firewall.py` chokepoint (ADR 0005) enforces as a contained segment.

4. **Per-mode warnings, each tied to its ACTUAL failure condition** (not generic boilerplate):
   FLEET → *"only for devices you physically control"*; VENUE → *"these devices are NOT trusted —
   ensure network isolation is active."* MANUAL and BULK MANUAL need **none** (a human reviews
   before trust).

5. **Mandatory auto-enroll audit log.** Every FLEET/VENUE auto event records, at minimum:
   - `timestamp`
   - device `stable_id` + `fingerprint` + `is_virtual` (from hardware-stable-ID / TOFU)
   - source IP / subnet (`<tailnet-ip>` / `<subnet>`) the enrollment arrived from
   - granting `token` / `<campaign-id>`
   - `mode` (`fleet` | `venue`)
   - the admin / `<account>` that created the campaign
   - resulting **network posture** (trusted vs guest/monitored)

   BULK MANUAL and MANUAL approvals already log via the existing approve/audit path; the new log is
   specifically for the **unattended** admits, so an owner can reconstruct *what was trusted while
   nobody was watching* and *which campaign let it in.*

6. **Lifecycle / retention differs per mode.**
   - **VENUE guest enrollments are transient** — they carry a **TTL** and **auto-de-enroll on
     absence** (a guest that leaves the venue and stops appearing is aged out). Guest state should
     not accumulate strangers' devices forever.
   - **FLEET / trusted devices are permanent** — an owned, provisioned machine persists like any
     manually-approved device.

## Why campaigns (not a settings toggle) is the whole point

The `auto_approve = 1` hole was dangerous because it was a **durable global state** a human could
set and forget. Modelling FLEET/VENUE as **bounded, self-terminating campaigns** means the unsafe
condition **cannot persist by neglect** — it expires by construction. The typed-"yes"
acknowledgement of the correct per-mode warning is captured at campaign creation, and the whole
event is auditable after the fact. Safety is structural, not vigilance-dependent.

## Implementation status

- **MANUAL — implemented pre-trip** as the `auto_approve = 0` default (ADR 0011). Nothing in this
  ADR changes it.
- **BULK MANUAL, FLEET AUTO, VENUE AUTO — post-trip build work.** Design locked here;
  build sequencing to be scheduled after the trip-critical installer/enrollment pieces land.
  VENUE additionally depends on the guest-network segment + the ADR 0009 inspection path being
  built.

## Status / next

**BUILD-READY (design locked).** Next step (post-trip): a build prompt specifying the
campaign model (count/window/subnet bounds + self-termination), the distinct guest-vs-trusted
enrollment states through the `firewall.py` chokepoint (ADR 0005), the campaign-setup typed-"yes"
+ per-mode warning UX, and the mandatory auto-enroll audit log.
