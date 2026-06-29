# Nemesis Verified Partner Program

> Roadmap capture — project-sized idea, **future revenue stream**. Records the concept and
> business-model intent; does not design the implementation. Post-commercial; possibly a
> **separate product line** from the main Nemesis stack.

## Concept

Software vendors pay for structured access to Nemesis [support bundles](support-bundle.md)
and certificate verification. This reduces their support costs dramatically while improving
the end user's experience — the same evidence that helps the user
([SMB software support](product-thesis-built-in-it-expertise.md#smb-software-support-the-hidden-value))
is monetizable on the vendor side.

## Vendor value

- **Support ticket resolution:** ~3 hours → ~15 minutes (pre-diagnosed bundle arrives with
  full context).
- **Certificate verification API:** instant clean-install proof.
- **Anonymized install analytics:** what breaks on what systems.
- **Product intelligence:** conflict patterns, failure rates.

## Certificate verification API

```
GET /verify/{NMS-CERT-id}
→ { valid: bool, software, date, findings, coverage_pct }
```

A vendor verifies a clean install in ~30 seconds — eliminating the "bad install" support
conversation entirely. (Certificate IDs are issued by the
[malware-detection-pipeline](malware-detection-pipeline.md) — `NMS-CERT` at certification
scan §1, `NMS-INST` at sandbox-verified install §7–8.)

## Partner tiers

- **Free:** basic bundle-receipt endpoint.
- **Pro:** API access + anonymized analytics.
- **Enterprise:** custom integration + dedicated support.

## Network effect

More users → more bundles → vendors see value → vendors join the program → vendors recommend
Nemesis → more users. The flywheel is the same shape as the community feed: value compounds
with installed base.

## Analytics (aggregated, anonymized)

- Install success rates per OS / hardware config.
- Common conflict patterns.
- Time-to-first-issue distributions.
- Actionable rollups, e.g. "23% of tickets preventable by updating SharedLib."

## Privacy

- Vendors **never** see individual user data — aggregate patterns only (same model as the
  community feed).
- **User controls what gets sent** — explicit consent per bundle.
- The Rule-8 sanitization gate from [support-bundle.md](support-bundle.md) applies to every
  off-box payload here too; this is a stricter case (commercial recipient), so consent +
  sanitization are hard gates, not options.

## Sequencing — post-commercial release

Prerequisites (all currently roadmap-only):

- **Support bundle feature** ([support-bundle.md](support-bundle.md)).
- **Certificate system** ([malware-detection-pipeline.md](malware-detection-pipeline.md)
  §1, §7–8) — `NMS-CERT` / `NMS-INST` issuance + a verifiable store.
- **Community backend infrastructure** (identity, submission, aggregation —
  [community-reporter-identity.md](community-reporter-identity.md),
  [community-signal-dedup.md](community-signal-dedup.md)).

**Open questions (not resolved here):**

- **Separate product line?** This may not belong in the main Nemesis stack — a vendor-facing
  API + analytics surface is a different deployment and a different customer.
- **Legal:** vendor data-sharing agreements, the consent model, and aggregate-analytics
  disclosure all need legal review (same bucket as the community-feed
  TOS/EULA/Privacy work already flagged in `PUNCHLIST.md`).
- **Verification-store trust:** how a vendor trusts an `NMS-CERT` lookup (signing, revocation)
  is undesigned.
