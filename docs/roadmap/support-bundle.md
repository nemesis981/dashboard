# Support Bundle — Automatic Diagnostic Package

> Roadmap capture — project-sized idea. Records the concept and design intent; does not
> design the implementation. One-click "I need help" → a sanitized, pre-diagnosed
> diagnostic package the user can route to self-fix, Nemesis support, the software vendor,
> or the community.

## Concept

A non-expert clicks **"I need help"** and Nemesis assembles a complete diagnostic package
in ~10 seconds (all data is already collected). The bundle is **pre-diagnosed** — it carries
the AI's most-likely-cause and a suggested fix in plain language — so the
"please describe your problem" back-and-forth is eliminated.

## Trigger

User clicks **"I need help"** / **"Get Support"** from the dashboard.

- **Generation time:** ~10 seconds (no new collection — reads existing state).
- **Rule 8:** sanitized BEFORE any transmission — no real IPs, paths, or usernames leave
  the box. Sanitization is a hard gate on every destination that sends data off-box.

## Contents

- **System profile (sanitized):** OS, RAM, CPU, Nemesis version.
- **Software timeline (last 30 days):** installs, updates, uninstalls — with certificate IDs.
- **Registry diff:** vs last week + vs pre-last-install.
- **Sandbox behavioral logs:** flagged behaviors from recent tests.
- **Security state:** canary status, scan findings, open tickets.
- **Connectivity:** diagnostics verdict, ping history.
- **AI diagnosis:** most-likely cause + suggested fix in plain language.
- **Suggested fixes:** one-click options where available.

## Three (four) destinations

- **[Fix automatically]** → Nemesis applies the suggested fix.
- **[Contact Nemesis support]** → sends to `support@nemesis-sw.com`; the private support
  ticket module receives a pre-diagnosed, self-contained bundle.
- **[Contact vendor support]** → generates a vendor-ready support package (professional
  format, pre-diagnosed).
- **[Post to community]** → sanitized bundle for forum / GitHub issue.

## Vendor-ready package

Formatted for non-technical communication to software vendors. Includes: system info,
installation timeline, what changed, what Nemesis detected, what the user has tried.
Takes ~10 seconds to generate vs ~2 hours manual. The vendor receives complete context
immediately — no clarifying round-trip.

## Private support module connection

An incoming bundle at `support@nemesis-sw.com` arrives **pre-diagnosed**. Support sees the
exact timeline, registry diff, and AI diagnosis — no clarifying questions needed → faster
resolution. Each ticket is self-contained, which scales support capacity.

## Value to user

A non-expert can get professional support **without knowing what information to provide.**
"I need help" → complete diagnostic package → answer. Eliminates the
"please describe your problem" back-and-forth.

## Connects to

- **Registry backup** — the registry-diff source. *(No roadmap capture yet — prerequisite.)*
- **Software inventory** — the timeline + certificate-ID source.
  (See [malware-detection-pipeline.md](malware-detection-pipeline.md) §8.)
- **Sandbox logs** — behavioral context.
  (See [malware-detection-pipeline.md](malware-detection-pipeline.md) §6–7.)
- **AI Engine** — diagnosis + plain-language summary (tiered).
- **Private support ticket module** — the receiving end. *(The `tickets` module exists; a
  first-party "private support" intake at `support@nemesis-sw.com` is not yet captured —
  prerequisite.)*
- **Community feed** — sanitized bundle = community intelligence.

## Open prerequisites (not yet captured elsewhere)

- **Registry backup / registry-diff engine** — the diff source has no design doc yet.
- **Private support intake** — routing `support@nemesis-sw.com` into a first-party support
  queue (distinct from the user-facing `tickets` module) is undesigned.
- **Sanitization gate** — the Rule-8 scrub applied to every off-box destination must be a
  single shared chokepoint, not re-implemented per destination.
