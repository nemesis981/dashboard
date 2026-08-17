# ADR 0022 — Source-Available License, Not a Standard OSS License

- **Status:** **DRAFT — captured, not finalized.** The `LICENSE` and `README.md` files
  this ADR explains are themselves marked DRAFT pending Paul's review and real legal
  review. This ADR records the reasoning behind the shape chosen, not a closed decision.
- **Date:** 2026-08-17
- **Affects:** `LICENSE` (new), `README.md` (new), the legal basis for the free/commercial
  split that `core/entitlements.py`, `core/license_key.py`, and `core/cap_guard.py` already
  enforce technically.
- **Depends on / Related:** the node-locked licensing engine (`core/install_id.py`,
  `core/license_key.py`, `core/backup_codes.py`, `core/remote_census.py`,
  `core/entitlements.py`) and the remote-device cap enforcement (`core/cap_guard.py`,
  `core/net_reachability.py`) — both already built and shipped as of this same date. This
  ADR addresses the *legal* document those mechanisms assumed existed but didn't.

## Context

An audit requested 2026-08-17 asked a specific question: does the repo's `LICENSE` file
say something fully permissive (MIT, Apache, etc.) that would already legally allow
unrestricted commercial use for free, undermining the free-personal/paid-commercial model
that had just been built and deployed?

**The actual finding was more fundamental: there was no `LICENSE` file at all**, no
`README.md`, and no license-grant language anywhere in the repository. `git log --all
--full-history -- "LICENSE*"` shows none ever existed. Under default copyright law, a
public repository with no explicit license grant is "all rights reserved" — nobody has
explicit permission to copy, run, modify, or redistribute the code, including the free-tier
personal use the product is designed to invite. In practice a public repo with an installer
inviting general use probably supports an *implied* license argument, but that's legally
weak and establishes no personal/commercial boundary at all.

This mattered more than a typical documentation gap because of one specific detail in the
locked tiering model (operator decision, 2026-08-16/17): **commercial firewall-only use is
available with no technical enforcement — license terms only.** For that mode, this
document isn't backup for the technical enforcement; it *is* the entire enforcement. Its
absence meant that mode was unauthorized-but-unenforced-by-anything, not merely
under-documented.

## Decision

Use a **source-available custom license**, not a standard OSI open-source license (MIT,
Apache 2.0, BSD, GPL, etc.), and not full proprietary closed-source either.

### Why not a standard permissive/copyleft OSS license

Every standard OSS license (permissive or copyleft) grants broad rights that include
unrestricted commercial use — that's a defining property of what makes them OSI-approved.
Adopting any of them would legally hand out exactly the thing the entitlement system exists
to withhold: a business could take the code, self-host it, and never touch the paid tier,
entirely within their rights under the license. This isn't a subtle mismatch; it's the
direct opposite of the product's monetization design. GPL's copyleft would additionally
create real complications for a paid-license path — a GPL'd codebase generally can't be
dual-licensed to withhold rights from downstream commercial users the way this model
requires.

### Why not fully closed-source

Nemesis's own positioning is built partly on transparency and auditability — "verify what
a security product installed on your own network actually does" is a real trust argument
for a firewall/security product specifically, distinct from most software categories. Fully
closed source would undercut that positioning without buying anything the source-available
model doesn't already achieve for the licensing goal.

### The shape chosen

Same family as license models used by products like Sentry, MariaDB (BSL-era), and similar
dual-model open-core products: source visible for review, free for personal/non-commercial
use, commercial use requires a separately-negotiated paid license. Concretely (see
`LICENSE` for full terms, currently draft):

- Personal/household use: free, matching what the free tier already grants technically
  (full agent, no capability reduction, capped remote-device count).
- Any commercial/organizational use: requires a Commercial License, matching
  `entitlements.is_commercial()`'s existing gate.
- Explicit statement that the license terms bind even where the software has no technical
  gate for a given mode — directly addressing the firewall-only-mode gap above.
- No specific pricing figures in the public `LICENSE` text — those remain a live business
  decision tracked privately (`~/work/nemesis-internal/scoping-and-estimates/`), consistent
  with Rule 10's existing treatment of pricing/threshold specifics.

## What this ADR does not decide

- The exact copyright holder name/entity, commercial-licensing contact, and governing
  law/jurisdiction — left as explicit placeholders in the draft `LICENSE`, Paul's call.
- Whether real legal counsel reviews and revises the drafted terms before they're treated
  as binding — **recommended, not yet done.** The draft was written by Window 2 (Claude) as
  a starting point, using the general shape of comparable real-world licenses, not by a
  lawyer, and should not be relied on for actual enforcement until reviewed.
- A real Contributor License Agreement — `LICENSE` §7 is a placeholder; not urgent while
  the project has no external contributors, but needed before any are solicited.
- Whether/when a time-delayed conversion to a permissive license (the BSL pattern — e.g.
  "becomes Apache-2.0 after N years") is worth adopting. Not included in the draft; worth
  considering later as a goodwill/community gesture, but it's an optional addition to this
  shape, not a requirement of it.

## Consequences

- Until the `LICENSE` file is reviewed and finalized, the project's actual legal footing is
  materially better than before this pass (an explicit draft grant exists to point to) but
  still not settled — this is a real, tracked gap, not a closed item. See `PUNCHLIST.md`.
- The firewall-only commercial mode remains enforced by document only, by design (per the
  locked tiering model) — finalizing this license is a prerequisite for that mode meaning
  anything, not an optional follow-up.
