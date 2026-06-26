# Roadmap stub — responsive dashboard, multi-user-ready

**Status:** parked (post-Pass-0; build after the single-user-assumptions audit).

## What
Deliver a **single-user, refresh-on-action** dashboard NOW, but build it **multi-user
READY** on bones that don't need to be rebuilt for the commercial tier:
- **Version data domains** — each data area carries a version/sequence so clients can tell
  what changed.
- **Widget-scoped refresh** — update the specific widget/card that changed, never a full
  page reload.
- **Single update path for all writes** — every write goes through one path that records
  "what changed" (rather than scattered ad-hoc refreshes).
- **Separate "what changed" from "how clients learn it"** — the change-tracking is
  independent of the delivery mechanism.

Multi-user delivery (e.g. **SSE push** to many clients) is a **COMMERCIAL-tier** feature,
built later on these same bones.

## Why
Building the single-user version naively (full page reloads, scattered refresh logic)
would have to be torn out to support multiple concurrent users. Designing the seams now —
versioned domains, scoped refresh, one write path — makes the commercial multi-user
delivery an addition, not a rewrite.

## Reasoning / guiding principle
**Updates refresh ambient data; they never disrupt active interaction.** A refresh must
not blow away a modal being filled in, an edit in progress, or a list the user is actively
reading. Ambient data updates quietly in place; the user's current task is sacred.

## Dependencies
- Run `single-user-assumptions-audit.md` first (its dashboard-update-paths section feeds
  this build).
