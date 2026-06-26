# Roadmap stub — single-user-assumptions audit (QUEUED, read-only)

**Status:** queued. **Read-only audit** — run **after** the Pass-0 migration completes and
**before** the responsive-dashboard build. Produces findings; changes nothing.

## What
Sweep the codebase for places that silently assume a single user / single actor, so the
multi-user-ready work has a real map to build against. Look for:
- **Global vs per-user state** — state stored as one global where it should be per-user.
- **Actions with no actor attribution** — writes/edits that record no "who did this."
- **Auth/session as one implicit identity** — the whole app behaving as a single logged-in
  user.
- **Concurrency assumptions** — e.g. the `tickets_seq` read-increment (read next number,
  then update) is not safe under concurrent writers; similar read-modify-write patterns.
- **Scattered write paths** — writes that don't funnel through a single, observable path.

## Why
Multi-user support (commercial tier) and the responsive dashboard both depend on knowing
exactly where single-user lock-ins live. Auditing first — read-only, before building —
keeps to "audit first" and avoids designing the responsive build on wrong assumptions.

## Output — classify every finding
- **(a) already multi-user-safe** — no action.
- **(b) cheap seam-now** — small change worth making during the responsive build.
- **(c) defer-to-commercial** — real work, parked for the commercial tier.

Plus a **dashboard-update-paths** section enumerating every place the dashboard mutates or
refreshes state — this directly feeds `responsive-dashboard-multiuser-ready.md`.
