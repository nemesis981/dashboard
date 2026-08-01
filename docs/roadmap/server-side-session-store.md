# Server-side session store — roadmap stub

- **Status:** PARKED. Captured 2026-08-01 (Window 2) from a Window 1 handoff note during the
  idle-lock/recovery-code-email build; not elaborated beyond the label at capture time. This
  is a minimal, honest stub per Rule 7 — do not treat the "why" below as Window 1's full
  reasoning, only what's directly inferable from context already in the repo.
- **Related:** [idle-lock-walk-away-protection](idle-lock-walk-away-protection.md) — that
  design deliberately stayed with the existing signed-cookie session (no schema/infra change)
  and explicitly listed "any change to `PERMANENT_SESSION_LIFETIME`/`session.permanent`" and
  "multi-device/session management UI" as non-goals. This stub is likely the natural next
  question once idle-lock ships: what a server-side session store would unlock that the
  cookie-only model structurally cannot.

## What's known

Nemesis auth (`dashboard.py`, Flask-Login) uses plain signed session cookies today — no
server-side session store. This is why idle-lock's design could add `last_activity` to the
cookie itself with no schema change: the server never has independent state about a session
beyond what the client presents back to it.

The structural limitation that a signed-cookie-only model can't remove, regardless of what's
layered on top of it:
- **No way to forcibly invalidate a specific live session from the server side.** A stolen or
  compromised session cookie remains valid until it naturally expires or the account's
  password changes (which invalidates nothing about the cookie itself — Flask-Login's
  `login_user`/`logout_user` don't revoke prior tokens). The concurrent-session detection
  built 2026-07-31 can *notice* and *alert* on a second session, but has no mechanism to
  *end* the other one.
- **No inventory of active sessions.** There's no "list of who's currently logged in, from
  where, since when" — `login_events` records login *attempts*, not session *lifetime*.
  Any future "sign out all other sessions" or admin session-management UI needs
  server-side session state to act on, not just to log against.

## Why this is parked, not scoped

No build size, schema shape, or specific trigger has been proposed. This needs the same
audit-first treatment as every other auth feature (current state investigation, then a
proposed design) before it graduates past a stub — not assumed to be "the same shape as
idle-lock." Flagging for Window 1 to elaborate the original motivation before this is
scoped further.
