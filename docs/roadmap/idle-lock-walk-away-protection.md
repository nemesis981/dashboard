# Idle-lock / walk-away protection — design

- **Status:** SHIPPED, 2026-08-01 (same day as design approval) — `219c282` (enforcement),
  `0e15c22` (in-page overlay + DOM-interaction heartbeat), `0573b79` (view-only health
  summary on the lock screen). Live in `dashboard.py`: `_IDLE_TIMEOUT_SECONDS`/
  `_SESSION_MAX_SECONDS` config, `_IDLE_LOCK_ALLOWED` allowlist, `session_idle_locked`
  audit-log row, dedicated re-auth flow (`dashboard.py:3359`), `static/nemesis-idle-lock.js`
  live on the settings page. Header found stale by `roadmap-state-audit-2026-08-31.md` —
  this doc's own tally lineage had it right since the 2026-08-06 baseline, but this header
  itself was never corrected until now, a full month after shipping. Corrected here.
- **Original design approval, 2026-08-01 (operator: 15-min default, no disable switch in v1,
  add an `audit_log` row on the lock transition).** Queued 2026-07-31, designed 2026-08-01.
- **Addendum 2026-08-01:** the absolute session cap (`SESSION_MAX_HOURS`, default 8h, full
  logout rather than confine) was approved by the operator mid-session, after this doc's
  initial draft — not unapproved scope creep during implementation; noted here so the written
  record matches what was actually authorized.
- **Size estimate:** 2–3 sessions (one route + one shared JS include + one env var; no schema
  change; the main cost is auditing every page-render function for JS-include coverage).
- **Related:** [0006-data-manager](../architecture/0006-data-manager.md) (unlock attempts route
  through the same `_users_conn()`/Data Manager path as login); the 30-day password-expiry
  policy and the recovery-code system (both built 2026-07-31, both interact with this — see
  §Interactions).

---

## Requirement (as given)

After X minutes of no activity, the dashboard session locks and requires the password before
it's usable again. Preventive, not forensic — distinct from `login_events`. A client-side
timer alone is not a real control (same limitation already documented on the credential-cache
drop path) — **server-side session expiry must be the actual enforcement mechanism**; a
client-side timer is a UX nicety (warn before lockout, auto-lock the UI) but must not be the
thing that's trusted. Configurable timeout, sensible default. Re-auth must not lose unsaved
work where reasonably avoidable.

## Current state (investigated, not assumed)

- **Sessions never expire today.** `dashboard.py` never sets `session.permanent = True` and
  never sets `PERMANENT_SESSION_LIFETIME`. Flask-Login's cookie is a plain signed session
  cookie with no embedded expiry — it lasts until the browser is closed or `/logout` is hit.
  A tab left open and unattended stays authenticated indefinitely. This is the exact gap the
  feature closes.
- **`_enforce_setup_and_auth()` (dashboard.py ~line 750) is the single `@app.before_request`
  chokepoint** that already gates every route (core + all module routes) on
  `current_user.is_authenticated`, and — as of 2026-07-31 — also enforces the password-expiry
  policy by redirecting to `/account/password` when `_password_expired()` is true, using an
  endpoint allowlist (`_EXPIRED_ALLOWED`) to keep the account reachable enough to fix itself.
  This is the natural, already-proven extension point: idle-lock is structurally the same
  problem (authenticated, but confined to a "prove it's still you" endpoint) and should reuse
  the pattern, not invent a second one.
- **`session[...]` is already used for ephemeral per-session state** — `session["pw_recovery_at"]`
  (set at recovery-code login, checked by `_recovery_grace_active()`). This establishes that
  storing a `last_activity` timestamp in the signed session cookie (not a DB column) is
  consistent with how this codebase already treats session-scoped, non-security-critical
  state. Unlike `recovery_grace_until` — which HAD to move to the DB because a stolen cookie
  could otherwise replay a stale "grace window open" flag — there is no equivalent replay risk
  here: an attacker holding a stolen cookie cannot forge a *newer* `last_activity` than what
  the server actually signed, so the cookie can only ever under-state freshness, never
  over-state it. **No schema change is required for the core mechanism.**
- **`_register_credential_failure()` is a shared brute-force budget across `login` AND
  `change_password`**, explicitly built so an authenticated form cannot become an unmetered
  password oracle for a hijacked session. Any new password-verification surface (the unlock
  screen) MUST call into this same function, not add a third independent counter.
- **`_log_login_event()` already anticipates multiple non-login credential-check sources** via
  its `source`/`action` params (used today by `login`, `change_password`, and nemesis-fwd's
  own credential checks). Unlock attempts should log through the same table the same way.
- **Configurable values that need a restart live in `/etc/nemesis.env`**, edited via
  Settings → `_update_nemesis_env()` → `nemesis-fwd`'s `write_env` op → dashboard restart.
  This is the established mechanism for an operator-adjustable value. (Note: the *existing*
  password-max-age, `_PASSWORD_MAX_AGE_DAYS = 30`, is actually a hardcoded module constant,
  not env-configurable — so there's no exact precedent for "auth policy value in nemesis.env,"
  but the general Settings/env-write/restart pattern is well established for everything else
  and is the right fit here since the requirement explicitly asks for configurability.)
- **The dashboard UI is NOT one shared Jinja layout.** Auth-adjacent pages (`login`, `setup`,
  `change_password`, recovery-code pages) render real templates from `templates/`. The main
  app surfaces (dashboard, settings, tickets, malware/queue, diagnostics, hw/devices — six
  distinct `<head>` blocks found) are each built by large per-route f-string HTML/JS blobs in
  `dashboard.py`, not a shared base template. The username/logout header appears to be
  produced by one shared builder (`_threat_indicator_html()` is called from a single site) —
  **this needs verification, not assumption**, before implementation: Window 1 must confirm
  every authenticated page actually funnels through that shared header point, or the idle
  tracking script will silently be missing from some pages (see §Risks).
- **Background auto-polling already exists and is a real trap for this design.** Confirmed via
  grep: `setInterval(refreshDashboard, 60000)` (main dashboard), plus device/scan/HW polling
  at 5s/30s/60s intervals elsewhere, all hitting `/api/...` endpoints through the same
  `@app.before_request` chokepoint as everything else. **If "any authenticated request"
  were allowed to refresh `last_activity`, a tab left open with auto-refresh running would
  never idle-lock — the exact walk-away scenario the feature exists to stop.** This is the
  central design constraint, addressed in §Mechanism below.

## Proposed mechanism

**Activity tracking is opt-in per endpoint, not opt-out.** Only a dedicated endpoint refreshes
`last_activity`; ordinary requests — including all the polling `fetch()` calls above — never
do, by default. This is deliberately an allowlist rather than a denylist: forgetting to
exclude a new polling endpoint later would silently defeat the whole feature (unsafe
failure), whereas forgetting to include the tracking script on some page just idle-locks a
user who's genuinely still working there (annoying, but fails safe).

1. **`session['last_activity']`** — an ISO timestamp, set at login (alongside `login_user()`
   in the `login()` route) and refreshed ONLY by a new endpoint, `POST /api/session/touch`.
2. **A small shared JS snippet**, included on every authenticated page the same way
   `_threat_indicator_html()` is (or, if that call site turns out not to be truly universal,
   via whatever the actual universal include point is — to be confirmed during
   implementation): listens for real interaction (`mousemove`/`keydown`/`click`/`scroll`/
   `touchstart`), throttled so it doesn't fire on every event, and POSTs to
   `/api/session/touch` at most once every ~30–60s **only if there was interaction since the
   last touch**. This is what background `setInterval` polling never does, which is exactly
   why it can't fake activity.
3. **Server-side enforcement** — a new check inside `_enforce_setup_and_auth()`, placed after
   the existing `current_user.is_authenticated` gate and *before* the password-expiry check
   (see §Interactions for why that order): if the endpoint isn't in a new
   `_IDLE_LOCK_ALLOWED` set and `now - session['last_activity']` exceeds the configured
   timeout (or `last_activity` is missing — fail closed, same posture as
   `_password_expired()`'s "unknown age counts as expired"), redirect to
   `/account/unlock?next=...` (reusing `_safe_next()`, same open-redirect guard as login).
   `_IDLE_LOCK_ALLOWED` = `{"account_unlock", "logout", "static", "api_health"}` — deliberately
   NOT including `login`/`setup` (those redirect an already-authenticated session straight to
   the dashboard, which would loop) and NOT including `/api/session/touch` (see next point).
4. **`/api/session/touch` is itself subject to the idle-lock gate.** Once locked, the client's
   heartbeat POST gets redirected/blocked exactly like any other endpoint — it cannot silently
   re-arm itself. Only a successful `/account/unlock` submission clears the lock. This closes
   the obvious bypass (a hostile or stuck tab spamming the touch endpoint to stay unlocked
   forever).
5. **`/account/unlock` (GET+POST)**, new route, modeled directly on `/account/password`:
   - GET renders a new `unlock.html` template (styled consistent with `change_password.html`)
     — password field only, `next` carried through.
   - POST verifies via `_check_password()` against the current user's row. Failure calls
     `_register_credential_failure(row, username, ip, ua, reason="idle_unlock_failed",
     source="idle_unlock", action="unlock")` — the SAME shared budget as login/change-password,
     so this cannot become a fresh, unthrottled guessing surface. Success sets
     `session['last_activity'] = now`, logs via `_log_login_event(..., source="idle_unlock",
     action="unlock")`, and redirects to `next` (or the dashboard).
   - **Does NOT call `logout_user()`.** The underlying Flask-Login session stays intact —
     unlock "confines, then releases" the session exactly the way `_password_expired()`
     already confines-without-rejecting. This is what makes the client-side overlay approach
     (next point) actually preserve in-progress state instead of forcing a fresh login.
6. **Client-side UX (nicety, not the control):** the same interaction-tracking script shows a
   warning banner ~60s before the configured timeout, then — at timeout — an in-page overlay
   (NOT a page navigation) prompting for the password, calling `/account/unlock` via `fetch()`
   and hiding itself on success. Because this never navigates away, any unsaved form input
   already typed into the page survives untouched. The server-side redirect (point 3) is the
   real backstop for a client that doesn't cooperate — see §Unsaved work below for the bounded
   case where that path *does* cost in-progress state.

## Config

- New env var, `IDLE_LOCK_MINUTES`, read from `/etc/nemesis.env` (same read path as other
  env-driven settings), editable from Settings alongside the existing env-config UI.
- **Default: 15 minutes** (operator-approved 2026-08-01), warning banner at T-60s.
- **No "disable" value in v1** (operator-approved 2026-08-01). The stated requirement is
  explicit ("nobody should have a live authenticated session sitting open and unattended") —
  silently allowing an operator to configure this off would undercut that. If a real use case
  emerges later (e.g. an always-on kiosk display), that's a deliberate future decision, not a
  default to build in now.

## Interactions with existing auth features

- **Password expiry (`_password_expired()`).** Idle-lock is checked *first* in
  `_enforce_setup_and_auth()`. If both conditions are true, the operator unlocks (proves the
  CURRENT password) and then, on their very next request, gets redirected again to
  `/account/password` (must set a NEW password). Two password prompts back-to-back is a real
  but minor UX cost of composing two independently-justified controls — flagging it rather
  than hiding it; not proposing a fix unless the operator wants one.
- **Recovery-code grace window (`_recovery_grace_active`, `_RECOVERY_GRACE_SECONDS`).**
  Orthogonal — recovery grace concerns "may set a new password without the old one," which
  has nothing to do with walk-away protection. No interaction: a session inside its recovery
  grace window still idle-locks and still unlocks with the (freshly recovery-set, or original)
  current password like any other session.
- **"Forgot the password entirely while idle-locked."** Because unlock does not call
  `logout_user()`, `current_user.is_authenticated` stays true, so the pre-auth
  `login_recovery` route's own guard (`if current_user.is_authenticated: redirect(dashboard)`)
  would bounce an idle-locked session away from the recovery-code entry point. The intended
  escape hatch is the existing one: `logout` stays in `_IDLE_LOCK_ALLOWED`, so an idle-locked
  operator can always explicitly log out and use the normal pre-auth recovery-code flow. Not
  proposing a special "recovery code accepted at the unlock screen" path — that adds surface
  for a rare scenario (forgetting a password within one active work session) that already has
  a working, if slightly less convenient, way out.
- **Shared lockout-tier budget (`_register_credential_failure`).** Unlock failures count
  against the SAME per-account budget as login and change-password failures, per the existing
  documented rationale (an authenticated form must not become an unmetered oracle). Concretely
  this means an idle-locked operator who mistypes their password a few times in a row is now
  drawing from the same counter a concurrent brute-force attempt against `/login` would be —
  intentional, matches the existing design philosophy, but worth stating plainly since it's a
  new way an operator could accidentally lock themselves out (mistyping at the unlock screen).
- **`audit_log` vs `login_events`.** Unlock success/failure are credential-check attempts →
  `login_events` (via `_log_login_event`, matching change-password's pattern). The
  lock-triggering transition itself (going idle → locked) gets its own `audit_log` row via
  `_audit("session_idle_locked")` (operator-approved 2026-08-01) — logged exactly ONCE per
  lock event, not on every subsequent blocked request while still locked. Simplest correct
  way to do that: set a session flag (e.g. `session['idle_lock_logged'] = True`) the first
  time the redirect fires, checked before calling `_audit()` again, and cleared on successful
  unlock alongside `last_activity`'s refresh — otherwise every blocked request during the
  locked period would insert a duplicate row.

## Schema changes

**None required.** `last_activity` lives in the signed session cookie, not the `users` table —
see §Current state for why that's sufficient here (no replay-forgery concern, unlike
`recovery_grace_until`). No new table, no `ALTER TABLE`, no Data Manager registration needed
for the core mechanism. (The `login_events` writes from unlock attempts go through the
existing `_users_conn()`/Data Manager path already in place for `_log_login_event`.)

## Unsaved work

The client-side overlay (never navigates away) covers the common case: a client that's
cooperating and fires its warning/lock UI in time preserves whatever's typed into the page,
because the DOM is never torn down. **A known limitation exists in a fallback path — see
`~/work/nemesis-internal/known-limitations/idle-lock-unsaved-work-gap-2026-08-01.md` for the
specific case and the operator's accepted-tradeoff decision on it (Rule 10 — not detailed
here).**

## Risks / things Window 1 needs to verify before or during build, not assume

1. **JS-include coverage.** The interaction-tracking script must reach every authenticated
   page, or pages missing it will false-positive idle-lock while genuinely in use. Requires an
   exhaustive check of all six main-app page-render functions (not just the one
   `_threat_indicator_html()` call site found by grep) to confirm there's truly one shared
   injection point, or to add the include to each one individually with a follow-up grep to
   prove coverage (e.g. every `<head>`/page function has the include, count matches).
2. **JS-in-f-string quoting.** CLAUDE.md's #1 recurring bug: this codebase renders HTML/JS
   from Python f-strings, and a raw apostrophe/double-quote/newline inside one causes a
   *silent* `SyntaxError`. The idle-lock snippet (JS string literals, any config value passed
   in) must use single-quoted JS literals or `json.dumps()` for anything dynamic (e.g. the
   configured timeout value), exactly per that standing rule.
3. **Throttling the touch endpoint.** The interaction listener must debounce client-side (not
   POST on every `mousemove`) — both for network chatter and because every `session[...]`
   write triggers a `Set-Cookie` on the response; touching on a fixed ~30–60s cadence (only
   when there was real interaction) keeps this cheap.
4. **`api_health` in both allowlists.** `_IDLE_LOCK_ALLOWED` reuses `api_health` from
   `_EXPIRED_ALLOWED` for the same reason — an external health check should not itself trip
   or be blocked by either control.

## Operator decisions (resolved 2026-08-01)

1. **Default timeout** — 15 minutes. ✓
2. **No-disable-switch stance** — v1 ships with no way to turn idle-lock off. ✓
3. **Lock-transition logging** — yes, an `audit_log` row via `_audit("session_idle_locked")`,
   once per lock event (see §Interactions for the dedup mechanism). ✓
4. **Unsaved-work fallback gap** — accepted as a documented tradeoff, extracted to the private
   known-limitations doc per Rule 10; no mitigation requested. ✓

No open design questions remain. Proceed to implementation (see §Implementation sequence
below).

## Non-goals (explicitly out of scope for this design)

- An absolute session-lifetime cap independent of activity (e.g. "log out after 12 hours no
  matter what") — a related but separate control; not requested, not designed here.
- Any change to `PERMANENT_SESSION_LIFETIME` / `session.permanent` — the idle check is a
  self-contained comparison against `session['last_activity']`, layered on top of whatever the
  underlying cookie lifetime already is, and doesn't need Flask's built-in mechanism touched.
- Multi-device/session management UI (listing or force-expiring a specific device's session)
  — no such UI exists today for anything else either; out of scope here too.

## Implementation sequence (proposed, for Window 1 — Window 2 does not write code)

One variable at a time (Rule 2), each step independently testable before the next lands.
Every step that ends in a `dashboard.service` restart is a STATE-CHANGING action per the
State Snapshots rule — Window 1 takes a dated USB snapshot (`alerts.db` + `STATE.txt`) before
restarting, even though no step here touches the schema, and reports what changed + confirms
the set was written before proceeding. No DB migration in this feature, so no separate
DB-only snapshot step — the service-restart snapshot covers it.

1. **`templates/unlock.html`** — new template only, styled consistent with
   `change_password.html`. Inert on its own (nothing routes to it yet); safe to land and
   restart with zero behavior change. Verify: page not reachable by any route, dashboard
   otherwise unaffected.
2. **Core enforcement: session init + `/account/unlock` route + `_IDLE_LOCK_ALLOWED` +
   the `_enforce_setup_and_auth()` check.** Bundled as one commit because splitting it further
   would leave an intermediate state where the redirect target doesn't exist yet or the check
   fires with no way to clear it. Includes: `session['last_activity']` set in `login()`
   alongside `login_user()`; `IDLE_LOCK_MINUTES` read from `/etc/nemesis.env` with a
   hardcoded-default fallback of 15 (matching `_PASSWORD_MAX_AGE_DAYS`'s style — a module
   constant is fine for v1 since there's no Settings-UI exposure yet, see step 6); the idle
   check itself (fail-closed on missing `last_activity`); the GET+POST `/account/unlock`
   route using `_check_password()` / `_register_credential_failure(..., source="idle_unlock",
   action="unlock")` / `_log_login_event(..., source="idle_unlock", action="unlock")`, no
   `logout_user()` call. **At this point idle-lock always fires at 15 minutes regardless of
   activity** (step 4 fixes that) — this is intentional and testable on its own: log in, wait
   past the timeout (or temporarily shorten it for the test), confirm every route redirects to
   `/account/unlock`, confirm the correct password clears it and returns to `next`, confirm a
   wrong password counts against the shared lockout-tier budget (check `login_events`).
   Verify: `py_compile`, then a real logged-in-session timeout+unlock cycle in a browser, plus
   confirming `login`/`change_password`/existing auth flows are unaffected.
3. **Audit row on lock transition.** `_audit("session_idle_locked")` called once per lock
   event via the `session['idle_lock_logged']` dedup flag (§Interactions), cleared on
   successful unlock. Verify: trigger a lock, confirm exactly one `audit_log` row appears (not
   one per subsequent blocked request); confirm a second lock cycle produces a second row.
4. **`POST /api/session/touch`**, gated by the SAME `_enforce_setup_and_auth()` idle check
   (i.e. blocked once already locked — no self-re-arming). Refreshes `session['last_activity']`
   only. No client JS yet at this step — verify by curling the endpoint directly with a valid
   session cookie, confirming it delays the next lock, and confirming it 401s/redirects like
   everything else once already locked.
5. **Client-side interaction-tracking JS**, injected at whatever the actual universal
   authenticated-page injection point turns out to be (verify the `_threat_indicator_html()`
   call site is genuinely shared across all six main-app page-render functions FIRST — do not
   assume; if it isn't, add the include to each render function individually and grep to
   confirm coverage count matches). Debounced touch calls on real interaction only; warning
   banner at T-60s; in-page lock overlay at timeout calling `/account/unlock` via `fetch()`.
   **Apply the JS-in-f-string quoting rule** (single-quoted JS literals / `json.dumps()` for
   the injected timeout value) — this is the codebase's #1 recurring bug and a silent
   `SyntaxError` here would break every authenticated page's render, not just this feature.
   Verify: manually exercise idle warning → overlay → unlock without a page reload on at least
   one page from each of the six render functions; confirm background `setInterval` polling
   (`refreshDashboard` etc.) does NOT by itself prevent the lock from firing.
6. **(Optional, negotiable) Settings-UI exposure for `IDLE_LOCK_MINUTES`.** The requirement's
   "configurable" is already satisfied by direct `/etc/nemesis.env` editing (documented, same
   as other advanced env values today) — Window 1's call whether to also surface it in the
   Settings page's env-config UI as a fast-follow within this feature or a separate later
   commit. If done, follows the existing `_update_nemesis_env()` → `write_env` →
   restart pattern exactly.

After the sequence lands and each step's own verification passes, a final end-to-end pass:
full login → idle past 15 min with the tab genuinely untouched → confirm lock fires → wrong
password a few times → confirm shared lockout-tier budget engages → correct password →
confirm return to `next` with session state intact → confirm exactly one `audit_log` row for
the lock and one `login_events` row for the successful unlock. Report real output (screenshots
or terminal, per Rule 3), not "should work."
