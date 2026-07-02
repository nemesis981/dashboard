# Roadmap — Dashboard roles / access-control levels (learning-gated)

**Status:** capture (foundational design item; **post-trip**, build NOT started). Design of record
for the dashboard permission model. Start simple, room to grow — do NOT over-engineer upfront.

**Rule 8:** placeholders only — no real IPs/hosts/accounts/keys.

> Capture only — no code, no build. Foundational: this is the access-control model the sensitive
> server→agent features (push-and-run diagnostics, one-click diagnostic-logging) authorize against.
> **Architectural home:** extends / feeds **[ADR 0007 — Device-User Relationship Model](../architecture/0007-device-user-model.md)**
> (Proposed, commercial-tier) and the auth/key model in
> **[ADR 0005 — device-auth](../architecture/0005-dns-firewall-device-auth-architecture.md)** /
> **[ADR 0011 — enrollment security](../architecture/0011-enrollment-security-model.md)**. Likely
> graduates to its own ADR (or an ADR 0007 addendum) when scheduled. Relates to the AI-tutorials
> plan (`ai-generated-tutorial-walkthrough.md`) — which this makes **load-bearing** — the
> server-tasks-consenting-agent pattern, and the push-and-run diagnostics feature
> (`diagnostic-scan-scope.md`).

---

## Current state (audited at design time, 2026-07-02)

Roles are **seamed but not enforced** — the socket exists, the house isn't wired (per the CLAUDE.md
multi-user-ready rule):
- **Flask-Login is done.** `dashboard.py` uses `login_required` / `current_user`; a `users` table
  exists (`alert_manager/database.py`).
- **A `role` column already exists** on `users`: `role TEXT NOT NULL DEFAULT 'admin'` — commented
  *"'admin'|'user' (commercial seam)"*. So the storage seam is present.
- **But there is NO role enforcement.** `_create_user()` and the signup route create everyone as
  `role="admin"`; no route checks `is_admin` / role to gate view-only vs powerful actions. Every
  logged-in user is effectively full admin today.
- **No per-capability permission storage** exists yet (no `user_permissions` / learning-unlock
  table). `device_user_permissions` is referenced as a commercial-tier future (ADR 0007), not built.

**Net:** the two-value seam is there; the tiering, enforcement, learning gate, and key-pair
authorization are all to-build. Confirm this still holds at build time.

## Role model (three-layer; start simpler, grow into it)

1. **USER — view-only + limited settings.** Read the dashboard; a **limited settings page** for
   *own preferences / basic config only*. **Cannot** take powerful/sensitive actions (no approvals,
   no push-and-run, no firewall changes). Powerful buttons are **hidden/disabled**, not just
   server-rejected.
2. **SUB-ADMIN — learning-gated, per-capability.** A delegated operator who **earns elevated
   permissions one capability at a time** via a **LEARNING GATE**: watch that capability's tutorial
   + pass its quiz → **that** capability unlocks for them. **Progressive and per-capability, not
   all-or-nothing.** This is the delegation tier — the owner can hand out access without handing out
   the ability to break things.
3. **FULL ADMIN — ungated, full perms.** The trusted owner / setup person. Full access outright,
   **not** slowed by learning gates. Can delegate (create sub-admins), approve, change all settings,
   and trigger the sensitive server→agent tasking.

**Optional finer granularity (LATER, only if real need emerges — do NOT build upfront):** e.g. an
"approve-but-not-push" mid-tier within admin. Add granularity only when a concrete need appears;
don't over-engineer the role system at the start.

## CRITICAL BOUNDARY — the learning gate is NOT the security boundary
Bake this into the design so it can't be misread later:
- The **learning gate proves COMPETENCE / understanding, not AUTHORIZATION.** A quiz stops an
  *untrained* delegate from firing a dangerous task by accident; **it does not stop an attacker** —
  an attacker isn't inconvenienced by a tutorial.
- It is **one layer of defense-in-depth**, layered *on top of* real authorization — it never
  **replaces** the verified-admin-role + key-pair check.
- A dangerous action requires **ALL** of: **(a)** correct **role tier**, **(b)** **learning-gate
  unlock** for that specific capability (for sub-admins), and **(c)** **key-pair / auth
  verification**. Missing any one → **NO action.**

## Authorization gate — push-and-run diagnostics (the sensitive server→agent tasking)
The server-side authorization gate for push-and-run (and one-click diagnostic-logging) requires
**BOTH**, and pairs with the agent-side consent for defense-in-depth:
1. **Verified admin-tier role** — FULL ADMIN, or a SUB-ADMIN who has **learning-unlocked** this
   capability. View-only USERs can't reach it (button hidden/disabled).
2. **Key-pair verification of the admin** — *mechanism TBD at design time:* a **new admin key
   pair**, vs. **tying into the existing enrollment/signing keys** (ADR 0011). Decide at build.
3. **(agent side, separate layer) per-device consent gate** — the target device's opt-in config
   must permit server tasking. This is the **server-tasks-consenting-agent** pattern: server
   authorizes + agent consents; both required.

**No valid admin role OR no valid key pair → NO action.** (Learning-gate unlock is an *additional*
requirement for sub-admins, not a substitute for either.)

## DB (seam → build)
- **Reuse the existing `users.role` seam**; extend the allowed values to the three tiers
  (`user` | `sub_admin` | `admin`) or an equivalent. Guarded `PRAGMA table_info` + `ALTER`/data
  migration per the DB rules — one canonical CREATE.
- **Add per-capability permission storage** for the learning gate — e.g. a
  `user_capability_unlocks(user_id, capability, unlocked_at, via_tutorial_id, quiz_score)` table
  (module/core-owned per ADR 0001; route writes through the Data Manager / single update path per
  ADR 0006; carry the **actor** seam). Capability keys name the dangerous actions
  (`push_and_run`, `firewall_change`, `approve_enrollment`, …).
- Route all of this through the single-writer / data-domain hooks (CLAUDE.md multi-user-ready) so
  the later commercial multi-user push has a clean seam.

## Target use case (who this is for — keep it in view during the build)
**Owner-operator delegation with built-in training.** A small-business **owner** (FULL ADMIN) — a
gas station or restaurant — adds an **assistant manager** (SUB-ADMIN) who needs genuine daily-ops
access, but the owner wants them **trained before they can touch dangerous capabilities**. The
learning gate handles this automatically: the assistant manager **earns each powerful permission**
by completing its tutorial + quiz, so the owner **delegates access without delegating the ability
to break things**, and without personally supervising every action.

## Value prop (commercial / multi-user tier)
Marketable to the target market (small businesses / no-IT-department owner-operators who add staff):
**"Give your staff access, but make them earn the dangerous permissions through training."** Role
delegation + training gates are exactly the kind of capability that **justifies a business tier** —
and they make the AI-tutorials roadmap load-bearing (completing a tutorial *does something*: it
unlocks capability). Fits the future commercial/multi-user tier (do NOT build the multi-user
machinery now — commercial-tier).

## Relationships & dependencies
- **ADR 0007** (device-user model, commercial-tier) — the architectural home; this is its
  dashboard-role dimension.
- **ADR 0005 / ADR 0011** — device-auth + enrollment signing keys; the "admin key pair" option may
  tie into these rather than mint a new pair.
- **ADR 0006** (Data Manager) — permission writes route through it (actor seam).
- **AI-tutorials** (`ai-generated-tutorial-walkthrough.md`) — the learning gate consumes tutorial +
  quiz completion; this makes that plan load-bearing.
- **Push-and-run diagnostics** (`diagnostic-scan-scope.md`) + one-click diagnostic-logging + the
  server-tasks-consenting-agent pattern — the sensitive features that authorize against this model.

## Build phasing (don't over-engineer upfront)
1. Enforce the **existing two values** first (USER view-only vs ADMIN full) — real enforcement on
   the seam that already exists, powerful actions hidden for USER.
2. Add the **key-pair authorization** on push-and-run (role + key pair).
3. Layer in **SUB-ADMIN + the per-capability learning gate** (needs the AI-tutorials plan).
4. Add finer admin granularity (e.g. approve-but-not-push) **only if a real need emerges.**

**Do NOT build now.** Post-trip. Graduate to an ADR (or ADR 0007 addendum) + build spec when scheduled.
