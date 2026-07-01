# Pre-1.0.8 build audit — installer text/behavior, tier-seeding, scope guardrail (2026-07-01)

> Read-only audit (Rule 1). Consolidates the day's build-window investigations against
> deployed server reality (commit `c9f0a2f`; installer file at HEAD `8e6bf9b`). No repo
> files changed, nothing built. Rule 8: placeholders only — code line refs + commit
> hashes, no infra values.
>
> **Server ground truth (deployed):** auto_approve defaults to **0** (opt-in checkbox on
> the generate form); devices land **PENDING**; manual approval via Settings → Devices;
> self-onboard rides a baked single-use Tailscale pre-auth key.

---

## Part 1 — Installer client-facing TEXT audit (vs server reality)

Every user-visible string in `nemesis_agent/installer_gui.py` was reviewed. Stale items:

### 🔴 STALE — describes the OLD flow

**1A. First-screen Tailscale instructions (PL-10) — `installer_gui.py:92–93`**
> "Before you start: install Tailscale (tailscale.com/download), log in with the account
> your admin gave you, and wait for its green checkmark."

The self-onboard path **auto-installs Tailscale and auto-joins via the baked pre-auth key**
(`_join_tailnet_with_preauth_key`, l294–336) — the user does neither. **Nuance:** this
`steps_text` is built **unconditionally** in `__init__` (l91–102), so it shows even when a
`preauth_key` is baked (the primary path), where it is flatly wrong; it is accurate only for
the no-key manual fallback. *Should* be conditional on `preauth_key` (self-onboard →
"Just click Install; setup handles the secure connection for you").

**1B. "Now protected" overstates completion — `installer_gui.py:28` (STEPS[3]) and `:99`**
> "Done! Your device is now protected."

With `auto_approve=0`, enrollment lands the device **PENDING**; agent heartbeats are gated
(`_agent_approved` false) until an admin approves. At "Done" the device is
**enrolled-but-awaiting-approval, not protected.** Appears **twice** (l28, and quoted inside
`steps_text` at l99) — must change together. *Should* read e.g. "Setup complete. Your device
is enrolled and waiting for your administrator to approve it."

### ⚠️ GAP — a missing string, not a stale one
There is **no pending/approval messaging anywhere** in the installer. Under PENDING-by-default
the completion screen should tell the user the device is waiting for admin approval. Today the
flow says "protected" and stops. Capture as its own item.

### 🟡 CONDITIONAL — correct only for the no-key fallback (not stale, flag for consistency)
`_ensure_tailscale` messages at **l225–226, l231–232, l238–240** ("install Tailscale… sign
in… Retry" / "log in with the account your admin provided"). Accurate for the **no-preauth-key
fallback** and **not shown** during self-onboard — the OLD default, now demoted to fallback.

### ✅ ACCURATE — matches self-onboard reality (no change)
`_join_tailnet_with_preauth_key` messages (l306, l308–309, l315, l325 "This installer is
spent…", l333–334) and `_verify_nemesis_reachable` (l251, l263–267).

### Secondary — stale code comments/docstrings (NOT user-visible)
`l7` ("with the token → auto-approve"), `l486` ("server auto-approves on a valid token"), and
the auto-approve framing near `l355–356`. These describe auto-approve as the default; it is now
opt-in. Flagged for accuracy since the file is being edited; no user impact.

---

## Part 2 — Installer BEHAVIOR vs server

| Server reality | Installer behavior | Match? |
|---|---|---|
| Self-onboard via baked single-use pre-auth key | `_join_tailnet_with_preauth_key` (l294–336): auto-install on bare box → `tailscale up --authkey` **once**, linear/no-retry → bounded state poll | ✅ |
| Conf consume-and-delete | `_consume_conf` (l338–348) deletes the sidecar at `_run` start (l354) | ✅ |
| device_id persist (fix #3) | `_enroll` l502–509 persists `device_id` + status | ✅ |
| auto_approve default 0 → PENDING | Installer is token-agnostic (server sets auto_approve) — behaviorally fine | ✅ behavior / ❌ text |

**The one mismatch is text, not logic:** the flow reaches "Done! Your device is now protected"
and starts the agent (`_start_agent_now`, l375) while the device is **PENDING** and gated until
manual approval; and the first-screen text tells the user to manually install/login to Tailscale
while the code does it for them (1A). Logic is correct and server-aligned; the user-facing
narrative is stale.

**Fix #3 confirmation:** present in current `main` (`installer_gui.py:502–509`, landed by
`c9f0a2f`). `build_installer.py` bundles `installer_gui.py` into the PyInstaller exe, so it
**ships in the next regenerated installer** — it is **not** in any already-distributed exe.
Activating it requires a regenerate + fresh installer link.

---

## Part 3 — Tier-seeding scope (dashboard Beginner/Intermediate/Pro from an installer picker)

**Tier storage today:** browser **localStorage only**, client-side. `static/tier.js`:
`STORAGE_KEY='explanationTier'`, `VALID=['beginner','intermediate','pro']`, `DEFAULT='intermediate'`
(l64–66); `getTier()` reads localStorage (l68–72), `setTier()` writes it (l74–79). It is
**per-browser/global**, not per-device.

**Server-side per-device tier:** **none.** No `tier` column on `agent_devices`; no settings row
keyed by device_id. (All Python/DB "tier" hits are unrelated: readiness "Tier A/B" attribution,
`lockout_tier`, malware "middle-tier".)

**Enrollment payload:** `/enroll` sends `source, public_key, device_name, os, os_version,
hardware_summary, signed_at, signature, pre_enrollment_scan, link_type, hardware_fingerprint,
enrollment_token` (`enrollment.py:243–255`) — **no tier**; the server INSERT
(`hw_monitor.py:1993`) stores a subset — **no tier**. A tier value **cannot ride existing
fields**: it needs a new `nemesis_install.conf` key → new payload field, **and** a new
`agent_devices` column added to the INSERT.

**Dashboard read path:** the dashboard reads tier **only** from localStorage (`getTier()`).
No server→tier read path exists. Devices render from `agent_devices` at `dashboard.py:1564`, so a
column would be available there, but consuming it needs new JS (seed localStorage from the value,
or teach `getTier()` to consult a server value). A design decision hides here: today's tier is one
global preference — "seed a device's tier" is either a one-time default seed (smaller) or a true
per-device tier model (a model change the global design doesn't support).

**Classification: REAL FEATURE (not a small wire)** — greenfield end-to-end.

| # | Component | Effort |
|---|---|---|
| 1 | Installer tier-picker UI (installer_gui.py and/or generate form) | NEW |
| 2 | Carry tier: picker → conf key → enroll payload field | SMALL (copy existing field plumbing) |
| 3 | Server: new `tier` column on `agent_devices` + guarded migration + parse + INSERT | SMALL-mechanical, NEW schema |
| 4 | Dashboard read path: surface per-device tier + JS to seed/consume localStorage | NEW |
| 5 | Design call: global-default-seed vs true per-device tier | decision, not code |

~4 code components + 1 schema migration + 1 design decision, spanning installer + agent + server
schema + dashboard JS (four layers). Cheapest variant (#5 = "seed the global default once") trims
#4 to a few lines, but #2/#3 (payload + column) are unavoidable.

---

## Part 4 — Scope-attribute guardrail (future per-device authorization)

**Existing home for a scope attribute:** `agent_devices` has **no** `scope`/`access_level`/`role`/
`user_id`/`owner` column. The only JSON-ish field, `last_heartbeat_data` (l205), is **overwritten
every heartbeat** — unsuitable. A future scope attribute **needs a schema change** — but a cheap one.

**Add a nullable scope column now? — Not necessary.** The codebase retrofits `agent_devices`
columns via idempotent guarded `PRAGMA table_info` + `ALTER TABLE ADD COLUMN` migrations (how
`hw_stable_id`, `link_type`, `hw_is_virtual` were added to existing rows with **zero
re-enrollment**). A future `scope` column drops in the same way, defaulting existing devices to
full-access. Adding it now buys nothing and cuts against "leave the socket, don't wire the house."

**Dashboard read path assumption:** `_render_agent_devices_html` (`dashboard.py:1564`) does a single
**unfiltered** `SELECT ... FROM agent_devices` — shows all devices to the logged-in admin (expected
single-user model). It is **one centralized read path**, so adding a per-user/scope `WHERE` later is
a clean additive change at one hook. Other device reads are narrow (scan history already
`device_id`-filtered at l6120). **Verdict: neutral-to-favorable**, not resistant.

**Minimal "don't-block-it" guardrail for today's build (no scope code needed now):**
- Keep device-list reads flowing through the single `_render_agent_devices_html` path — don't
  scatter new `SELECT … FROM agent_devices` reads with hardcoded "all devices" assumptions.
- Keep populating `enrolled_by` on enrollment (already done) — the actor seam a future owner/scope
  anchors to.
- Don't fake a scope/owner value inside `last_heartbeat_data` or any volatile JSON blob.
- If the tier column lands, add it via the same guarded-`ALTER` pattern scope will use later.

The later scope feature is already set up to be **additive** — guarded `ALTER ADD COLUMN scope` + a
`WHERE` at one read path, no re-enrollment. Only scattering un-centralized reads or faking a scope
field would break that.

---

## Part 5 — Bottom-line summary (1.0.8 sizing)

| Build decision | Size | Trip timing |
|---|---|---|
| **Installer text fixes** (1A PL-10 first-screen, 1B "now protected", + pending-approval message) | **SMALL** (text-only, ~2 strings + 1 new message; conditional-on-preauth_key logic is the only care) | **Trip-safe** — matches deployed reality; do before regenerating the trip installer |
| **Tier-picker + tier-seeding** | **REAL FEATURE** (~4 components + schema migration + design call) | **Post-trip** — spans 4 layers; not same-day; not trip-critical |
| **Per-device scope attribute** | **No build now** — guardrail only | **Post-trip** (with multi-user); today's work stays additive if the 4 guardrail items are respected |

**One-read takeaway:** only the installer **text fixes** belong in a pre-trip 1.0.8 (small, and
required so the regenerated installer's words match the PENDING/self-onboard reality). Fix #3
(device_id persist) is already in `main` and ships with that regenerate. Tier-seeding is a real
post-trip feature. Scope needs **nothing today** beyond not painting the read path into a corner.
