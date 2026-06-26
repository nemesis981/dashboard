# Settings Page — UI-vs-Reality Audit

- **Date:** 2026-06-25
- **Mode:** Audit only — no code changed, no fixes applied.
- **Scope:** The Settings page (`dashboard.py` `settings_page()` render) and its supporting
  module/status code. Hunting for UI that shows a state which may not match what the system
  actually does — prioritising cost- and data-egress-relevant disconnects.

> Sanitized for the public repo: no home paths, no real IPs. Env-var **names**
> (`ANTHROPIC_API_KEY`, `ABUSEIPDB_KEY`) are referenced, never values.

## The core pattern

The settings page renders each module's status from the **toggle/enabled flag**
(`is_enabled`), not from the module's **actual runtime state** (`status()`). "Enabled"
(green) therefore means *"the module's code is loaded / toggled on"* — it says nothing
about whether the feature is configured, reachable, or actually doing anything. This is the
same conflation that motivated the audit (ai_engine `required`), and it recurs across the
page. Notably, the real per-module status **is** already available
(`modules_loader.module_status()` is returned by `/api/modules`, `dashboard.py:4294`/`4305`)
— the rendered page just doesn't use it.

---

## Findings (ranked — cost/safety first)

### 1. [HIGH · cost] `ai_engine` shows "Enabled / core" regardless of whether AI can actually run
- **Location:** `dashboard.py:1558,1566–1567,1580` (row status) + `:1564,1574–1577` ("core"
  badge) ; real key state computed at `:1519–1533`, shown only in the sub-panel `:1617`.
- **UI implies:** Green **"Enabled"** + **"core"** badge + lock → "AI is on and working."
- **Actually does:** AI does nothing without `ANTHROPIC_API_KEY`. The module's own
  `get_status()` returns `active` | `no_key` | `disabled`. The row label is from
  `is_enabled` (loaded/toggled), **not** `get_status()`. The honest key indicator
  (green/amber/red) exists but only *inside* the sub-panel; the headline row stays green.
- **Why it's a disconnect:** A user reads the green row as "AI active." With no key it's
  inert (missed analysis); with a key + nonzero rate limits it spends money — neither is
  conveyed by the row.
- **Proposed fix:** Render the ai_engine row status from `get_status()`
  ("Active" / "No API key" / "Disabled"), not from `is_enabled`.

### 2. [HIGH · generalized] Every module row's status is the toggle flag, never `status()`
- **Location:** `dashboard.py:1566–1567`, emitted at `:1580` and `:1594`; contrast the
  unused real source at `:4294`/`4305`.
- **UI implies:** Green "Enabled" = "this module is working."
- **Actually does:** `status_label = "Enabled" if enabled else "Disabled"` — purely the
  toggle. The module's real `status()` (running/stopped/**error**) is ignored. Example:
  the `dhcp` module's `status()` returns `error · "cannot reach Pi-hole"` when Pi-hole is
  down, but the settings row would still show **"Enabled"** green.
- **Why it's a disconnect:** "Enabled" ≠ "working" for any module; an errored/stalled
  module still looks healthy on the settings page.
- **Proposed fix:** Drive the row label/colour from `modules_loader.module_status(name)`
  (running/stopped/error), with the toggle separate.

### 3. [HIGH · data egress / cost] AbuseIPDB auto-report threshold implies reporting that may not be happening — or silently is
- **Location:** threshold UI `dashboard.py:1828–1860`; runtime gate
  `modules/anomaly_detection/module.py:985–993` (`_auto_report_abuseipdb` — *"If
  `ABUSEIPDB_KEY` is absent, returns silently"*).
- **UI implies:** Choosing "Medium-and-above" / "High-only" / a custom score = "IPs at this
  threshold are auto-reported to AbuseIPDB."
- **Actually does:** With **no `ABUSEIPDB_KEY`**, nothing is ever sent (silent no-op) — yet
  the control shows an active threshold. With a key, IP reports **are auto-sent to a third
  party**, and the control never surfaces the key requirement or the data-egress (unlike
  the AI section, which shows key status).
- **Why it's a disconnect:** Either the user thinks reporting is on when it's a no-op, or
  they don't realise selecting a threshold sends data externally and automatically.
- **Proposed fix:** Show `ABUSEIPDB_KEY` presence beside the threshold and label it
  "auto-sends IP reports to AbuseIPDB" (disable the control when no key).

### 4. [MED · conceptual root] `required: true` / "core" conflates "code must load" with "feature enabled"
- **Location:** `dashboard.py:1564,1568,1574–1577,1582–1584` ("core" badge, lock, tier text
  "Required — cannot be disabled").
- **UI implies:** "core / required / locked" reads as "this feature is on and essential."
- **Actually does:** `required` only guarantees load order and that `set_enabled` raises
  (the code can't be unloaded because other modules import it). It says nothing about the
  feature being configured or active. This is the root cause of #1.
- **Why it's a disconnect:** Two orthogonal axes — *loaded* vs *active* — are shown as one.
- **Proposed fix:** Reword to "core (always loaded)" and show feature/active state from
  `status()` separately from the load-lock.

### 5. [MED · cost] AI rate-limit & "allow manual analysis" controls render as live even with no key
- **Location:** rate fields `dashboard.py:1622–1633`; "allow manual AI analysis when rate
  limit reached" `:1817–1826`; "show AI suggestions" `:1767–1779`.
- **UI implies:** Spend controls are in effect and meaningful.
- **Actually does:** With no `ANTHROPIC_API_KEY`, none of these can cause (or prevent) spend
  — there is no AI to rate-limit. They appear fully active regardless.
- **Why it's a disconnect:** Same family as #1 — implies an active cost surface that may be
  inert. (When a key *is* present, the manual-override toggle genuinely increases spend, so
  it should read as cost-relevant.)
- **Proposed fix:** Gate/annotate these controls on key presence (disabled + "needs API
  key" when absent).

### 6. [MED · delivery] No settings-page signal that email alerts are actually being delivered
- **Location:** email config is wizard-only (`dashboard.py:3313–3324`, has a test button);
  no module-row/status equivalent. Failures are log-only (`watchdog.log`:
  "Failed to send alert email…", referenced `dashboard.py:47`).
- **UI implies:** Once SMTP is configured in the wizard, alert emails "work."
- **Actually does:** If SMTP creds are wrong/expired, sends fail **silently** at runtime;
  the only evidence is a log line. The settings page shows no last-send/health state.
- **Why it's a disconnect:** A safety-relevant notification channel can be dead with no
  surfaced indication.
- **Proposed fix:** Surface last email-send result (ok/failed + time) on the settings page.

### 7. [LOW] Module toggle shows the new state before a restart actually applies it
- **Location:** toggle `dashboard.py:1596–1600`; caveat `:2233–2234` ("Dashboard restart
  required for module changes to take effect / Flask restart").
- **UI implies:** Flipping the toggle changed the module's runtime state now.
- **Actually does:** Route/feature changes need a dashboard restart; the checkbox/label can
  show the target state while runtime hasn't changed.
- **Why it's a disconnect:** Transient mismatch between shown and effective state.
- **Proposed fix:** Show a "pending restart" badge on a toggled-but-not-yet-applied module.

### 8. [INFO · correctly derived — contrast] AI header incident badge & Anthropic Service Status
- **Location:** `dashboard.py:6579` (`ai-status-badge`), `:6439`, settings panel `:1437`/
  `:1794` — all from `get_incident_state()` / `get_incident_banner_html()`.
- These **are** derived from the real Anthropic-status poll (not assumed), and are the right
  model to copy for the disconnects above. Included as a positive reference, not a defect.

---

## Summary

7 disconnects + 1 positive contrast. The unifying defect: **the settings page reports the
toggle/enabled flag as if it were runtime state**, and treats "module loaded" as "feature
active." The fix direction is consistent — render module/feature status from the existing
`status()` / `get_status()` / key-presence signals (already available) instead of from
`is_enabled`. Highest impact: #1 and #3 (a user can misjudge whether money is being spent or
whether IP data is being sent to a third party).
