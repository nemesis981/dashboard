# Agent-side local notification on connectivity loss — stub

- **Status:** PARKED, captured 2026-09-06. Not built. Split out deliberately from the same
  day's two agent-resilience fixes (local engine-health visibility, checkin-staleness
  escalation — see `docs/audits/` private mirror for the full investigation) because this
  one is a real design task, not a bounded fix.

## What prompted this

A resilience audit into what protection the endpoint agent (`nemesis_agent/`) provides when
it can't reach the dashboard found that a local detection — a malware-scan finding, a
Suricata IDS alert, a behavioral (Falco/Sysmon) event — currently produces **no proactive
local alert to the user at all**. Notification is entirely server-mediated:
`agent.py`'s `_send_notification()` has exactly one call site, driven by a server-pushed
`"notify"` task delivered in a heartbeat *response* (`_handle_response_tasks`). If the
heartbeat can't complete, that whole path never runs — a real local finding just sits
queued (or, for scan/Suricata results, isn't even queued anywhere the GUI reads) until
connectivity returns and the server decides to push a notification back.

Behavioral findings ARE visible locally today, but only passively — via the GUI's
Findings tab, which a user has to think to open. There is no equivalent of a Windows
toast/balloon firing at the moment of detection when the server can't be reached.

## Why this is a design task, not a quick fix

- **Debounce/rate-limiting is a real question.** A machine actively under attack, or a
  noisy behavioral rule, could otherwise spam desktop notifications. The existing
  `_recent_findings` buffer has no de-duplication or severity threshold built for this
  purpose.
- **Which findings warrant an autonomous local alert is a product decision**, not an
  engineering default. Every behavioral event? Only HIGH severity? Only when
  disconnected, or always (with the disconnected case just being the one that matters
  most)?
- **Interacts with the connectivity-staleness escalation work landing alongside this
  audit** (`agent_gui_core.py:overall_state()`) — once that escalates state after a
  prolonged outage, does crossing that same threshold also fire a "you're on your own for
  now" notification, or are these two independent triggers? Worth deciding together
  rather than shipping one, then bolting the other on later and re-deriving the interaction.
- **Platform-specific delivery** (Windows toast / macOS notification center / Linux
  notify-send) already has a working path via `_send_notification` — the design gap is
  entirely about WHEN to call it autonomously, not HOW to deliver it.

## What's already true and doesn't need re-deriving

- The delivery mechanism (`_send_notification`, cross-platform) already works and is
  already exercised by the server-pushed path — this is not new plumbing, it's a new
  local trigger into existing plumbing.
- `_recent_findings` (behavioral only) and the checkin-error state (`_last_post_error`,
  `_last_post_fail_at`) are the two candidate trigger sources already available in memory
  with no new instrumentation needed.

## Not scoped further here

Deliberately left open rather than guessed at: notification content/wording, debounce
window, severity threshold, and whether this ships as a standing feature or something a
user can turn off (per the existing agent config pattern of `scan_on_reconnect`-style
booleans). Graduate to a full build spec once these are discussed.
