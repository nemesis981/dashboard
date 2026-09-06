# Roadmap — Agent-update scheduling: state-awareness, fairness, and why not Wake-on-LAN

- **Status:** **DECISION CAPTURED, 2026-09-06 — build order operator-approved, nothing built
  yet.** Build state-awareness + a retry queue + fairness ordering. **Do NOT build
  Wake-on-LAN.** If proactive wake is ever wanted later, use agent-armed RTC wake timers, not
  magic packets. Investigation and reasoning: Window 1, 2026-09-06. Written up: Window 2.
  Full measurement provenance (including a corrected earlier analysis, retracted rather than
  annotated): `~/work/nemesis-internal/handoff/2026-09-06-window1-handoff.md` (private mirror,
  commit `082badb`).

## 1. The reframe this decision rests on

The danger of a fleet reconverging online after a rollout pause is not **exposure duration**
— it is **starvation**. A strictly sequential, one-device-at-a-time rollout may never *reach*
a device whose online windows are short and fragmented. Measured on the one device with real
history (§3): at roughly 90 minutes online per day, spread in fragments, against a queue that
needs 100–200 contiguous minutes to work through a 20-device fleet, that device can be skipped
day after day while the queue itself looks healthy — nothing about the queue's own state would
say so.

**Fairness ordering fixes this. Waking a device does not** — a device that gets woken still
has to wait its turn in a queue with no fairness. The two are not substitutes for each other,
and the measurement work below exists to establish this before either gets built.

## 2. Why wake is not *necessary* — only faster

A genuinely suspended device is not exposed: nothing of the product is running or listening on
it. The exposure window starts the moment it comes online on its own, and a priority queue can
act on it in the first seconds of that window rather than waiting for its turn. The residual
gap — a device wakes, gets used, and sleeps again before a critical update finishes landing —
is narrowed by priority-on-checkin ordering, not eliminated by pre-waking either. Waking a
device earlier buys speed, not correctness; the correctness problem is starvation, and fairness
is what closes it.

**Amendment, 2026-09-06 later the same day — a shipped capability already narrows the residual
gap above, with no wake mechanism at all.** `nemesis_agent/agent.py` (`8722521`, Window 3) now
detects a suspend/resume as a wall-clock jump measured inside the poll loop's own sleep
(deliberately wall-clock rather than monotonic: Linux's `CLOCK_MONOTONIC` excludes suspended
time, so a monotonic check would still wait out the pre-suspend timer after waking, which is the
exact bad case; wall-clock advances correctly on both Linux and Windows). Detection routes
through the existing early-beat request path, so it inherits the standing rate limiter — a false
positive (an NTP step) costs exactly one extra heartbeat, not a new failure mode. Independently
re-run: `test_resume_detect.py`, 24/24 (was 21; see the latency note below). The original "5/5
mutations killed" claim was commit-message-sourced and unrun by either reviewing window — now
made reproducible rather than re-argued: `nemesis_agent/mutate_resume_detect.py` (`fe0f8b4`) is
a one-command gate (mutates a private temp copy, never the shared checkout; checks its own
baseline first; distinguishes a moved anchor and a no-op mutation from a real kill) that ADDS a
sixth mutant targeting the exact tunable relationship in the latency note below, which the
original five did not cover. Independently run: **all 6 mutants caught, exit 0.**

**The latency claim is a relationship between two tunables, not a fact about either alone, and
it is now pinned by a test rather than left to arithmetic.** The detection slice
(`RESUME_CHECK_SLICE_S`, 60s) has to exceed the early-beat rate limiter
(`POLL_INTERVAL_FLOOR`, 15s) for the resume beat to fire promptly — on Linux, monotonic time
does not advance during suspend, so `_last_beat_at` can still look recent after hours of
wall-clock time, and the floor could in principle hold the beat back. `2bf05e5` (Window 3, same
day) added the test that exercises this exact interaction with a realistic last-beat time rather
than the sentinel the other integration cases use to factor the floor out deliberately — tune
the slice below the floor and the timing claim below would silently go false with every other
test still green. Independently re-run: 24/24.

Effect on this document's own reasoning, worded to avoid hard-coding either tunable: a resuming
device now announces itself within about a minute of waking, rather than waiting out up to the
full 300-second poll interval, so "update-on-checkin priority" (§3 item 2) gets a materially
earlier trigger — the resume beat itself is the trigger. This makes the no-wake case in this
section stronger, not weaker: the latency gap a wake mechanism would have existed to close was
closed here with no wake mechanism at all. See §6 for
the one caveat (capability, not yet coverage).

## 3. Confirmed build order

1. **State model (online / suspended / offline / unreachable) + a retry queue that re-attempts
   at the device's next check-in, rather than blocking the whole rollout on one unreachable
   device.** Stand-alone; confirmed to build first.
2. **Fairness + resumability**: oldest-failure-first ordering, update-on-checkin priority (a
   device that just came online gets its overdue update before anything else queued for it),
   and chunked/resumable transfer so a short online window still makes forward progress instead
   of restarting from zero next time.
3. **Pattern-aware staggering** (predicting *when* a device is likely to be online and timing
   rollout waves around it) — **deferred until multi-device history exists to actually test the
   premise.** See §4; the one device measurable today argues against the premise it would rest
   on, not for it.
4. **Agent-armed RTC wake timers** — deferred until a real operational need is demonstrated,
   and gated on the agent first reporting its power source (see §6). Not Wake-on-LAN; see §5
   for why.

## 4. Why pattern-aware staggering is deferred — measured, not assumed

Three facts, each verified independently against live `alerts.db` before this doc was written,
not merely relayed from Window 1's own report:

- **A presence-history substrate already exists with no new schema.** `hw_metrics` writes one
  row per heartbeat, carrying `device_id` and `timestamp`. No dedicated presence table is
  needed to start measuring this.
- **The fleet is `n=1` for learning purposes today.** Grouping `hw_metrics` by `device_id`:
  `local` (the appliance itself, not an agent) carries 21,918 rows across 78 days; the one real
  agent with meaningful history (`ece4736c...`, "trip-laptop"/`<lan-friendly-name>`) carries **731 rows
  across 40 distinct days**; the only other enrolled agent has carried exactly **1 row**. A
  pattern-aware scheduler has essentially nothing to train against yet.
- **The one device that CAN be measured is not schedule-shaped.** Its busiest 2-hour window
  holds only **~26% of its check-ins** (188 of 731, independently re-derived from live data),
  spread across roughly 20–21 of 24 hours. That is a household laptop used irregularly, not a
  fleet booting at a fixed hour. The premise a pattern-aware scheduler would need — a
  recognizable, exploitable online schedule — is directly testable on the only device available
  to test it against, and it does not hold there. Building staggering logic now would be tuning
  a model to a sample of one, and the one sample argues against the shape of model being
  proposed.

## 5. Why Wake-on-LAN specifically was rejected, not merely deferred

This was investigated in detail because an earlier read of the situation (an agent that had
gone silent, believed to be on a different site) suggested WoL might be the fix — that read was
**wrong and has been corrected, not merely appended to**: the device in question
("trip-laptop"/tailnet name `<tailnet-hostname>`) is LAN-local, not remote, and its MAC
was already sitting in the `devices` table under its LAN friendly name the whole time — a correlation ADR 0023
exists specifically to make automatic and currently does not, on this exact device, because it
runs a pre-2026-08-19 agent that never reports `lan_macs`. Even with the "no broadcast domain"
blocker resolved by this correction, the decision stands: **do not build WoL.** Measured against
the four safety constraints any wake mechanism would need to satisfy:

| Constraint | Wake-on-LAN (magic packet) | Agent-armed RTC timer |
|---|---|---|
| Authenticated wake | **Fails by construction.** A magic packet is matched by NIC firmware against a byte pattern; there is no inbound authentication to check. Vendor "SecureOn" is a 6-byte plaintext field, not real auth. | **Solved by construction.** No inbound packet exists to spoof — an already-authenticated agent arms the timer locally, before it suspends. |
| LAN-only / needs a collected MAC | Requires L2 adjacency and a correlated MAC (the ADR 0023 gap this very investigation ran into). | **Dissolved.** No L2 adjacency and no MAC collection needed; works over Tailscale. |
| Battery / physical safety | Not addressed by the mechanism itself. | **Partly free** — OS power policy (confirmed for Windows) already disables wake timers on battery by default, which aligns with the safety requirement rather than fighting it. |
| Per-device opt-in | Requires enforcement elsewhere (the mechanism itself has no opt-in concept). | **Unchanged, still required, and easier to honour** — an excluded device simply never arms a timer. |

The one thing WoL can do that an armed timer cannot is **wake right now, on command** — and
that is precisely the case argued unnecessary in §2, and the case that carries all of the
authentication risk in the table above. Additional honest limits of the timer approach, recorded
so they aren't rediscovered later as surprises: it requires the agent to have been running
*before* the device suspended (true for exactly the population an update rollout would target);
the wake time has to be chosen in advance, so it cannot serve an on-demand emergency case; and
RTC wake generally does not work from a full shutdown (ACPI S5), only from sleep/standby.
Mechanisms, for whoever picks this up later: Windows Task Scheduler's "wake the computer to run
this task" / `powercfg`, Linux `rtcwake` or systemd `WakeSystem=true`, macOS `pmset schedule`.

## 6. Prerequisites before any wake mechanism is buildable

- **The agent must report its power source.** No battery/AC-state column exists anywhere in the
  schema today (`gpu_power_watts` is GPU power draw, not battery/AC state, confirmed by
  direct schema inspection) — the battery-safety constraint above is currently
  unimplementable for lack of this one field.
- **The agent-update gap itself is the prerequisite underneath every item here.** The empty
  `agent_device_macs` table (§5, the ADR 0023 correlation) is the same problem wearing a
  different hat: the correlation code is correct and has simply never reached the one device
  old enough to need it, because that device has never been updated. Closing the agent-update
  gap this whole roadmap item is about is also what would let ADR 0023's own correlation work
  the way it was designed to.
- **Pattern-aware staggering (§3 item 3) needs more than one device with real history** before
  its premise can be tested rather than assumed — see §4.
- **The resume-detection capability (§2 amendment) is capability, not coverage.** Every
  currently-enrolled device runs agent code that predates it and gains nothing from it until
  reinstalled — the identical shape as the `agent_device_macs` gap two bullets up: correct code
  that has not yet reached the fleet it would help.
- **Any fairness/queue design assumes check-in work actually gets enqueued — that assumption
  was false until this same afternoon.** `core_module/hw_monitor/hw_monitor.py` (`dcbf625`,
  Window 3) fixed a self-deadlock where `enqueue_task` opened a second SQLite connection while
  the heartbeat's own transaction held the writer lock, so every `attest_manifest`/
  `attest_challenge` enqueue attempt failed silently behind a "never raises into the beat"
  contract — three days, 58 occurrences, invisible because the failure logged to a sink nobody
  was reading next to the one that looked healthy. Independently verified:
  `test_enqueue_task_deadlock.py`, 17/17. Recorded here because it is load-bearing for this
  whole roadmap item specifically: a fairness queue built on top of an enqueue path that quietly
  drops work would look correct in the same way the deadlock itself looked correct for three
  days — right up until someone checked whether a row actually landed.

## 7. Not built here

Per Rule 1, this document captures the decision; it changes no code. See §3 for the confirmed
build order once implementation starts.
