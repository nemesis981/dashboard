# Roadmap stub — Windows agent rework, tied to the paused memory-injection module

**Status:** parked (what + why; do NOT build yet — not for action now). Tracks three
requirements against the Windows agent (`nemesis_agent/`), captured while scoping the paused
memory-injection module.

**No standalone design doc for the memory-injection module itself exists yet in this repo** —
searched `PUNCHLIST.md`, every `docs/roadmap/*.md` and `docs/architecture/*.md`, and the audits
directory; no hits anywhere. If/when that module resumes and gets its own scoping doc, **fold
this entry into it** rather than tracking it separately — that's the explicit intent behind item
1 below, and behind capturing all three together here instead of scattering them.

## What

Three requirements surfaced against the Windows agent, in the context of the paused
memory-injection module:

1. **The agent will need real rework once memory-injection work resumes.** This is a
   **dependency/prerequisite item for that module**, not a standalone agent improvement with its
   own independent schedule. Whatever the memory-injection module ends up needing from the agent
   drives the shape of this rework — it isn't specified further here because the module itself
   isn't scoped yet.
2. **A small GUI, launched from the system tray/taskbar icon**, showing agent status and
   allowing config items to be edited as needed.
3. **Recognize when a Windows Update has occurred and offer to self-test** in the new
   environment, to determine whether the agent itself needs updating.

## Why

- **Item 1** — the memory-injection module is expected to depend on agent internals (whatever
  APIs/hooks it needs to actually perform or support memory injection) that don't necessarily
  exist in the agent's current shape. Flagging this now, while the module is paused, means the
  rework is scoped as part of resuming that work rather than discovered mid-build.
- **Item 2** — a tray-icon GUI is an operational visibility/manageability gap independent of
  memory-injection specifically, but it's especially relevant once the agent is doing something as
  sensitive as memory injection: an operator would reasonably want to see agent status and adjust
  config without digging into config files by hand, particularly for a capability with this much
  potential for user-visible side effects if misconfigured.
- **Item 3** — memory-injection-based detection techniques are typically sensitive to the exact
  kernel/API surface they operate against. A Windows Update can silently change that surface out
  from under the agent, breaking detection technique correctness with no visible symptom unless
  something actively checks. Recognizing the update and offering a self-test is how the agent
  would catch that class of silent breakage instead of continuing to run against assumptions the
  OS no longer honors.

## Reasoning / shape

- Capture-only, per the request. None of this has an implementation plan; item 1 in particular
  can't be scoped further until the memory-injection module itself is designed.
- Items 2 and 3 are agent-general improvements that happen to matter more once memory-injection
  work is live, not techniques specific to memory injection themselves — worth noting in case
  they're ever considered for the agent independent of that module's timeline. Captured together
  here because that's how they surfaced, per the request to fold them into wherever this paused
  work is tracked.
