# Roadmap — Memory-injection detection: design prerequisites

- **Status (split 2026-08-04): the observation-layer foundation proceeds now; the detection
  technique itself stays paused.** Approved build structure: a technique-independent observation
  layer (full process enumeration, UDP-visible connection reporting, agent integrity attestation
  — see [agent-rebuild-config-driven.md](agent-rebuild-config-driven.md), now active) lands
  first, verified independently. The memory-injection detection technique layers on top
  separately, later, and remains capture-only until the open ownership question below is
  resolved. **This split does not change what this doc is** — see "What this doc is not," below,
  still true without modification. It changes only when the technique-independent parts of the
  prerequisite work can start.
- **Status (original, 2026-08-03), unchanged for the paused part:** Capture-only. Paused — do NOT
  build the detection technique. No implementation plan exists; this records what earlier design
  discussion already established as prerequisites and constraints, so the module can be scoped
  for real the next time it's picked up instead of starting from nothing. **Supersedes**
  [windows-agent-memory-injection-rework-prereqs.md](windows-agent-memory-injection-rework-prereqs.md)
  — folded in here per that stub's own instruction ("If/when that module resumes and gets
  its own scoping doc, fold this entry into it rather than tracking it separately").
- **What this doc is not:** a design for the detection technique itself (what memory
  patterns get inspected, how injection is distinguished from legitimate activity). Nothing
  here describes that. This is the *operational and architectural* scaffolding the technique
  would need to run inside — privilege model, failure modes, deployment gating — captured
  because those constraints were already worked out before the technique itself was, and
  are load-bearing on how the eventual design can even be shaped.

## New prerequisites and blockers (added 2026-08-04)

- **Blocking dependency: agent integrity attestation.** There is no agent self-integrity check of
  any kind anywhere in the product today. An attacker who replaces the agent's code gets an agent
  that reports success with no findings, indefinitely, with no other signal catching it. A
  memory-injection detector — which would run as an even more privileged component per the
  architectural tension below — inherits this problem wholesale, not partially: the detector's
  own verdicts are only as trustworthy as the agent process reporting them. Already tracked on
  the public PUNCHLIST; a fuller scoping exists in the private mirror.
- **Blocked by a concrete agent defect, not just a missing feature.** Process enumeration today is
  a top-10-by-CPU sample, not a real process view. Memory-injection detection needs full
  enumeration as step zero — a low-CPU malicious process is exactly the case a CPU-sorted top-10
  sample never surfaces. This is one of the technique-independent observation-layer items above,
  not specific to memory-injection, but memory-injection cannot proceed without it either way.
- **New prerequisite: an appliance RAM budget model, which does not exist today.** Reading process
  memory has a transient working-set cost with no fallback — memory cannot be scanned from disk —
  so this work needs a real RAM budget for the appliance, and today the only figures available
  are single idle measurements. **Stated explicitly: this budget model is a shared artefact with
  three consumers, not an implementation detail of memory-injection specifically** — (i) this
  feature's own working-set need; (ii) tmpfs bounds elsewhere in the product (`/tmp` and a
  planned sandbox scratch area), expressed as percentages so they scale with whatever hardware
  actually ships; (iii) headroom for a possible future RAM-backed detonation VM, if the parked
  sandbox-testing roadmap item is ever picked back up. It is also a direct input to ADR 0014's
  still-open hardware-baseline item, where the spec is deliberately a placeholder expected to
  converge from real measurement rather than being designed against now — this budget model *is*
  part of that measurement. Scoping it to this feature alone would produce a number that is
  already wrong for the appliance the moment either other consumer lands.
- **The open question this doc cannot resolve alone: who owns the executing-payload case?**
  [adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md) is a
  live, always-on local-trigger list that already covers a payload executing after getting past
  Tiers 1/2. This doc is paused scaffolding with no detection technique yet. Two documents
  currently cover adjacent ground with different statuses — deciding which one owns this case
  belongs in one of these two docs, before either resumes in earnest, or this risks being built
  against scaffolding while Tier 3's living list quietly covers the same ground independently.

## Why this exists

Memory-injection-based detection is a fundamentally different capability from anything the
agent does today (hardware telemetry, file-based scanning, network posture). It needs
elevated, SYSTEM-level access to inspect other processes' memory — a privilege tier and
process model the current agent was never built for. Scoping that gap now, while the
detection module itself is still paused, means the agent rework happens as planned
prerequisite work rather than discovered mid-build the way [[core_module]]'s DB-access
migration was discovered after the fact.

## Prerequisites (established, not yet built against)

1. **Elevation / `SeDebugPrivilege` requirement.** Inspecting another process's memory on
   Windows requires the debug privilege, which requires the agent process to run with
   elevated rights it does not have today (the current agent runs as a normal service-level
   process, not as SYSTEM with debug rights explicitly enabled). This is not a permissions
   tweak — it's a different security posture for the whole process, with everything that
   implies for attack surface: a compromised agent with `SeDebugPrivilege` can read and
   potentially manipulate the memory of anything else on the box, which is a meaningfully
   larger blast radius than the agent's current capabilities.

2. **The JIT false-positive baseline is a first-class problem, not a tuning pass.**
   Legitimate JIT compilers (browsers, .NET, the JVM, any language runtime that generates
   and executes code at runtime) do things that look structurally identical to malicious
   memory injection from the outside — allocating executable memory, writing code into it,
   jumping to it. A detector that can't distinguish "Chrome's JIT" from "a process hollowing
   attack" is not shippable with a false-positive rate fixed later; the baseline false-
   positive rate against ordinary JIT-heavy software on a real desktop has to be established
   and be part of the initial design, not an afterthought tuned once users start
   complaining. Treat this as a design constraint on the detection approach itself, not a
   threshold to adjust post-launch.

3. **Windows-Update self-test requirement.** Memory-injection detection is sensitive to the
   exact kernel/API surface it operates against, and a Windows Update can silently change
   that surface with no visible symptom unless something actively checks. The agent needs to
   recognize when an update has occurred and offer to self-test in the new environment,
   specifically so a silently-broken detector doesn't keep running as though nothing
   changed. (Carried forward from the original stub, item 3 — unchanged.)

4. **Signing-timeline trigger.** An elevated-privilege build with `SeDebugPrivilege` and
   SYSTEM-level access is a materially more dangerous thing to have unsigned and circulating
   than the current agent. **This must be resolved before any elevated-privilege build ever
   leaves VMs or internal test hardware** — it is a hard gate on distribution, not a nice-to-
   have. Ties directly to the deferred-to-2.0 signing decision already on record
   (`~/work/nemesis-internal/known-limitations/windows-security-prompts-unsigned-agent-2026-08-02.md`):
   that decision was made in the context of the *current* agent's risk profile, and needs to
   be explicitly re-evaluated once an elevated-privilege build exists, not assumed to still
   apply unchanged. Concretely: no elevated-privilege memory-injection build gets distributed
   to a real device, trip laptop included, until signing is in place for it specifically.

## Newly-surfaced architectural tension: interactive UI vs. SYSTEM-level privilege

The tier-3 key-protection work (2026-08-03) established that the agent needs an interactive
desktop session to prompt for a device password at startup (`secret_prompt.py`,
`nemesis_agent/agent.py`'s `_unlock_key_material()`). Memory inspection wants the opposite:
SYSTEM-level privilege, running as a service with no desktop and no interactive session to
prompt from.

**Those two requirements cannot both be satisfied by one process.** A single-process agent
that is sometimes an interactive desktop app (to prompt for a password) and sometimes a
privileged SYSTEM service (to inspect memory) is not a coherent process model — Windows
services don't get a desktop by default, and a desktop-interactive process doesn't get
SYSTEM-level debug rights without the same elevation problem the password prompt is trying
to avoid needing.

**This likely means splitting the agent into two components:**

- **A session-side UI component** — runs in the user's desktop session, owns the
  interactive surfaces (the device-secret prompt, and item 2 below's tray-icon status/config
  GUI). No elevated privilege.
- **A privileged service component** — runs as SYSTEM (or with `SeDebugPrivilege`
  specifically), owns memory inspection and anything else that genuinely needs that
  privilege tier. No desktop, no interactive prompts.
- **Authenticated local IPC between them.** The two components need to communicate (status,
  config changes, unlock events) without that channel becoming a privilege-escalation path —
  an unauthenticated local socket that a privileged service listens on is exactly the kind of
  thing a lower-privilege local process could abuse to drive SYSTEM-level actions. The
  channel needs real authentication, not just "it's localhost so it's fine."

**Why this matters now, not just when the module resumes:** this is materially bigger than
what the existing tray-icon-GUI roadmap item (below, item 2) implies on its own. A tray icon
reachable from a single-process agent is a small, contained addition. A tray icon that is
one half of a two-process, IPC-connected architecture — where the other half runs as
SYSTEM — is a different scale of work, and the design has to account for that split from the
start rather than building the tray GUI first and discovering the privilege split later.

## Folded in from the original stub (2026-08-03, unchanged in substance)

The original `windows-agent-memory-injection-rework-prereqs.md` stub captured three items,
carried forward here rather than tracked separately:

1. **The agent will need real rework once memory-injection work resumes** — a
   dependency/prerequisite item for that module, not an independently-scheduled agent
   improvement. Also included: a dashboard addition to update all agents running a given
   Windows upgrade level (win X.X.X) across the fleet, rather than a blanket
   update-everyone action — connects to the Windows-Update self-test above (item 3), since
   recognizing the agent's own Windows version is the prerequisite for the dashboard being
   able to target an update at exactly the affected agents.
2. **A small GUI, launched from the system tray/taskbar icon**, showing agent status and
   allowing config items to be edited as needed. **Now understood to be the session-side UI
   component** of the two-process split above, not a standalone addition to today's
   single-process agent — see the architectural-tension section for why that's a bigger
   scope than it first appears.
3. **Recognize when a Windows Update has occurred and offer to self-test** in the new
   environment — see prerequisite 3 above (same item, now formalized as a named
   prerequisite rather than a loose capture bullet).

## Reasoning / shape (still capture-only)

- None of this has an implementation plan. The detection technique itself isn't scoped at
  all; what's captured here is everything that has to be true of the agent's architecture
  *before* that technique could be built into it.
- The two-process split is a strong architectural implication, not yet a decision —
  worth pressure-testing against real Windows service/session constraints before treating it
  as settled, but nothing in the constraints above points toward a simpler alternative.
- Signing (prerequisite 4) is the hardest external gate: it depends on the already-deferred
  2.0 signing decision, re-scoped for a higher-risk build. Revisit that known-limitations
  doc specifically when this module is picked back up, don't assume its conclusions
  transfer unchanged.
- Rule 10 note: this doc stays at the architecture/prerequisite level deliberately — privilege
  model, process split, deployment gating — and does not describe the detection technique
  itself, which is the part that would actually need a disclosure judgment call if and when
  it's designed.
