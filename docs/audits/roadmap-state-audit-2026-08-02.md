# Roadmap-vs-state audit — 2026-08-02

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-08-01.md` (kept as history).
>
> **Written retroactively on 2026-08-03**, filling a gap — no morning audit ran on
> 2026-08-02 itself. Reflects state as of 2026-08-02 morning (i.e. the 08-01 baseline
> plus that day's file-set/shipping changes), NOT the current 2026-08-03 state — the
> 2026-08-02 YARA auto-update build (see `roadmap-state-audit-2026-08-03.md`) postdates
> this snapshot and is correctly absent from it.

**Tally: 5 SHIPPED · 8 PARTIAL · 55 STUB/PARKED — 68 total.** Retroactive morning-of
snapshot (2026-08-02), after 2026-08-01's build day (idle-lock enforcement shipped, two
new roadmap stubs captured from Window 1 handoffs).

## Drift since 2026-08-01 baseline

### File-set: +3, none removed (65 → 68)
| New file | Added in | Class |
|---|---|---|
| idle-lock-walk-away-protection.md | `5b4427d` (2026-08-01) | **SHIPPED — header stale.** Header reads "Implementation not yet started," but commits `219c282 feat(auth): idle-lock enforcement -- confine on idle, log out at the cap` and `0e15c22 feat(auth): idle-lock in-page overlay + DOM-interaction heartbeat` (both 2026-08-01, same day the stub was captured) build and ship it. Confirmed live in `dashboard.py` (`_IDLE_TIMEOUT_SECONDS`, `_IDLE_LOCK_ALLOWED`, `session_idle_locked` audit row). The 2026-08-01 closeout commit (`154cfb1`) says so directly in its own subject line: "idle-lock shipped." |
| server-side-session-store.md | `00e95c1` (2026-08-01) | PARKED — header confirms ("Captured 2026-08-01 from a Window 1 handoff note"); no commits touch its scope |
| automated-abuse-reporting.md | `a7c8786` (2026-08-01) | PARKED — header confirms ("Idea/roadmap only. Not designed in code detail, not started"); no commits touch its scope |

Traced via `git log --diff-filter=A --since=2026-08-01 --until=2026-08-02 -- docs/roadmap/`
— three additions, no removals.

### Shipping: 1 new-that-day item shipped same-day as capture; 8 PARTIAL unchanged
- **`idle-lock-walk-away-protection` — captured and shipped same day (2026-08-01).** See
  file-set drift above; unusual only in that a stub graduated to SHIPPED before the next
  morning's audit ever classified it as PARKED, which is why it's filed directly as
  SHIPPED here rather than shown moving from a prior PARKED state.
- **8 PARTIAL — unchanged from 08-01 baseline, no feat commit touched any of their
  roadmap files on 08-01:** `clean-uninstall-build-spec`, `installer-unified-v1.0.6`,
  `malware-detection-pipeline`, `latent-bug-fleet-clamav-only`,
  `lateral-movement-outbreak-detection`, `open-source-threat-feeds`,
  `sandbox-first-software-testing`, `sandbox-to-system-migration`.
- **`malware-yara-rule-autoupdate` — still PARKED as of this snapshot.** Its header said
  "parked (idea captured — do NOT build yet)" and that was still accurate at 08-02
  morning; the build that makes it stale (`0506aed`/`79a4996`/`5ef9a93`) is dated
  2026-08-02 daytime, after this snapshot's cutoff. Correctly carried in the PARKED
  count here — see `roadmap-state-audit-2026-08-03.md` for its reclassification.

## Notable same-period activity NOT reflected further in this tally (by design)
2026-08-01 was a full build day beyond the idle-lock item above; most of it maps to
ADR/HANDOFF-tracked work with no corresponding `docs/roadmap/` item:
- ADR 0019 Increment 3 measured and PASSED; Increment 4 (verdict emission) built gated
  off by default, cutover held pending review.
- Full authentication system pieces: recovery-code email, audit-trail rows for
  `core/manage.py` mutations, lockout-tier email off the request thread, background
  pollers marked, `login_events` timestamps corrected to local time.
- Absolute session cap (`SESSION_MAX_HOURS`, default 8h) approved by the operator
  mid-session as an addendum to the idle-lock design, noted in the roadmap file itself.

## SHIPPED (5)
| Item | Evidence |
|---|---|
| connection-type-awareness | `b3146fe` — link_type WiFi/ethernet, stored in `agent_devices`, shown in dashboard |
| diagnostics-anthropic-status-banner | `b7b7174` — `_poll_anthropic_status()` in `ai_engine/module.py` |
| diagnostics-connectivity-watcher-tool | `53975ea`–`086a659` — watcher service, VPN probes, dashboard card, systemd unit |
| hardware-stable-identifiers | `daf273f` — fingerprint (Win+Linux), TOFU, `agent_devices` migration; Mac deferred |
| idle-lock-walk-away-protection | `219c282`/`0e15c22` (2026-08-01) — enforcement + overlay live in `dashboard.py`; header stale, see drift note above |

## PARTIAL (8)
| Item | State |
|---|---|
| clean-uninstall-build-spec | Phases 1–3 built; de-enroll endpoint (:5001) deployed live + migration applied; e2e VM uninstall lifecycle test still UNRUN |
| installer-unified-v1.0.6 | Delivery + self-onboard (v1.0.7) live; two before-trip fixes remain (auto_approve default, double-enroll) |
| malware-detection-pipeline | Layer A (ClamAV+YARA) + Layer B canary live; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Documented; fix lives in ADR 0004 (status Proposed, not built as of this snapshot) |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete, no backend code |
| sandbox-first-software-testing | Design complete, no code; requires VM Lab |
| sandbox-to-system-migration | Design complete, no code; requires VM Lab + software_inventory |

## Method
Same as 2026-08-01: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A` (and `-D` to confirm no removals) provenance for any
new files, `git log <baseline-date>..<this-date> -- docs/roadmap/<file>.md` per
non-parked item to catch silent shipping. Date-bounded (`--since=2026-08-01
--until=2026-08-02`) to reconstruct the morning-of snapshot rather than today's actual
state — this file is a historical fill-in, not a live run. Superseded immediately by
`roadmap-state-audit-2026-08-03.md`, which is the current baseline for Morning Status.
