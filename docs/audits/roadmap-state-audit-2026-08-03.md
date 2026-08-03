# Roadmap-vs-state audit — 2026-08-03

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-08-02.md` (kept as history; that
> file was itself written retroactively on 2026-08-03 to fill a gap — no morning audit
> ran on 2026-08-02).

**Tally: 6 SHIPPED · 8 PARTIAL · 54 STUB/PARKED — 68 total.** Morning run (2026-08-03),
after one heavy build day (08-02: ADR 0004 resolution + build, YARA SSRF hardening,
pre-warn page, VM fleet work).

## Drift since 2026-08-01 baseline

### File-set: +3, none removed (65 → 68)
| New file | Added in | Class |
|---|---|---|
| idle-lock-walk-away-protection.md | `5b4427d` (2026-08-01) | **SHIPPED — header stale.** Header still reads "Implementation not yet started," but `dashboard.py` has `_IDLE_TIMEOUT_SECONDS`/`_IDLE_LOCK_ALLOWED`/`session_idle_locked` audit row live, and commits `219c282 feat(auth): idle-lock enforcement`, `0e15c22 feat(auth): idle-lock in-page overlay + DOM-interaction heartbeat` (both 2026-08-01) confirm the build. HANDOFF's 2026-08-01 closeout commit message says so directly: "idle-lock shipped." |
| server-side-session-store.md | `00e95c1` (2026-08-01) | PARKED — header confirms ("Captured 2026-08-01 from a Window 1 handoff note"); no commits since touch its scope |
| automated-abuse-reporting.md | `a7c8786` (2026-08-01) | PARKED — header confirms ("Idea/roadmap only. Not designed in code detail, not started"); no commits since touch its scope |

Traced via `git log --diff-filter=A --since=2026-08-01 -- docs/roadmap/` — three additions,
no removals (`--diff-filter=D` empty over the same window).

### Shipping: 1 baseline-PARKED item moved to SHIPPED, header stale
- **`malware-yara-rule-autoupdate.md` — PARKED → SHIPPED.** Header still says
  `**Status:** parked (idea captured — do NOT build yet)`, but commits `0506aed
  feat(malware): YARA rule auto-update mechanism + cross-platform exclusions`, `79a4996
  feat(malware): YARA updater routes, SSRF guard, rate limit, settings validation`,
  `5ef9a93 fix(malware): YARA test-seam override -- allowlist, not denylist` (all
  2026-08-02) build and harden it in three successive rounds. Confirmed live in code:
  `modules/malware_detection/module.py` and `manifest.json` both carry YARA
  auto-update logic. HANDOFF.md §1 states it plainly: "YARA rule auto-update is live,
  SSRF-guarded... rate-limited, with a dashboard card showing rule freshness." This is
  exactly the header-staleness trap this audit exists to catch — classifying off the
  file's own `Status:` line would have missed it.
- **8 PARTIAL — unchanged, no feat commit since 08-01 baseline for any of them:**
  `clean-uninstall-build-spec`, `installer-unified-v1.0.6`, `malware-detection-pipeline`,
  `latent-bug-fleet-clamav-only`, `lateral-movement-outbreak-detection`,
  `open-source-threat-feeds`, `sandbox-first-software-testing`, `sandbox-to-system-migration`.
  Verified via `git log --since=2026-08-01 -- docs/roadmap/<file>.md` for each — zero
  commits touched any of them directly. (`malware-detection-pipeline`'s Layer A/B is a
  distinct, already-PARTIAL scope from the YARA-autoupdate item above; the two don't
  overlap in the roadmap file set.)
- **Broader sweep:** every other baseline-PARKED filename (53 total, minus the YARA item
  above) was keyword-matched against all 72 commits since 2026-08-01. All other hits were
  generic-word noise (`adr`, `ai`, `dashboard`, `track`) against unrelated commits — no
  second silent-shipping case found. Full candidate list and method: this session's
  worklog.

## Notable same-period activity NOT reflected further in this tally (by design)
2026-08-02 was one heavy build day — most of it maps to ADR/HANDOFF-tracked work with no
corresponding `docs/roadmap/` item, so correctly none of it moves the tally beyond the
YARA item above:
- ADR 0004 resolved (hinge questions a/b/c) and built same day: Steps 1–3 (YARA
  auto-update UI/SSRF/rate-limit, actor-seam + local-ISO-timestamp migration on five
  `scan_*` tables, agent-heartbeat authentication). M3 unblocked, not started.
- Windows installer pre-warn page shipped, then two same-day follow-on fixes
  (`_AUTH_EXEMPT` omission, installer-token-revocation gap it surfaced).
- Config-shadowing audit; `malware_settings` shadow-fix pattern not yet applied to
  `diagnostics_settings` (carried forward, see PUNCHLIST).
- VM fleet: gauge VM built/pruned, W3-TEST rig retired, two new standing rules
  (`KEEP`-naming, ARP-not-DHCP-leases identification).
- PL-10 reopened (stale-text root cause still unresolved) — process/doc item, no roadmap
  file.
- Twenty 07-31 commits plus all of 08-02 remain the live head; nothing pending push per
  HANDOFF §1 as of this baseline.

## SHIPPED (6)
| Item | Evidence |
|---|---|
| connection-type-awareness | `b3146fe` — link_type WiFi/ethernet, stored in `agent_devices`, shown in dashboard |
| diagnostics-anthropic-status-banner | `b7b7174` — `_poll_anthropic_status()` in `ai_engine/module.py` |
| diagnostics-connectivity-watcher-tool | `53975ea`–`086a659` — watcher service, VPN probes, dashboard card, systemd unit |
| hardware-stable-identifiers | `daf273f` — fingerprint (Win+Linux), TOFU, `agent_devices` migration; Mac deferred |
| malware-yara-rule-autoupdate | `0506aed`/`79a4996`/`5ef9a93` (2026-08-02) — auto-update mechanism, SSRF-guarded routes, rate limit; header stale, see drift note above |
| idle-lock-walk-away-protection | `219c282`/`0e15c22` (2026-08-01) — enforcement + overlay live in `dashboard.py`; header stale, see drift note above |

## PARTIAL (8)
| Item | State |
|---|---|
| clean-uninstall-build-spec | Phases 1–3 built; de-enroll endpoint (:5001) deployed live + migration applied; e2e VM uninstall lifecycle test still UNRUN |
| installer-unified-v1.0.6 | Delivery + self-onboard (v1.0.7) live; two before-trip fixes remain (auto_approve default, double-enroll) |
| malware-detection-pipeline | Layer A (ClamAV+YARA) + Layer B canary live, canary hardened further 08-02; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Documented; fix lives in ADR 0004 (now resolved/built — worth a re-check next audit whether this graduates) |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete, no backend code |
| sandbox-first-software-testing | Design complete, no code; requires VM Lab |
| sandbox-to-system-migration | Design complete, no code; requires VM Lab + software_inventory |

**Flag for next audit:** `latent-bug-fleet-clamav-only`'s PARTIAL classification was
pinned to ADR 0004 being unresolved ("fix lives in ADR 0004, status Proposed, not
built"). ADR 0004 is now resolved and Steps 1–3 built (HANDOFF §1). Not reclassified here
— its roadmap file itself wasn't touched and this pass didn't have time to trace whether
ADR 0004's build actually covers this item's specific fix — but it's the most likely next
mover and should be checked directly against the roadmap file's own described fix, not
inferred from the ADR alone.

## Method
Same as 2026-08-01: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A` (and `-D` to confirm no removals) provenance for any
new files, `git log <baseline-date>..HEAD -- docs/roadmap/<file>.md` per non-parked item
to catch silent shipping, PLUS (new this pass) a keyword sweep of all baseline-PARKED
filenames against every commit subject since the baseline date, to catch shipping that
never touched the item's own roadmap file — this is what surfaced the YARA case, which a
per-file-only check would have missed entirely. Baseline doc for tomorrow's Morning
Status: this file (2026-08-03), superseding 2026-08-01.
