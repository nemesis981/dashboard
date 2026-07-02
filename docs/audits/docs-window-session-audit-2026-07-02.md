# Docs-window session audit — 2026-07-02

> Read-only findings + docs-only actions from the 2026-07-02 DOCS window (Win 2) session.
> Consolidates every finding produced today into one report. No code touched (docs-window
> contract). Rule 8: placeholders only — no real IPs/hosts/paths/accounts/names. Commit-first,
> push held for operator review.

**Scope:** three closeout actions from the morning roadmap-vs-state audit + a new
features-and-benefits audit baseline. All work docs-only.

---

## Finding 1 — Roadmap file-set drift: +7 files since the 2026-07-01 baseline

**Finding:** `docs/roadmap/*.md` grew from **44 → 51** files. Seven added, none removed. The
prior baseline (`roadmap-state-audit-2026-07-01.md`, 4 SHIPPED / 7 PARTIAL / 33 PARKED = 44)
was stale by seven files.

**Classification of the 7 new files (verified against headers + `git log` + code):**

| New file | Class | Basis |
|---|---|---|
| clean-uninstall-build-spec | **PARTIAL** | Phases 1–3 built (`9321cfe`/`5b03260`/`14ce142`); de-enroll endpoint (`:5001`) deployed live; e2e VM uninstall test pending. |
| uninstall-deenroll | PARKED | Originating stub; capture (design item, post-trip). |
| connection-health-subsystem | PARKED | DESIGN of record, not built (`e48fd5d`). |
| enrollment-modes-build-spec | PARKED | BUILD-READY design, not built; execute-ready post-trip (ADR 0012). |
| interactive-ai-clarification | PARKED | Roadmap capture; future item, post-packaging. |
| server-on-windows-roadmap | PARKED | Capture (what + why; parked). |
| sse-inspection-proxy-build-spec | PARKED | DESIGN CAPTURED, not built. |

**Corrected tally: 4 SHIPPED / 8 PARTIAL / 39 PARKED — 51 total.** No *silent* drift — the
growth is all accounted-for (six new parked captures + one spec that has since been built).

**Action taken:** authored new dated baseline `docs/audits/roadmap-state-audit-2026-07-02.md`
(supersedes 07-01, which is kept as history). Committed in `aedfb01`.

---

## Finding 2 — Stale status header on a shipped spec (header-trust trap)

**Finding:** `docs/roadmap/clean-uninstall-build-spec.md` carried
`Status: BUILD-READY spec (design of record). Not built.` while its code had in fact shipped —
phases 1–3 built (`9321cfe`/`5b03260`/`14ce142`) and the de-enroll endpoint deployed live. This
is the exact stale-header-on-shipping pattern the morning audit discipline exists to catch (a
"parked/not-built" header on code that has moved).

**Action taken:** corrected the header to **PARTIAL** — phases 1–3 BUILT; de-enroll endpoint
(`:5001`) DEPLOYED live; end-to-end VM uninstall lifecycle test still PENDING — with the three
phase commit hashes. Committed in `aedfb01`.

**Note (honest):** PARTIAL, not SHIPPED — the full uninstall lifecycle test on a VM is still
UNRUN (carried on HANDOFF as an open item).

---

## Finding 3 — CLAUDE.md Morning-Status baseline references were internally stale

**Finding:** the Morning-Status section of `CLAUDE.md` referenced the old baseline in **four**
places (not one): "baseline's 44", "10 non-parked items (4 SHIPPED + 7 PARTIAL)", "33
baseline-PARKED items", and the summary baseline line (4/7/33, 44). Bumping only the summary
line would have left the section self-contradictory.

**Action taken:** updated all four references for consistency → baseline's **51**, **12**
non-parked (**4 SHIPPED + 8 PARTIAL**), **39** baseline-PARKED, and the summary line to
**2026-07-02: 4 SHIPPED / 8 PARTIAL / 39 PARKED (51 total)** pointing at the new baseline file.
Committed in `aedfb01`. (This is the one code-adjacent file touched — `CLAUDE.md` is a docs/ops
file, not product code; docs-window-appropriate.)

---

## Finding 4 — Features-&-benefits audit baseline authored (new)

**Finding / gap:** no honest feature→benefit inventory existed to seed the future "Are you
interested?" showcase doc, and no `docs/business/` directory or interest-document brief existed
(`docs/business/interest-document-brief.md` is **not present** as of this session).

**Action taken:** created `docs/business/features-benefits-audit.md` — the raw, honest baseline
inventory (feature → plain-language "so that…" benefit → real status), grounded in repo reality
(`ARCHITECTURE.md`, module manifests, code-presence checks: backup endpoints,
`enrollment_status` approval, scan queue). Committed in `7a20505`.

**Key inventory findings (honest maturity snapshot):**
- **WORKING core today:** self-hosted dashboard, Pi-hole DNS filtering (+ optional DHCP
  takeover, opt-in), Suricata IDS, ClamAV/YARA malware scan (Layer A), hardware/health fleet
  monitoring, alerts + tickets + email, unified cross-platform agent + fleet scan (Win/Linux
  proven), VPN/remote awareness, self-onboard enrollment **with manual approval**, backup/restore,
  optional AI Engine, behavioral/zero-day anomaly detection, connectivity self-diagnostics.
- **Roadmap-SHIPPED (4):** connection-type-awareness, diagnostics Anthropic-status banner,
  connectivity watcher, hardware stable identifiers (Win+Linux; Mac deferred).
- **PARTIAL (honest, do-not-overclaim):** clean install/uninstall lifecycle (built, **e2e VM
  test pending**); malware pipeline (Layers A–B live, C–D scaffold/planned; Mac behavioral
  pending Apple ESF); community threat-intel contribution (module present, shared backend still
  roadmap).
- **PLANNED (not built):** Mac deep agent + mobile apps, enrollment modes/config-driven rebuild,
  connection-health subsystem, interactive AI clarification, sandbox-first testing + VM lab,
  MSP/multi-user, support bundle + AI tutorials, server-on-Windows.

**Framing guardrails baked in (for the later doc):** non-technical "no IT department" benefit
angle; no pricing anywhere; stage honesty (solo-built, AI-assisted, in-development) kept as a
feature; SHIPPED/WORKING vs PARTIAL vs PLANNED clearly separated so maturity isn't
misrepresented; statuses cross-referenced to the 2026-07-02 roadmap audit.

---

## Session actions summary

| Action | Files | Commit | Push |
|---|---|---|---|
| New roadmap-state baseline (4/8/39, 51) | `docs/audits/roadmap-state-audit-2026-07-02.md` | `aedfb01` | **PUSHED** (per operator) |
| Bump CLAUDE.md Morning-Status baseline refs | `CLAUDE.md` | `aedfb01` | **PUSHED** |
| Fix stale clean-uninstall status header → PARTIAL | `docs/roadmap/clean-uninstall-build-spec.md` | `aedfb01` | **PUSHED** |
| Features-&-benefits audit baseline | `docs/business/features-benefits-audit.md` | `7a20505` | **HELD** (as of this report) |
| This consolidated session audit | `docs/audits/docs-window-session-audit-2026-07-02.md` | (this commit) | HELD |

**Verification:** `aedfb01` confirmed pushed — local == origin (0/0) at
`aedfb012fffcaea4d612fefb5cf24efcf4d9d3a4`. Rule-8 scans on every commit returned clean
(only loopback `127.0.0.1` prose in pre-existing CLAUDE.md text — not a leak).

## Open items carried (docs-window)
- `docs/business/interest-document-brief.md` — not yet authored; the polished "Are you
  interested?" doc is shaped from the features-benefits baseline later.
- `CUSTOM_TAILSCALE_UNINSTALL.md` — still owed (vendor-integration rule) for the Phase-3
  uninstaller's Tailscale-removal code.
- Held screenshot `docs/audits/trip-1.0.8-test2-startmenu-uninstall-2026-07-01.png` (untracked)
  — still awaiting a Rule-8 decision (shows a "Test-User" account name).
- PL-11 (PawnIO) — install guides must tell users to approve the PawnIO install for temps/fans.

## Method
Read-only inspection of `docs/roadmap/*`, `ARCHITECTURE.md`, module manifests, and targeted
code-presence greps (no edits to product code). Classifications diffed against the prior baseline
and confirmed via `git log` + file headers. All changes committed docs-only; pushes gated on
operator review per the closeout contract.
