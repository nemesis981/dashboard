# Roadmap-vs-state audit — 2026-09-05

> Read-only audit (Rule 1). **Full re-derivation**, not an incremental diff — the prior
> baseline (`roadmap-state-audit-2026-09-02.md`) was flagged in `HANDOFF.md` as three
> sessions stale ("the single most overdue doc-audit item"), so this pass re-swept every
> commit landed since 09-02 across all 92 files on disk rather than continuing to diff
> against an aging baseline. Supersedes `roadmap-state-audit-2026-09-02.md` (kept as
> history).

**Tally: 18 SHIPPED · 16 PARTIAL · 57 STUB/PARKED — 91 total.**

**Why 91, not the 92 files on disk:** `product-thesis-built-in-it-expertise.md` stays
excluded (operator decision 2026-08-31, unchanged) = 91 tracked + 1 excluded = 92 on disk,
confirmed against `ls docs/roadmap/*.md` = 92.

**Arithmetic note on this refresh (flagged explicitly rather than silently corrected):**
the investigating pass's own headline line initially read "17 SHIPPED · 16 PARTIAL · 58
PARKED," which does not reconcile against its own per-file drift table below — walking the
09-02 baseline (16/14/58) through the five listed moves plus three new PARKED files yields
18/16/57, not 17/16/58. Both newly-SHIPPED files were independently re-verified against
live code before adopting 18 as the published number (see §1) — this is the "check the
shape, don't trust the summary line" discipline applied to this audit's own output, not
just to the code it audits.

## File-set drift: +3 files since 09-02

All three added after the 09-02 baseline was finalized (verified via `git log
--diff-filter=A` timestamps against the baseline commit's own timestamp, `aa2ce48`
11:23:16 plus its two same-day addenda through `76e47a9` 12:07:59 — these three post-date
all of that):

| File | Added | Classification |
|---|---|---|
| `spamhaus-drop-firewall-ingest.md` | 2026-09-02 13:29 (`a430359`) | PARKED — capture-only per own header, split out of `open-source-threat-feeds.md` |
| `consent-disclosure-installer-surfacing.md` | 2026-09-03 13:34 (`52f4ce8`) | PARKED — capture-only per own header |
| `firewall-rule-schema-and-precedence.md` | 2026-09-03 13:39 (`eb304bd`) | PARKED — capture-only per own header |

No files removed since 09-02 (`git log --diff-filter=D -- docs/roadmap/` since 2026-09-02
returns empty).

## Shipping drift: 5 items moved or need a closer look

| File | 09-02 | Now | Evidence |
|---|---|---|---|
| `installer-email-delivery.md` | PARKED | **SHIPPED** | `9c5eef2`. Own header already self-corrected to SHIPPED. Independently confirmed live: `dashboard.py:5569 def api_agent_installer_generate()`. |
| `removable-media-device-control.md` | PARKED | **SHIPPED** | `0ca9f8e`/`07ace9e`/`86a3c83` ("v1 final piece"). Own header is STALE (still says "parked... do NOT build yet") — not header-trusted, verified directly: `nemesis_agent/modules/usb_devices.py` + `usb_devices_windows.py` exist, live route `dashboard.py:15823 def api_usb_events()` confirmed, plus `core_module/hw_monitor/test_usb_device_control.py`. **Caveat carried forward, not new:** `api_usb_events` is missing a `ROUTE_MINIMUMS` entry (already tracked in `PUNCHLIST.md`, fails safe per the loader's own enforcement, not blocking the SHIPPED call). |
| `open-source-threat-feeds.md` | PARKED | **PARTIAL** | `fb22ec9`/`c741c85`. Real module `modules/threat_feeds/` (994 lines incl. tests), manifest declares a dashboard card, Pi-hole blocklist management shipped — but only one of several Tier-1 sources named in the doc is built. Own header still reads "parked... do NOT build yet" — stale, needs a content refresh independent of this bucket move. |
| `lateral-movement-outbreak-detection.md` | PARKED | **PARTIAL** | `952f6c3`/`17b0ec0`. Real module `modules/lan_behavior_monitor/` (1647 lines, dashboard card, enabled by default) — matches the doc's own "RESOLVED 2026-08-30" reduced-scope Tier 1 language (see CLAUDE.md's own flow-counting-mismeasurement history on this exact file). Tier 2 still unbuilt. Header not yet updated to reflect the Tier 1 ship — stale. |
| `enrollment-modes-build-spec.md` | PARTIAL | PARTIAL (bucket unchanged, **content stale**) | `e1b33a2`/`cba48d7`/`204dacb`/`c7e66a8` built the `enrollment_auto_audit` schema, the audit-write path, the `source_subnet` binding, and a typed auto-approve gate — real progress into FLEET-auto (Step 2), while the doc's own header still claims only "Step 1 SHIPPED." No bucket move (PARTIAL is still the right bucket — more of the doc's total scope remains unbuilt than built), but the header needs a refresh so a future reader doesn't undercount what's already landed. |

**Net effect:** SHIPPED 16→18 (+2), PARTIAL 14→16 (+2, one file's bucket held with stale
content flagged separately), PARKED 58→57 (+3 new, −2 to SHIPPED, −2 to PARTIAL = net −1),
total 88→91 (+3 new files, consistent with the 89→92 on-disk count).

## Flagged, not classified as drift

- **`alert_manager/port_risk.py` + `nemesis_agent/modules/listening_ports.py`** (305+
  lines, real code, `8fe95f2`/`2a2d50f`/`c332b1a`) have **no caller anywhere in the repo
  outside their own test files** — genuinely in-progress but not reachable from any
  production path yet. No matching roadmap file exists for this specific mechanism;
  `vulnerability-patch-management.md`'s "Port-exposure check" section names this exact
  planned feature and correctly stays PARKED — the code exists but isn't wired in. Not a
  classification error, just worth surfacing so it isn't independently rediscovered later
  as "why does this code have no roadmap entry."
- **Licensing (`1c1115a`) and entitlements (`d007bf4`) feat commits** have no corresponding
  public roadmap file. Consistent with the established private-module/Tier-2 pattern
  (`HANDOFF.md` confirms this is Window 3's private key-pack build) — not a public
  tracking gap, same reasoning already applied to Tier 2 TLS interception elsewhere in this
  audit series.
- **`malware-layer-d-local-ml.md`** (already PARTIAL) has 2 new commits (`745c56d`,
  `5069f57`) that read as progress within its existing bucket, not a bucket move. Not
  independently re-verified in depth this pass.

## Not independently re-verified this pass (scope boundary, stated plainly)

Per this audit's full-re-derivation methodology: the 16 baseline-SHIPPED and remaining 12
baseline-PARTIAL items not named in the drift table above were checked only via
commit-subject keyword sweep (no match found), not individually re-opened and re-read
against live code. Same boundary the 09-02 audit itself declared for its own incremental
pass — stated explicitly here rather than implied, so "unchanged" means *no commit-level
signal found*, not *individually re-verified*. Likewise, the ~54 baseline-PARKED items with
no matching commit activity were not re-opened individually; only those matching the dense
`feat` commit activity since 09-02 (licensing, diagnostics canary, layer-d, entitlements,
port-risk/exposure, installer email delivery, usb-control, anomaly post_detection_egress,
threat-feeds, lan-behavior, enrollment ADR 0012) were checked, per the table above.

## Method

Full commit list since the 09-02 12:07 baseline (addenda included) swept for roadmap-
relevant `feat`/`docs(roadmap)` subjects. Every real hit verified directly against live
code (`grep`/`Read` of the named module or route, not commit-message claims alone) —
per this project's standing "classify against code and git log, never against a file's
own Status header" discipline. File-set arithmetic (91 tracked + 1 excluded = 18 + 16 + 57
= 91) confirmed against `ls docs/roadmap/*.md` = 92 on disk.

Baseline doc for the next Morning Status: this file (2026-09-05), superseding
`roadmap-state-audit-2026-09-02.md`.
