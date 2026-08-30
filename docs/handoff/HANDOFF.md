# HANDOFF — current state

> Last updated **2026-08-30, nightly closeout (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/
> accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per
> Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-08-30-001.md` (curated — covers the whole day,
> both the morning docs/audit session and the afternoon/evening push-batch verification) and
> `docs/handoff/worklog/2026-08-30-001.md` (raw chronology, same scope).

---

## ⚠ 1. PIA is INTENTIONALLY connected overnight — soak test, not stray state

**Do not disconnect it first thing tomorrow without reading this.** Today's connectivity
classifier work (`cc75d5c` → `fbed8ef` revert → `d33f0b8` rebuild → `8f7703a`/`74bda0c`
generalisation) fixed a real production bug (a permanently-true `vpn_connected` flag silently
suppressing genuine IPv6/egress faults) and then generalised the replacement predicate
(`tunnel_carries_egress()`) past PIA-specific behaviour. PIA is being left connected overnight
**deliberately**, to let the new classifier run against real, sustained tunnel state rather
than only a point-in-time check.

**Verified live at session end** (`piactl get connectionstate` → Connected; `ip route show`
→ both `0.0.0.0/1` and `128.0.0.0/1` present via `tun0`) — the exact `/1`-straddle shape the
new predicate was built to classify as full-tunnel.

**Check first thing tomorrow morning:**
- Did `watcher.py` stay correctly classified overnight — no false DEGRADED/LOCAL_FAIL
  episodes for a VPN that never actually dropped?
- Did PIA itself stay connected the whole time, or did it reconnect/flap? (A reconnect cycle
  overnight is a separate, independently-worth-knowing fact from the classifier's own
  correctness.)

## 2. Push status — clean

`origin/main == local HEAD == c8bcb4f`, verified via `git fetch` + `git rev-parse` at session
end. 0 unpushed commits, working tree clean. **61 commits landed today** across all windows,
pushed in 8 independently-verified batches — see the supplement for the full batch-by-batch
account, including several count/attribution corrections caught before pushing (a claimed "3"
that was actually 5, a claimed "8" that was actually 7, a claimed "~25 including 5333a0c" that
was actually 2 with `5333a0c` already published three batches earlier).

## 3. Today's shipped work, condensed (full detail in the supplement)

- **DNS-exfiltration + rogue-DHCP detection** — reopened into v2 scope, spec'd, built.
- **Lateral-movement Tier 1 spec + Tier 2 scoping** — written; Tier 1's core premise (LAN
  peer-to-peer visibility) was found live-broken without gateway mode — see item 5 below.
- **Gateway Mode** — steps 1a through 5 shipped (`ip_forward` persistence, tailnet
  loop-prevention, negative-scope SNAT, installer provisioning, the reversible switch with
  proven rollback, the capability table). This is a substantial build, not a scoping doc
  anymore — reconciliation against `gateway-mode-scoping.md` is owed (item 5).
- **A1/A2 admin-approval ladder** — pairing/listing/approval-request routes, `restart` gated
  on verified approval, appliance-local gating for `ip_block_permanent`, a minimal
  front-end (pairing/approvals cards, ceremony), the L1 propose/approve/execute AI loop's
  first production writer.
- **Fork B policy-route bypass** — VPN-topology classification + refuse path, bypass table,
  plan/apply split, runtime reconciliation with rollback of a losing bypass, VM matrix +
  end-to-end reconcile against a real kernel. **NAT/masquerade piece still queued** (item 5).
- **Netfilter/tailnet drift detection** — root checker + unprivileged poller, pure-core
  detection logic. **Not yet deployed** as a running service (item 5).
- **Malware quarantine-restore** — capture original mode, admin-only restore, plus the
  ai_engine capability-ceiling correction it prompted.
- **Two real bugs caught and fixed same-day:** the RP-ID pairing crash (`pin_rp_id()` called
  with no argument; diagnosed read-only by this window, fixed by Window 1 as `c78d929`) and
  the capability-dormancy crash-loop (`8a8580f` — a live outage, 8 crash-loop cycles).
- **Installer Basic Auth removed** (operator ruling — dashboard login is the sole auth gate);
  two vhost gaps it exposed filed to PUNCHLIST, not fixed yet.
- **A new standing CLAUDE.md practice**: any module declaring routes now needs a
  registry-completeness test (prompted by `8a8580f` narrowing what the startup path catches
  loudly).

## 4. Elevated grants — see `docs/handoff/elevated-grants-tracking.md`

Unchanged pattern from this morning's structural fix — full detail lives in that file, edited
in place, not embedded here. Not re-checked live this evening (last live check was this
morning's Morning Status); no reason to believe it's changed, but say so plainly rather than
imply a check that didn't happen.

## 5. Open items, queued — not started, not forgotten

- **`scripts/nemesis-drift-check` deployment.** Built today (`a1805ed`, `e53aa85`). No
  matching systemd unit exists on this box as of session end — code exists, isn't live.
- **Fork B's NAT piece.** Everything else in Fork B's policy-route scope landed today; NAT/
  masquerade specifically did not. See `docs/roadmap/adr-0009-l3-fork-b-scope.md` (Piece 2)
  and PUNCHLIST (~line 1418).
- **Window 1's ADR 0005 rewrite handoff.** Named repeatedly today as next up; genuinely not
  started this session — every time it came due, a push batch or reassignment took priority.
- **Gateway-mode / checklist / lateral-movement-Tier-2 doc reconciliation.** Explicitly
  deferred by the operator until *after* the ADR 0005 handoff. Today's Gateway Mode build
  (steps 1a-5) and the live switched-LAN visibility finding (a non-gateway appliance
  structurally cannot see unicast peer-to-peer LAN traffic — confirmed via measurement, not
  assumed) both bear directly on `gateway-mode-scoping.md` (checklist item 1) and the
  ARP-spoofing-parked reasoning in `lateral-movement-outbreak-detection.md`. Neither doc
  reflects this yet.
- **The "prefix-coverage" PUNCHLIST entry.** Operator asked this be recorded as queued.
  **Not independently located this session** — searched `PUNCHLIST.md` and every commit that
  touched it today, found nothing matching. Recording it as open per direct instruction, but
  flagged honestly: a fresh session should ask for the specific line reference rather than
  trust this note has the right item.

## 6. Roadmap-vs-state

Tally as of this morning's audit: 11 SHIPPED / 12 PARTIAL / 61 PARKED — 84 total, baseline
`docs/audits/roadmap-state-audit-2026-08-24.md`. **Not re-run this evening** — today's shipping
volume (Gateway Mode, admin-approval, DNS-exfil, rogue-DHCP, quarantine-restore) almost
certainly moves several roadmap files from PARKED/PARTIAL toward SHIPPED, but that reconciliation
is folded into item 5's deferred doc pass, not redone piecemeal here.

## 7. Closeout health check

- Working tree: clean, confirmed via `git status --short` immediately before this commit.
- Closeout commit is HEAD: confirmed after this handoff's own commit (see below).
- local == origin: will confirm via `git fetch` + `git rev-parse HEAD origin/main` after push.
- HEAD touches only expected docs: confirmed for this commit (HANDOFF + worklog + supplement
  only, staged by exact path).
- Rule-8 spot-check: HANDOFF/worklog/supplement all scanned before commit — clean, placeholders
  only.
- Open items durably captured: this file's §5, plus the supplement's matching section.

## 8. Cross-references

- `docs/handoff/worklog/2026-08-30-001.md` — raw chronology, full day.
- `docs/handoff/supplements/2026-08-30-001.md` — curated account, full day, including the
  batch-by-batch push verification record and every count/attribution correction caught.
- `docs/handoff/elevated-grants-tracking.md` — standing elevated-grants record.
- `docs/briefing/2026-08-30.md` — this morning's Morning Status briefing.
- `docs/roadmap/dns-exfiltration-detection.md`, `rogue-dhcp-detection.md`,
  `lateral-movement-outbreak-detection.md`, `v2-completion-checklist.md` — today's roadmap
  work; the last two still owe the reconciliation pass in §5.
- `docs/handoff/supplements/2026-08-29-001.md` — prior day, `ed6af88` incident (closed this
  morning, see this file's history for that account).

## Topology

Largest single-day shipment of the tracked history so far: Gateway Mode went from a scoping
stub to steps 1a-5 built; the A1/A2 admin-approval ladder got its first production routes,
UI, and AI-loop writer; Fork B's policy-route bypass went from bypass-table design to a
VM-matrix-proven runtime reconciler; two real production bugs (RP-ID pairing crash,
capability-dormancy crash-loop) were caught and fixed same-day; and the connectivity
classifier had a full fix→revert→rebuild→generalise cycle, kept as separate history
deliberately rather than squashed, per Window 1's own recommendation — the regression and its
correction are both worth preserving as a record, not tidied away.
