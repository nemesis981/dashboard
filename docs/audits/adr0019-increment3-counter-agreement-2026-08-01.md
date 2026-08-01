# ADR 0019 Increment 3 — counter agreement, measured and PASSED (2026-08-01)

**Result: PASS.** The derived `nemesis_enforce` observe rules and ufw's own per-IP DROP
counters agreed exactly, over two independent intervals, on traffic confirmed to have
arrived. This is the proof Increment 3 exists to produce, and the gate Increment 4 was
waiting on.

> **Mechanism detail kept private per Rule 10** (operator decision, 2026-08-01, matching this
> ADR's existing disclosure posture): the specific nftables hook priority, chain names, and
> rule-by-rule traversal used to construct a valid test are exploit-relevant precision, not
> architectural direction. This audit records the result, the measurement discipline, and the
> harness-defect narrative — not the mechanism. Full evidence is in the private mirror.

---

## Why four earlier attempts proved nothing

Increment 3 compares two counters for the same address. For that comparison to mean
anything, real traffic has to reach the point in the ruleset both the per-IP block and the
derived observe rule live at. Four attempts, across this and earlier sessions, failed to
achieve that — each for a distinct, separately-diagnosed reason, not a repeat of the same
mistake:

1. **Table not loaded.** Lost at a reboot; nothing re-applied it before the attempt (the gap
   this ADR's persistence unit now closes going forward).
2. **Table applied, zero blocks in place.** No observe rules existed during the window, so
   there was nothing for either side's counters to agree or disagree about.
3. **A real block, but a silent peer.** The rule was present, but the target sent no traffic
   against it — both sides reading zero is not agreement; a comparison needs real traffic on
   both sides to mean anything.
4. **Self-generated synthetic traffic (ICMP).** Invalid as a measurement, not merely another
   inconclusive result: synthetic traffic sent from a testing tool does not exercise the same
   code path a genuinely new inbound connection does, so it cannot stand in for one. This
   attempt is also what led to a separate, independently-tracked finding about the current
   interim block mechanism — recorded privately, not detailed here.

A fifth run then produced a **correctly-isolated measurement**: an independent traffic
generator producing confirmed new connections, with arrival and source verified directly by
packet capture rather than inferred from either side's counters, and a hard gate that aborted
the run if the generator wasn't confirmed producing real traffic. That is the measurement
that passed.

## A harness defect that produced a false FAIL, since retracted

An earlier run of this same test reported a `FAIL — the two engines disagreed`. **That
verdict has been retracted.** It was not a firewall defect — it was a bug in the measurement
script itself: the two sides of the comparison represented the same address in two different
text formats (one included a network-mask suffix, one didn't), so the exact-match lookup
between them silently failed and defaulted to reading as "zero" on one side. That default
was then misread as "the firewall dropped nothing," producing a FAIL against a mechanism that
was in fact working correctly.

**Fix, at the harness level:** both sides of the comparison now derive their address
representation from the same source so they key identically by construction rather than by
coincidence, and — the more durable fix — a missing or unmatched reading now fails the run
outright (`INCONCLUSIVE`) rather than silently defaulting to a value that looks like real
data.

## Harness rule adopted: absence of a reading is not a measurement

Every defect found during this work — across four earlier attempts plus this false-FAIL
artifact — shared one shape: a value that could not actually be obtained was reported as
though it had been measured (an empty comparison read as "agree"; a failed lookup defaulted
to "zero" and was read as real). The rule now recorded in the measurement harness itself:

> A missing value must be reported as missing, and must make the run inconclusive. It must
> never fall back to a value that means something. Defaults are for configuration, never for
> evidence.

## Increment status after this run

| Increment | Status |
|---|---|
| 1 — priority placement | Proven. Re-confirmed during this work. |
| 2 — lockout failsafe | Proven. Auto-revert observed disarming cleanly on confirm. |
| 3 — derived observe-only rules | **PROVEN 2026-08-01.** Counter agreement measured over two intervals on confirmed real traffic. |
| 4 — cutover to real enforcement authority | **Both hard prerequisites now met**: the netlink watcher (built, VM-verified) and this measurement. Not yet started. |

## Reproduction

Full evidence (packet capture, generator log, before/after rulesets, raw measurement output,
and the specific mechanism detail behind why the valid attempt worked) is kept in the private
mirror, not reproduced here.
