# Scope — consolidating the two genuine duplication findings (DESIGN ONLY, NOT BUILT)

**Date:** 2026-09-02 · **By:** Window 3 · **Status:** design/scope for operator review.
**No code changed.** Follows on from `docs/audits/duplicated-logic-sweep-2026-09-02.md` (A1, A2)
and applies the same discipline as `net_identity.py`'s consolidation: read what each caller
actually needs before designing anything, keep genuinely different behaviour separate, propose a
shared utility only where the underlying mechanism — not just the surface shape — is the same.

---

## Part 1 — eve.json tail-loop consolidation

### What each of the three callers actually does, verified line-by-line

| | `lan_behavior_monitor` | `lan_integrity` | `anomaly_detection` |
|---|---|---|---|
| selftest gate before tailing | yes (`behavior.selftest()`) | yes (`rogue_dhcp.selftest()`) | **no** |
| rotation detection | `(inode, size)` compare | `(inode, size)` compare | `(inode, size)` compare — **identical logic, independently written** |
| distinguishes "never run" from "ran, offset legitimately 0" | **yes** — `_get_state("eve_offset", "")`, empty string is the sentinel | **no** — defaults straight to `"0"`, cannot tell the two apart | **no** — same as lan_integrity |
| first-run policy | seek to end (today's fix) | **none** — falls straight through to offset 0 | bounded historical baseline (`INITIAL_BASELINE_MAX_DAYS`), then jump to end |
| structured error on stat/read failure | `_record(E_EVE_UNREADABLE, ...)` | `_record(E_EVE_UNREADABLE / E_ARP_SOURCE_UNREADABLE, ...)` | **none** — bare `log.exception` at the outer loop, no dashboard-visible code |
| event-type filter | byte-sniff `arp`/`alert`/`mdns` before JSON parse | byte-sniff `dhcp`/`arp` before JSON parse | byte-sniff `dns` before JSON parse — same technique, different types |
| per-event handling | fully module-local (`behavior.parse_*`, in-memory state machines) | fully module-local (`rogue_dhcp.*`, `arp_watch.*`) | fully module-local (baseline/exfil accumulators) |
| offset/inode persisted at end | yes | yes | yes |

**A third real drift, found while gathering this table, not in the original sweep:**
`anomaly_detection._detection_cycle()` has no structured error code on a read/stat failure — its
only handling is `log.exception("anomaly_detection: cycle error")` in the outer loop, with no
`_record(...)` call. Its two siblings both surface a dashboard-visible error state on the same
failure. Not the same bug class as the A1 backlog-replay finding, but directly relevant to this
design: it's an existing gap in error observability, not a design decision this consolidation
gets to invent.

### What is genuinely the same mechanism (worth sharing)

1. **Rotation detection** — `(inode, size)` compare against persisted state, reset offset to 0 on
   mismatch. Identical in all three, character-for-character similar. This is boilerplate, not
   domain logic.
2. **The seek-and-iterate-lines shape** — open, seek to offset, iterate raw lines, track
   `fh.tell()` for the next offset. Identical mechanism, only the byte-sniff strings and the
   per-line handler differ.
3. **First-run / offset-loss ambiguity** — all three currently have some version of "what do I do
   when there's no reliable prior offset," and two of the three answer it wrong or not at all.
   This is exactly the kind of decision that should be a single, tested piece of logic with the
   *policy* as a parameter, not three independent (and now provably divergent) answers.

### What is genuinely different (must NOT be forced together)

1. **What happens per matched line** is 100% domain-specific — `behavior.parse_arp_probe()` vs
   `rogue_dhcp.parse_event()` vs DNS baseline accumulation. None of this belongs in a shared
   utility; it's the entire reason these are three separate modules.
2. **First-run policy itself is a real design choice per detector**, not one-size-fits-all:
   - `lan_behavior_monitor` is a **rate-based** detector — a burst from last week is definitionally
     not "happening now." Seek-to-end is correct for it.
   - `anomaly_detection` needs a **baseline** — "what's normal for this network" requires some
     history. Bounded-then-jump is correct for it.
   - `lan_integrity` detects **standing state** (which DHCP server is active, which IP↔MAC
     bindings exist) — arguably closer to `anomaly_detection`'s shape than
     `lan_behavior_monitor`'s, since a rogue DHCP server that appeared 2 hours ago and is still
     serving IS something a fresh install should surface, not silently skip. **This is Window 1's
     call, not mine** — I've handed the immediate fix to them with both options named; whichever
     they pick, the shared utility (if built) must support both as an explicit parameter, not bake
     in one answer.
3. **Selftest gating** — `anomaly_detection` doesn't have one. Whether it should is a question
   about that detector's own failure semantics, not something a shared tailer utility should
   decide by omission or by forcing a gate that wasn't asked for.

### Proposed shape (strict superset — not built)

```python
# alert_manager/eve_tail.py  (proposed location — neutral, alongside net_identity.py)

def tail_cycle(state_get, state_set, event_types, handle_line,
                first_run_policy="seek_end",     # "seek_end" | "bounded_baseline" | "from_zero"
                baseline_fn=None,                 # required iff first_run_policy == "bounded_baseline"
                error_recorder=None,               # optional _record(code, detail)-shaped callable
                path=EVE_LOG):
    """One safe pass over new eve.json bytes. Returns (new_offset, new_inode, error|None).

    Does NOT touch state itself beyond returning what changed -- callers persist via their
    own _set_state, so each module keeps its own state-key names and its own counters.
    Does NOT interpret matched lines -- `handle_line(event_type, raw_bytes, parsed_json)`
    is caller-supplied and does 100% of the domain-specific work.
    """
```

Deliberately **thin**: rotation detection, offset bookkeeping, the byte-sniff-then-parse loop,
and the first-run policy branch are the only things it owns. Everything else stays exactly where
it is. `error_recorder` is optional specifically because forcing it into `anomaly_detection`
would be inventing a design decision (should that detector's read failures be dashboard-visible?)
that belongs to whoever owns that module, not to this consolidation.

**Open question for whoever builds this:** is a shared function actually less risk than fixing
`lan_integrity`'s immediate exposure directly (Window 1, in progress) and leaving the mechanism
duplicated a while longer? The immediate bug does not require this design to land first — see
PUNCHLIST, filed as its own item, unblocked by this document either way.

---

## Part 2 — `/proc/net/arp` parser consolidation

### What each consumer actually needs

| | `arp_watch.parse_proc_arp()` | `device_scanner._arp_devices()` |
|---|---|---|
| skip header | `text.splitlines()[1:]` | `fh.readlines()[1:]` |
| column extraction | `parts[0]`=ip, `parts[2]`=flags, `parts[3]`=mac | identical indices |
| INCOMPLETE filter | `flags == "0x0" or not mac` (after normalisation) | `flags == "0x0" or mac == "00:00:00:00:00:00"` (before normalisation) |
| MAC normalisation | `_norm_mac(mac)` — a real function, not inspected further in the original sweep | bare `.lower()` |
| subnet filtering | **none** — every resolved entry matters (all are potential spoofing signal) | **yes** — drops anything outside the scanned `net` (docker/VPN/other-interface neighbours) |
| output shape | list of dicts: `ip, mac, opcode, gratuitous, source, confidence, ts` | list of tuples: `(ip, mac, vendor)` |
| consumer | security classification (`classify()`, spoofing state machine) | device inventory (vendor lookup, DB upsert) |

**`_norm_mac()`'s actual behaviour was checked now** (flagged as unchecked in the original sweep),
and the divergence is real and concrete, not merely theoretical:

```python
_NULL_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}

def _norm_mac(m):
    m = (m or "").strip().lower()
    return m if m and m not in _NULL_MACS else None
```

**Corrected 2026-09-02, same day, after Window 1 independently re-checked this section**: the gap
is narrower than first stated. `device_scanner`'s `parts = row.split()` (no-argument `split()`)
already discards all whitespace during tokenisation, so `parts[3]` can never carry leading/
trailing space — "never strips" was not a real second gap, it described behaviour that has no
observable consequence. **The actual, sole defect is the missing broadcast-MAC guard**:
`arp_watch` rejects both the null MAC and the broadcast MAC (`ff:ff:ff:ff:ff:ff`);
`device_scanner` rejects only the literal null MAC. **Concrete consequence**: a broadcast ARP
entry in `/proc/net/arp` — not a hypothetical edge case, gratuitous/broadcast ARP traffic exists
on real networks — would be silently discarded by `arp_watch` and could be recorded as a spurious
device by `device_scanner`. Not observed to have fired; not checked against the live ARP table
for this box. A one-line fix (add the same `_NULL_MACS`-style check) closes it directly, without
needing the full consolidation below — see the sequencing note at the end of this document.

### What is genuinely the same (worth sharing)

Parsing `/proc/net/arp` text into `(ip, mac)` pairs, with INCOMPLETE/null/broadcast filtering.
This is a pure function of the file's text format — the kernel's ARP table layout, not anything
about either consumer's purpose.

### What is genuinely different (must NOT be forced together)

- **Output shape** — `arp_watch` needs full observation dicts (source, confidence, timestamp) for
  its classification state machine; `device_scanner` needs bare `(ip, mac)` for inventory + vendor
  lookup. A shared parser should return the minimal common shape (normalized `(ip, mac)` pairs)
  and let each caller build its own richer structure on top — not try to satisfy both shapes in
  one return type.
- **Subnet filtering** — `device_scanner`'s "is this in the network I'm scanning" filter is
  entirely about its own inventory scope and has nothing to do with ARP parsing. Stays local.
- **What "usable" means downstream** — `arp_watch` treats every resolved entry as spoofing signal;
  `device_scanner` only cares about entries in its target subnet. Same input, different
  downstream questions — exactly the "legitimately different consumers of the same parsed rows"
  shape named in the original sweep.

### Proposed shape (strict superset — not built)

```python
# alert_manager/proc_arp.py  (proposed location — neutral, alongside net_identity.py)

_NULL_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}   # the union of both current checks

def parse_proc_arp_text(text):
    """(ip, mac) pairs from /proc/net/arp content. Drops header, INCOMPLETE
    entries, and null/broadcast MACs. Returns [] on unparseable input, never
    raises -- callers already have their own stat/read error handling."""
```

Deliberately **only** the extraction. `arp_watch.parse_proc_arp()` would call this and build its
richer dicts on top; `device_scanner._arp_devices()` would call this and apply its own subnet
filter and vendor lookup. Neither downstream consumer's logic moves.

---

## Summary and recommendation

| | mechanism duplicated | already measurably drifted | shared utility scope |
|---|---|---|---|
| eve.json tailer | rotation detection, seek/iterate, first-run ambiguity | yes — 2 of 3 lack backlog protection; 1 of 3 lacks structured errors | thin: rotation + iterate + pluggable first-run policy. Domain logic (what a matched line means) stays fully local to each module. |
| `/proc/net/arp` parser | column extraction, INCOMPLETE/null/broadcast filtering | yes — broadcast-MAC gap is concrete, not hypothetical | thinner still: pure text→`(ip,mac)` extraction. Both consumers' shaping and filtering logic stay fully local. |

**Both proposals are intentionally narrow.** In each case the shared piece is boilerplate — file
mechanics or text parsing — never the domain logic that makes each module what it is. That is the
same boundary `net_identity.py` drew today (one enumeration, per-caller failure policy layered on
top), applied to two more categories of "the same question asked three times."

**Recommended sequencing, not a demand:**
1. `lan_integrity`'s immediate exposure (PUNCHLIST, Window 1 owns it) does not wait on either
   design here — it's a same-day patch to one file regardless of consolidation timing.
2. The `/proc/net/arp` broadcast-MAC gap is small and mechanical; whoever picks this up could
   plausibly fix `device_scanner`'s filter directly (copy the two-line `_NULL_MACS` check) faster
   than building the shared module, if the operator wants the concrete defect closed without
   waiting for the full consolidation.
3. The eve.json tailer utility is the larger design decision (three call sites, one live policy
   choice still open in `lan_integrity`'s fix) — natural to sequence after Window 1's fix lands,
   so the utility's `first_run_policy` parameter is designed against three *settled* answers
   rather than a moving target.

**Not proceeding to build either without explicit go-ahead**, per the instruction that opened this
task.

