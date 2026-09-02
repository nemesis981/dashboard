# Audit — duplicated/drifting logic across the codebase (read-only)

**Date:** 2026-09-02 · **By:** Window 3 · **Type:** Rule 1 read-only sweep. No code changed.

**Why this ran.** Today produced three real instances of the same failure shape: independent
implementations of "the same question" quietly drifting apart — the IP/MAC self-identity
resolvers (fixed today, `alert_manager/net_identity.py`), a near-duplicate USB collector Window 1
caught before building it, and earlier stale-spec instances in the roadmap docs. Operator asked
for a full sweep: where else does this pattern exist?

**Method, same discipline as this morning's roadmap sweep — apply it especially hard here.** This
morning's sweep shipped a headline claim ("zero findings") that turned out to be a guess
generalized from three verified samples, and was wrong. Every finding below was read in context
and checked against the actual code, not inferred from a name or a docstring match. Where a
candidate turned out to be legitimately different, the reasoning is recorded, not just the
verdict — so a future reader can tell "checked and different" from "not checked."

**Scope note.** This is a targeted sweep of the categories requested (identity/consent/
classification logic, shared external data sources), not an exhaustive scan of the repo. Time was
budgeted for depth over breadth per the operator's instruction; a few adjacent leads are named at
the end as not fully chased.

---

## Category A — Genuine duplication worth consolidating

### A1. Three independent `eve.json` tailers, and one carries today's already-fixed bug class

**The mechanism is duplicated, not just the intent.** `modules/lan_behavior_monitor/module.py`,
`modules/lan_integrity/module.py`, and `modules/anomaly_detection/module.py` each independently:
open `EVE_LOG`, seek to a stored byte offset, detect rotation via `(inode, size)` compared against
persisted state, byte-sniff `event_type` before paying full JSON-parse cost, and skip malformed
lines. The rotation-detection block is near-identical across the first two:

```python
offset = int(_get_state("eve_offset", "0") or 0)
inode = int(_get_state("eve_inode", "0") or 0)
if st.st_ino != inode or st.st_size < offset:
    offset = 0
if st.st_size <= offset:
    ...
```

**⛔ `lan_integrity` carries a LATENT version of the bug fixed in `lan_behavior_monitor` TODAY.**
Earlier today, `lan_behavior_monitor`'s first run replayed the full 1.1GB `eve.json` backlog and
produced 43 false findings — a real, live incident, fixed same-day (`10d2649`) by seeking to end
on first run rather than defaulting to offset 0.

`lan_integrity/module.py`'s offset default is `_get_state("eve_offset", "0")` — **the identical
zero-default that just caused a live incident elsewhere** — and its own docstring claims safety by
resemblance rather than by mechanism:

> *"Offset AND inode are tracked... **Same shape as anomaly_detection's tailer, which is the
> proven one in this codebase.**"*

That claim does not hold up. `anomaly_detection`'s tailer is NOT a bare zero-offset start — it
runs `_build_initial_baseline()` first (a **bounded** historical read, capped by
`INITIAL_BASELINE_MAX_DAYS`) and only then sets `eve_offset = st.st_size`
(`modules/anomaly_detection/module.py:432-497`). `lan_integrity` has neither the bound nor the
jump-to-end: verified by grep across the whole file, there is no `baseline`, `first.run`, or
`backlog` guard anywhere in `modules/lan_integrity/module.py`.

**Currently NOT firing on this box** — verified against the live DB, `lan_integrity`'s
`eve_offset` is already at `1208032407` (past the file's early history), because this install's
offset was established before the file grew large. **The exposure is real but latent**: it fires
on any fresh install, or if `eve_offset`/`eve_inode` state is ever lost — a DB restore from an
older snapshot, a migration, or a manual reset would all trigger a full-backlog replay of rogue-
DHCP and ARP-spoofing history, collapsed into "now," on a detector whose whole job is flagging
security-relevant network changes.

**Recommend:** treat this as its own PUNCHLIST item independent of any consolidation decision —
it is a live latent defect, not a style question. A shared "safely tail a rotating JSON-lines
file" utility, with the first-run policy (bounded-baseline vs. jump-to-end vs. none) as an
explicit parameter each caller sets, would prevent this class recurring a fourth time — but the
immediate fix (give `lan_integrity` the same jump-to-end `lan_behavior_monitor` just got) does not
need to wait for that design decision.

### A2. Two independent parsers of `/proc/net/arp`, already measurably drifted

`modules/lan_integrity/arp_watch.py:parse_proc_arp()` and
`core_module/device_scanner/device_scanner.py:_arp_devices()` each independently parse the same
kernel file, with the same shape:

| | arp_watch.py | device_scanner.py |
|---|---|---|
| skip header | `text.splitlines()[1:]` | `fh.readlines()[1:]` |
| columns | `parts[0]`=ip, `parts[2]`=flags, `parts[3]`=mac | same indices |
| INCOMPLETE filter | `flags == "0x0" or not mac` | `flags == "0x0" or mac == "00:00:00:00:00:00"` |
| MAC normalisation | `_norm_mac(parts[3])` | `.lower()` |

**The INCOMPLETE-entry check and the MAC normalisation have already diverged.**
`arp_watch._norm_mac()` is a real function (not inspected further here — worth a look for what it
does beyond `.lower()`); `device_scanner` does a bare `.lower()` and a literal string comparison
against the all-zero MAC. Two implementations of "is this ARP entry usable" is exactly the shape
that let the `is_ours()` self-identity check drift this morning — a security-relevant filter
written twice will diverge given enough time, and here it already has, just not yet in a way that
has produced an observed defect.

**Not the same finding as A1** — `lan_integrity/module.py._read_proc_arp()` correctly delegates
to `arp_watch.parse_proc_arp()` rather than re-parsing (verified: it opens the file and passes the
text straight through), so this is genuinely two parsers, not three. `device_scanner.py` is the
outlier.

**Recommend:** a shared `parse_proc_arp_line(s)` (or a shared "current ARP table" accessor) that
both consumers call, with each retaining its own downstream classification logic — `arp_watch`'s
spoofing-detection state machine and `device_scanner`'s device-inventory shape are genuinely
different consumers of the same parsed rows, only the parsing itself should be one definition.

---

## Category B — Similar-but-legitimately-different (verified, don't touch)

Each of these was checked against the actual implementation, not assumed clean from a name match.

### B1. `net_if_addrs()` — six call sites, three consolidated today, three genuinely different

`alert_manager/net_identity.py` (built and wired today) consolidates three of the six
`psutil.net_if_addrs()` call sites — `firewall._local_addresses()`,
`lan_behavior_monitor._refresh_local_identity()`, `anomaly_detection._pde_refresh_local_ips()` —
into one definition, with per-caller failure-policy layering preserved (fail-empty for firewall,
keep-previous for the self-exclusion callers). **Verified live**: all three now delegate rather
than reimplement.

The other three were **not** touched by that consolidation, and checked individually here rather
than assumed to be leftover drift:

- **`core_module/hw_monitor/agent_source_guard.py`** — **raises** `GuardError` on failure, by
  design ("never handed back an empty list that is indistinguishable from 'this host has no
  networks'"). Folding this into `net_identity`'s empty-on-failure contract would silently weaken
  a fail-loud security guard. Legitimately different failure semantics, not an oversight.
- **`core/remote_census.py._own_tailnet_addresses()`** — deliberately narrower: filters to
  `tailscale*` interfaces only, to avoid mislabelling this server's own tailnet node as an orphan.
  A different, smaller question than "every local address."
- **`nemesis_agent/agent.py`** — runs on the **monitored device**, not the Nemesis server. It is
  in a different package (`nemesis_agent/`, shipped to and executed on client machines) and
  cannot import `alert_manager/net_identity.py`, which is server-side only. Different machine,
  different process, different question ("is this address inside the configured Nemesis subnet"
  vs. "is this address the appliance itself").

**Verdict: correctly out of scope for today's consolidation.** Worth a one-line note in
`net_identity.py` acknowledging these three exist and why they're separate, so a future reader
doesn't rediscover this via the same grep.

### B2. Consent logic — single canonical source per side

Wide surface (31 files reference "consent"), but the decision logic is not duplicated:
`alert_manager/conn_consent.py` is the sole writer of the server-side `conn_consent` table, and
`hw_monitor._server_consent_version()` is the sole reader performing the fail-closed ingest-gate
decision. The only other direct `SELECT` against that table
(`conn_consent.py:155`) checks `revoked_at` alone, inside the write module's own pre-mutation
guard — a narrower, legitimately different question ("is this already revoked, before I revoke
it again"), not a second copy of the ingest decision. `nemesis_agent/consent.py` is the
agent-side equivalent, in a different package for the same machine-boundary reason as B1's third
item.

### B3. Hardware fingerprinting — single canonical source, properly reused

`nemesis_agent/hwid.py` is the one signal-collection implementation. `core/install_id.py` and
`core_module/hw_monitor/hw_monitor.py` both load it **by absolute path** rather than
reimplementing, with matching reasoning in both docstrings ("same fix, same reasoning as..."). A
comment in `install_id.py` flags hw_monitor's loader as "broken," which reads alarmingly out of
context — verified: it refers to a past `sys.path` mechanism bug in the *loading*, already fixed
identically in both places, not a fingerprinting-logic divergence.

### B4. The "known set" dedup pattern — one function, one file

`_persist_known_set()` (trust-boundary dedup for known users/USB devices) is defined once in
`core_module/hw_monitor/hw_monitor.py` and called only from within that same file.
`dashboard.py`'s only hit is a tooltip string naming where the data lives — display, not logic.

### B5. MAC vendor lookup — one function, one file

`lookup_mac_vendor()` is defined once in `device_scanner.py`; other hits are callers or comments
referencing it, not reimplementations.

### B6. `dns_exfil.py` / `post_detection.py` — pure logic, not I/O duplication

Both matched an early grep for `eve.json`/`EVE_LOG` reference. Verified: neither opens the file —
they are scoring/correlation logic consumed by `anomaly_detection/module.py`'s single tailer.
Counted correctly as one tailer for that package, not three (see A1).

---

## Category C — Ambiguous / needs a closer look (not verified either way)

Named honestly as unchased rather than silently dropped, per the operator's instruction to be
explicit about scope:

- **`arp_watch._norm_mac()`'s exact behaviour** was not compared line-by-line against
  `device_scanner`'s bare `.lower()`. The INCOMPLETE-flag check is confirmed to match; whether the
  normalisation difference is currently benign (e.g., `/proc/net/arp` MACs may already arrive in a
  fixed case) or a live source of missed matches was not established.
- **The `dmesg`/`/proc/*` reader list surfaced but not individually checked**: `diagnostics/
  hardware.py`, `core_module/malware_scan/malware_scan.py`, `modules/dhcp/module.py`,
  `diagnostics/vpn_status.py`, `scripts/gen_units.py`. These read different `/proc` paths for
  different stated purposes (hardware stats, DHCP leases, VPN interface state) and looked
  unrelated on a first pass, but none was verified with the same rigor as the ARP and eve.json
  findings above. Time-boxed out rather than confirmed clean.
- **Whether `anomaly_detection`'s bounded-baseline policy is itself correctly bounded** (i.e.,
  does `INITIAL_BASELINE_MAX_DAYS` actually prevent the same class of replay-collapse A1 found,
  just with a longer window rather than none) was asserted from its own docstring, not independently
  re-derived or tested here.

---

## Summary

| finding | class | status |
|---|---|---|
| A1: 3 eve.json tailers, `lan_integrity` carries a latent version of today's bug | genuine, latent security-relevant bug | needs its own fix, independent of any consolidation timing |
| A2: 2 independent `/proc/net/arp` parsers, already-drifted normalisation | genuine duplication | worth consolidating, not urgent |
| B1–B6 | six candidates checked, all legitimately different or already correctly consolidated | no action |
| C: 3 items | not verified either way | flagged, not investigated further today |

**One finding stands apart from the rest: A1's `lan_integrity` exposure is not a style
preference, it is the same live-incident class that fired earlier today, sitting unfired in a
sibling module, protected only by a docstring's inaccurate claim of parity.** Recommend it get a
PUNCHLIST entry today rather than waiting on a general tail-utility design discussion.
