# Finding — the connectivity watcher reports DEGRADED for as long as an IPv6-blocking VPN is connected

**Status:** Open. Found 2026-08-03 while answering an unrelated question about API
connectivity. **Not a connectivity fault** — a diagnostics false positive. Filed separately
so it does not get folded into the PIA/Tailscale testing story it surfaced during.

**Filed here rather than `PUNCHLIST.md` only because that file had another window's
uncommitted work in it at the time.** Fold it into the punchlist when the file is free.

---

## What was observed

`diagnostics_connectivity_samples` shows a continuous `DEGRADED` verdict with the note
`ipv6 keytest failed`:

| verdict | note | samples | window |
|---|---|---|---|
| `DEGRADED` | `ipv6 keytest failed` | **1,264** | 2026-08-01 03:12 → 2026-08-03 15:05 |
| `ALL_OK` | — | 694 | 2026-08-03 15:06 → present |

**At least 60 hours continuous, and the true duration is unknown** — 2026-08-01 03:12 is
simply the oldest retained sample. The table is capped at 2,880 rows
(`watcher_samples_max`, ~48h at 60s), so the start of this condition has already aged out.

Throughout the entire window, every other probe passed: `routing_ok`, `dns_ok`, `egress_ok`
and `api_ok` recorded **zero** failures across 654 samples in the last 12h alone. Real
outbound connectivity — including to `api.anthropic.com` — was never affected.

## Mechanism (confirmed, not inferred)

`_probe()` in `modules/diagnostics/watcher.py` runs three curls against `api_host`:

```
api_ok = _curl(api_host)          # whatever the stack picks
v4_ok  = _curl(api_host, "-4")    # forced IPv4
v6_ok  = _curl(api_host, "-6")    # forced IPv6
```

and `classify()` returns `ALL_OK` only when **all three** succeed; if `api_ok` passes but a
variant fails, the verdict is `DEGRADED`.

So `ipv6 keytest failed` means exactly: **`curl -6 https://<api_host>` did not succeed.**

Verified directly once the condition cleared: the host has a global IPv6 address and a
default IPv6 route, and `curl -6` to the API returns HTTP 404 in ~0.04s — the expected
unauthenticated response. IPv6 works fine.

The condition cleared the moment the VPN tunnel came down. Its daemon and client processes
are still running, but no tunnel interface is present. **Consumer VPNs commonly disable or
block IPv6 outright as leak protection** — that is a deliberate, correct security feature,
not a fault.

Supporting evidence: mean probe latency was **269.5 ms** across the 433 samples before the
transition and **37.5 ms** across the samples after — a ~7x drop consistent with traffic no
longer traversing a tunnel.

*(Labelled honestly: the mechanism above is confirmed. Attributing the exact 15:06 clear to
the VPN specifically is an inference from timing plus the latency shift — the watcher's own
`vpn_connected` field read 1 both before and after, so it did not register the change.)*

## Why it matters

**Any Nemesis user running a VPN with IPv6 leak protection sees a permanent "Degraded"
verdict.** That is a large fraction of the intended audience — the product's whole thesis is
non-expert users who are likely to run exactly this kind of VPN.

The consequences are the usual ones for a false positive that never clears:

- A permanently-degraded badge trains the operator to ignore the diagnostic, so a *real*
  degradation later is invisible in the noise.
- The verdict vocabulary is `ALL_OK` / `DEGRADED` / `UPSTREAM_FAIL` / `LOCAL_FAIL`. `DEGRADED`
  is documented as "Connection works but one path is impaired (e.g. IPv6)" — technically
  accurate, but it reads to a non-expert as "something is wrong with my firewall", when the
  correct reading is "your VPN is doing its job".
- It is self-inflicted noise in the one surface meant to answer *is it me or them*.

## Suggested direction (not a decision)

Options worth weighing, in rough order of preference:

1. **Detect the absence of usable IPv6 and treat the v6 keytest as N/A rather than failed.**
   If there is no global IPv6 address or no default IPv6 route, `curl -6` failing carries no
   information. This also fixes plain IPv4-only networks, which have the same false positive
   for a completely different reason.
2. **Treat "v6 fails while v4 and default both pass" as informational, not `DEGRADED`** —
   surface it as a note without changing the verdict.
3. **Make the v6 keytest opt-in** via a setting, defaulting off.

Option 1 is the most correct: it distinguishes *"IPv6 is broken"* from *"there is no IPv6
here"*, which is the actual missing signal.

## Also visible in the same retained window — separate, not investigated

Recorded because the evidence ages out of this table within ~48h and would otherwise be lost:

| verdict | note | samples | window |
|---|---|---|---|
| `LOCAL_FAIL` | `dns resolution failed` | **868** | 2026-08-01 10:19 → 2026-08-02 09:22 |
| `UPSTREAM_FAIL` | — | 50 | 2026-08-01 09:16 → 10:17 |
| `LOCAL_FAIL` | `no default route` | 4 | 2026-08-01 08:12 → 2026-08-02 18:52 |

The DNS one is ~23 hours of `LOCAL_FAIL`, which is a materially different claim from the IPv6
issue — that verdict means *"a local problem is blocking traffic"*. Whether it was real or
another artifact of the same test activity is **not established here** and wants its own look.
