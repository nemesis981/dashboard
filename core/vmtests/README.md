# Fork B VM test harnesses

These are NOT part of the ordinary suite. They require **root** and an **isolated VM**,
because they create real `wireguard`/`tun` devices and edit the live routing table.

    test_forkb_topology_matrix.py   decision layer vs REAL kernel interface kinds
    test_forkb_reconcile_e2e.py     reconcile() against a live routing table

Run only on a throwaway VM with an isolated data plane. `core/test_forkb_policy_route.py`
is the hermetic suite and needs none of this.

**What they prove that fixtures cannot:** that `info_kind` for a genuine WireGuard device
really is `wireguard`, that the `tun` sysfs fallback fires, and — the important one —
that a bypass which loses a priority race is actually removed from the kernel again
rather than left in place reporting success.

**What they do NOT prove:** the behaviour of any particular VPN product. They feed the
classifier real kernel data; they do not run PIA, OpenVPN or WireGuard as clients.

## Known one-off: a SNAT chain observed with no config (2026-08-30, unreproduced)

During the first end-to-end switch run, a cleanup check reported one masquerade rule
present while `/etc/nemesis.env` held no gateway keys. The same anomaly had already
produced a spurious FAIL earlier in that run, by seeding a dirty baseline.

**Ruled out by measurement afterwards:**

* it does not survive a reboot (clean on restart);
* a fresh render with no config emits zero masquerade rules;
* a `ufw reload` with no config produces no chain -- sampled every second for 10s,
  all zero;
* the watcher does not silently restore a stale ruleset: `autorestore` is off by
  default, and its journal shows it ALERTING on the test's table edits
  (`NEM-FWW-0002 deleted`, `NEM-FWW-0001 modified outside Nemesis`) rather than
  repairing them.

**Not explained, and not reproduced since.** Recorded rather than dismissed because a
NAT rule existing without configuration is exactly the shape that matters. The
practical guard is already in place: `test_gateway_switch_e2e.py` phase 0 asserts a
clean baseline on all four axes and REFUSES to run otherwise, so this cannot silently
corrupt a future result the way it corrupted the first one.
