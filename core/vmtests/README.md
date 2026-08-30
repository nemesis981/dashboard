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
