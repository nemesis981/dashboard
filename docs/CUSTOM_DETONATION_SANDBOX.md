# CUSTOM_DETONATION_SANDBOX.md — local disposable-VM detonation sandbox

Malware **detonation tier**: run a file you ASSUME IS HOSTILE in a throwaway,
isolated VM and observe what it *does* — the behavioral confirmation a
signature/ML layer structurally cannot give for a novel sample. Self-hosted; the
sample never leaves the machine. Implementation: `modules/malware_detection/sandbox.py`
(`DisposableSandbox`), base built by `build_detonation_base_linux.sh`.

The whole security of this feature is two properties, both ENFORCED and both live-proven
against real VirtualBox (2026-08-21):

1. **Isolation is VERIFIED before detonation, and REFUSED if it cannot be proven.** Every
   NIC must be `none` (or one explicit hostonly adapter) and no shared folder may remain;
   the config is read back and detonation fail-closes on any doubt. A sandbox that detonates
   into an unverified environment is a live-malware breach with a "contained" label.
2. **Teardown is GUARANTEED and READ-BACK VERIFIED.** The throwaway VM is destroyed no
   matter how detonation ends, and its absence is confirmed against `VBoxManage list vms` —
   never assumed from a command returning.

---

## The isolation-safe result channel (why guestcontrol, not the network)

The sample must be executed and its observation retrieved **without** giving the guest a
network or a writable path to the host. Both happen over the VirtualBox **guestcontrol**
channel — a host↔guest control device, NOT a NIC — so they work with `network='none'`:

- **execute:** `guestcontrol run` invokes the in-guest runner.
- **collect:** `guestcontrol copyfrom` pulls the observer's event file out.

The sample goes IN one way only: on a **read-only ISO** (no shared folder, so the guest
cannot write back to the host through it).

---

## The detonation base-image contract (what the base MUST carry)

`build_detonation_base_linux.sh` provisions all of this; the items and the reasons — every
one learned the hard way on the 2026-08-21 live build:

- **Full Guest Additions USERLAND** (from the host's `VBoxGuestAdditions_<ver>.iso`), NOT the
  distro `virtualbox-guest-utils` package. The distro package serves guest properties but its
  `VBoxService` does **not** reliably do guest *process control* — guestcontrol `run`/`copyfrom`
  fail with "session terminated / VERR_DUPLICATE". The full-GA userland works.
  - The GA kernel-**module** build may FAIL on a very new kernel (seen on 7.0:
    `vboxguest uses symbol __flush_tlb_all ... does not import it`). **Harmless** — modern
    kernels ship an in-tree `vboxguest`; only the userland is needed. The builder checks the
    module is present from *some* source and proceeds.
- **An in-guest OBSERVER** — Falco (reuses `deploy_behavioral_linux.sh`), writing JSON events
  to `/var/log/falco/events.json`. Falco is `enable`d so it runs on every clone's boot.
- **`/opt/detonate/run-sample.sh` + a scoped NOPASSWD sudoers rule.** The guestcontrol session
  runs as an **unprivileged login user** (root is PAM-locked on Ubuntu and cannot open a
  guestcontrol session), so the runner is called `sudo -n /opt/detonate/run-sample.sh`,
  passwordless for **that one path only**. The runner mounts the read-only sample ISO
  (`/dev/sr0`) and executes the sample.
- **An empty `events.json` at snapshot time**, so each detonation's observation is only that
  sample's behavior.

Host steps bracket the in-guest build (attach the GA ISO before; power off, **detach the GA
ISO** so the sample ISO is the only optical device, isolate the NICs, and snapshot after).
Exact commands print at the end of the builder.

---

## Using it

```python
from sandbox import DisposableSandbox
s = DisposableSandbox("Detonation Base", "clean-detonation-base", network="none",
                      guest_user="test-user", guest_pass="<pw>",
                      observer_path="/var/log/falco/events.json")
report = s.detonate("/path/to/sample",
                    run_cmd=["/usr/bin/sudo", "-n", "/opt/detonate/run-sample.sh"],
                    timeout_s=30)
# report["isolation_verified"] is True, report["detonated"] is True,
# report["observation"]["events"] is the Falco events the sample produced,
# and the throwaway VM is already destroyed + confirmed gone.
```

Proven live 2026-08-21: a benign sample that reads `/etc/shadow` detonated in a real isolated
clone produced 40+ `Read sensitive file untrusted` observations, pulled out over copyfrom, and
the VM was confirmed destroyed.

**Real malware:** identical flow. Never disable the isolation verification, never give the base
a NIC, never widen the NOPASSWD rule. Keep real samples encrypted/labelled at rest and treat
the read-only ISO as the one-way door it is. A verdict from detonation is a finding INPUT,
advisory like the other layers.

---

## Windows detonation (future)

The base would carry Sysmon/Procmon as the observer and a RunOnce/scheduled-task runner; the
sandbox flow (isolate → verify → attach RO sample → execute → collect observation → guaranteed
teardown) is identical, only the in-guest front door differs. The Linux/Falco base is the one
built and proven today.

## Rule-8

No real IPs / hostnames / home paths in the base image, the runner, or examples — placeholders
only. The base's login/guestcontrol credential is a throwaway test-VM credential (see the
local-secrets convention), never a host secret, and lives only inside the disposable base.
