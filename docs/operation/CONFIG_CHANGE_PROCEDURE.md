# Pushing Config Changes Safely

## The Golden Rule
Never push a config change directly to your full fleet. Always test on a VM agent first.

## Procedure

### Step 1 — Make the change
Update the config on the Nemesis dashboard. The change is staged but not yet applied to any
agents.

### Step 2 — Test on a VM agent
If you don't have a VM agent enrolled, create one (see VM Lab).
Dashboard → Devices → [VM device] → Restart Agent.
Wait ~30 seconds. Verify:
- Agent shows connected
- New config version shown on the device detail
- Changed feature works as expected

### Step 3 — If the test passes, deploy wide
Dashboard → Devices → Restart All Agents.
Agents restart in sequence (staggered — one at a time, 30 seconds apart by default). Monitor
each coming back online. The dashboard shows which agents are on the new config version.

### Step 4 — If the test fails, fix first
The VM took the hit. Real devices are untouched on the previous config. Fix the config,
re-test on the VM, then deploy wide.

## Why the VM?
The VM is disposable. A bad config on a VM costs nothing to fix. A bad config on a remote
device could mean a support call or a site visit. The VM absorbs the risk so your real fleet
doesn't have to.

## The VM as your permanent canary device
Keep one VM agent enrolled at all times. It's the first to receive every change, proving it's
safe before it touches real devices. Take a clean VM snapshot after every successful config
push — that's your known-good baseline to roll back to.
