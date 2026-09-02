# CUSTOM — Tailscale removal on Windows agent uninstall

Vendor integration guide (per the CLAUDE.md vendor-integration rule). Covers how
`NemesisUninstall.exe` decides whether to remove Tailscale alongside the Nemesis Windows
agent, and why that decision is provenance-gated rather than a simple yes/no toggle. Owed
alongside the Tailscale-removal code per `docs/roadmap/clean-uninstall-build-spec.md`'s own
success criteria; written 2026-09-02, after `cc332c7` flagged it as still outstanding.

- **Implemented in:** `nemesis_agent/uninstaller_gui.py` (`_tailscale_component`,
  `_tailscale_removable`, `_leave_tailnet`, `_remove_tailscale`).
- **Related:** [`docs/roadmap/clean-uninstall-build-spec.md`](roadmap/clean-uninstall-build-spec.md)
  (the design of record — read that for the full manifest schema and consent-UX flow this
  guide summarizes); [`CUSTOM_TAILSCALE_OAUTH.md`](CUSTOM_TAILSCALE_OAUTH.md) (the *install*-side
  Tailscale integration — auth-key minting; this guide is the *uninstall*-side counterpart);
  ADR 0011 (enrollment security — the de-enroll call this uninstaller also makes).
- **Rule 8 — read first.** No real device IDs, tailnet IPs, or hostnames anywhere in this
  guide or in the manifest it describes. The manifest itself must never store secrets (no
  auth key, no enrollment token) — only a `device_id` for the de-enroll call.

---

## The problem this solves

Nemesis's Windows installer can install Tailscale for the user (self-onboarding) or can run
on a machine that already had Tailscale installed for some other reason. An uninstaller that
always removes Tailscale would delete software the user brought with them; one that never
removes it leaves orphaned software behind on every self-onboarded install. **Both are
wrong, and the difference isn't visible at uninstall time unless it was recorded at install
time.** This guide documents the provenance mechanism that makes the correct choice
knowable, and the consent gate that makes it, in the end, the user's call rather than the
installer's guess.

## What it does (interface contract)

**Provenance is recorded once, at install time, into a JSON manifest** — the single source
of truth the uninstaller reads. For Tailscale specifically:

```json
"tailscale": {
  "installed_by_nemesis": true,
  "removal": "offer",
  "pre_existing": false,
  "install_path": "<Program Files>\\Tailscale or null"
}
```

- **`installed_by_nemesis`** — was Tailscale absent before the Nemesis installer ran, and did
  the Nemesis installer put it there? Determined by probing (`where tailscale` /
  `%ProgramFiles%\Tailscale\tailscale.exe` / the Tailscale ARP key) **before** installing,
  not inferred afterward.
- **`removal`** — one of three values, matching the general manifest `removal` semantics
  used for every component this uninstaller manages: `"auto"` (silently removed, it's ours),
  `"offer"` (offered via the consent checklist, since it's a system-level install that could
  matter elsewhere), or `"never"` (never touched). **Tailscale is always `"offer"` when
  Nemesis installed it — never `"auto"`.** Even software Nemesis put there is significant
  enough, and useful enough independent of Nemesis, that removing it silently would be the
  wrong default.
- **`pre_existing`** — set `true` when the probe found Tailscale already present before
  installation. This is the hard override: **`pre_existing:true` forces `removal:"never"`
  no matter what else is true**, and the removal function enforces this at read time, not
  just at write time (see below).

**The uninstaller's actual gate** — `_tailscale_removable()` — is a single, narrow
predicate:

```python
def _tailscale_removable(manifest):
    ts = _tailscale_component(manifest)
    return bool(ts.get("installed_by_nemesis")) and ts.get("removal") == "offer" \
        and not ts.get("pre_existing")
```

All three conditions must hold. **A missing manifest — an older install, or a corrupted
one — fails this check by construction** (an empty dict's `.get()` calls all return falsy),
which is the deliberate fail-closed default: an uninstaller that can't prove it installed
Tailscale never touches Tailscale. This is the skip-if-absent pattern applied to a removal
decision rather than a feature probe: absence of proof is treated as "don't touch it," never
as permission.

## The removal sequence, when it does run

Only reached when `_tailscale_removable()` is true **and** the user has explicitly consented
via the uninstaller's checklist UI — the manifest gate and the consent gate are both
required, neither substitutes for the other.

1. **De-enroll first, while the tailnet connection is still up** — the signed de-enroll call
   needs to reach the server over the tailnet, so this must happen before Tailscale is
   touched, not after.
2. **Leave the tailnet** — `_leave_tailnet()` runs `tailscale logout` then `tailscale down`,
   best-effort (failures are swallowed; a Tailscale that's already down or already logged out
   is not an error condition here).
3. **Remove Tailscale itself** — `_remove_tailscale()` runs
   `winget uninstall --id Tailscale.Tailscale --silent --accept-source-agreements`, matching
   the removal mechanism Tailscale's own MSI installer registers with Windows (parity with
   what a user would get from Settings → Apps).

Each step is independently best-effort (wrapped, exceptions swallowed) — a failure at any
step does not block the rest of the Nemesis uninstall from completing. The design accepts
"Tailscale removal didn't fully succeed" as a lesser failure than "the whole uninstall got
stuck because a third-party product's removal hung."

## What this does NOT do

- **Never removes a pre-existing Tailscale install**, regardless of consent-checklist state —
  the `pre_existing` flag overrides anything the user might click.
- **Never infers provenance after the fact.** If the probe wasn't run at install time (an
  older Nemesis version, or a manifest that predates this mechanism), there is no attempt to
  guess retroactively — the missing-manifest fallback in `_tailscale_removable()` handles
  that case by refusing, not by re-probing at uninstall time (the system state at uninstall
  time reflects months of use, not the state the original install-time probe actually saw).
- **Does not remove Tailscale from any other device on the tailnet** — this is local, agent-
  side removal only. The tailnet node deregistration (`tailscale logout`) is a side effect of
  leaving the tailnet cleanly, not a separate device-management action.

## Where this fits in the uninstall flow

The consent checklist that gates this (per `clean-uninstall-build-spec.md`) presents the
Tailscale toggle with copy that states *why* the default is what it is — *"You had Tailscale
before installing Nemesis — leave this unchecked unless you're sure"* for the pre-existing
case, versus *"Nemesis installed Tailscale for you"* when `installed_by_nemesis` is true.
The manifest-driven default is what the checkbox starts at; the user's own click is still
what actually authorizes removal.
