# Contributing to Nemesis Firewall

Thank you for contributing. Nemesis is a security product used by non-expert users who depend
on it to protect their networks. This means contributor code is held to a high standard — not
to be exclusionary, but because the consequences of bugs here are real.

## The module contract (mandatory, enforced)

Every contributed module MUST follow this contract. The module loader enforces these rules —
a module that violates them will not load.

### 1. Declare your schema
Your `manifest.json` must declare every table your module uses. The Data Manager validates
this before your module loads. No declaration = no load. See
`docs/architecture/0006-data-manager.md`.

### 2. Use the Data Manager for all DB operations
Your module NEVER calls `sqlite3.connect()` directly or uses bare `get_db()` outside the Data
Manager contract. All reads and writes go through the Data Manager. This gives you atomicity,
attribution, and access control for free — and prevents the whole class of race conditions and
cross-module data-access bugs. See `docs/architecture/0006-data-manager.md`.

### 3. Use your own table prefix
Your tables must use your module's declared prefix (e.g. `mymodule_*`). You may not read or
write another module's tables. The Data Manager enforces this at runtime.

### 4. Include a CUSTOM_*.md guide for any vendor-specific integration
If your module integrates with a specific vendor/product (a VPN client, a hardware sensor, a
notification service), you must ship a `CUSTOM_*.md` guide alongside it. See `CUSTOM_VPN_PROBE.md`
for the pattern: contract + skip-if-absent + minimal example + registration. A vendor
integration without a custom guide is incomplete.

### 5. Respect the Rule-8 split
Raw IPs, hostnames, and user-identifying data go to flat files only. The DB stores verdicts,
booleans, and sanitized summaries. Never commit real paths, IPs, or credentials to the repo.

### 6. Follow the module lifecycle contract
Your module implements `start`/`stop`/`status`/`get_dashboard_card`/`get_routes`. It gates on
its enabled flag each loop (self-gating, no `systemctl` from toggle). It handles SIGTERM/SIGINT
gracefully. See `CLAUDE.md` for the full lifecycle contract.

## What the Data Manager gives you for free
When you use the Data Manager correctly:
- Your writes are atomic (no race conditions possible)
- Your writes are attributed (actor recorded automatically)
- Your table access is scoped (can't accidentally touch other modules)
- Your failures are handled (bounded retry → graceful unload)
- Your schema is validated (catches mistakes before they reach users)

## Submitting a module
- Follow the contract above
- Include tests (or a VM audit procedure) that verify your module installs, runs, and
  uninstalls cleanly on a fresh box
- Include a `CUSTOM_*.md` if you have vendor-specific integrations
- Run the leak-scan before submitting (no real IPs/paths/credentials)
- Submit a PR — modules are reviewed before merging

## Getting help
Open an issue or reach out at support@nemesis-sw.com. The community is here to help you build
something good.
