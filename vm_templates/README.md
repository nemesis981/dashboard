# VM Templates

This directory holds VM configuration templates for the Nemesis Test Lab. Each template
defines how to create a specific OS/version VM for testing agent deployments and config
changes.

## Template format
Each template is a subdirectory containing:
- `template.json` — VM specs (RAM, CPU, disk, network mode)
- `autoinstall.yaml` — cloud-init/preseed for unattended install
- `README.md` — what this template is for, requirements

## Contributing a template
Follow the same pattern as `CUSTOM_VPN_PROBE.md`: contract + working example + registration
point. Submit a PR — templates are reviewed before merging.

## Why this exists
Non-expert users under stress Google "fix repo" and land on SEO-poisoned results, introducing
malicious repos to their security appliance. The VM Test Lab keeps users inside a verified
trusted flow — they never evaluate sources themselves.

## Current templates
None yet — coming with the VM Lab feature (see `docs/roadmap/nemesis-test-lab.md`).
