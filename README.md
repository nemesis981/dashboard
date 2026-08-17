> **DRAFT — this README did not exist before 2026-08-17 and is a starting
> point, not a finished project page.** Written alongside a first-draft
> `LICENSE` (see below) as part of closing a gap where the repo had neither.
> Review and expand before treating either as final — see
> `docs/architecture/0022-source-available-license.md` and `PUNCHLIST.md`.

# Nemesis Firewall

A self-hosted network security dashboard — built-in IT-department-style
protection for people who don't have an IT department. Runs on a small
appliance on your own network: firewall enforcement, intrusion detection,
malware scanning, and device monitoring, with a web dashboard for visibility
and control.

## Status

Active development. Not yet a general-availability release — see
`PUNCHLIST.md` and `docs/roadmap/` for current state and open items.

## Installing

```
sudo bash install.sh
```

See `install.sh` for supported platforms (Ubuntu 22.04/24.04/26.04 LTS).
Windows agent installation is documented separately for enrolled devices —
see the dashboard's own enrollment flow once the server is running.

## License

Nemesis Firewall is **source-available**, not open-source under an OSI
license. Personal, non-commercial use is free. Commercial use requires a
paid license. Full terms: [`LICENSE`](LICENSE) (currently in draft — see
the notice at the top of that file). Rationale for this licensing model:
[`docs/architecture/0022-source-available-license.md`](docs/architecture/0022-source-available-license.md).

## Contributing

Not yet accepting external contributions in a formal sense — the
contribution terms in `LICENSE` §7 are a placeholder pending a real
Contributor License Agreement. If you're interested, open an issue first.
