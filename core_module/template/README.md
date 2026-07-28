# Adding a core process

Copy this directory to `core_module/<your_process>/`, then work through the list.
Nothing here is optional — each item is enforced or checked somewhere.

## 1. `manifest.json`

- `name` — snake_case, and it must equal the directory name. This one string is
  the DM namespace key, the Settings toggle id, the name the AI uses when it
  tells a user to stop this process, and the owner field on future error codes.
  **One name, four consumers.**
- `stopping_this_means` — required prose. The Settings toggle shows it as the
  confirmation text and the AI quotes it. If you cannot state what breaks, the
  process probably should not be toggleable.
- `disableable` — set `false` for anything that gates privilege or is required
  for the UI's own controls to work (e.g. a privileged helper). A disable flow
  that can turn off the thing enforcing privilege is an attack, not a feature.
- `namespace.tables` — every table this process WRITES. Reads need no entry
  (ADR 0001 is write-own / read-any).

## 2. Namespace registration

Add an entry to `NAMESPACES` in `alert_manager/data_manager.py`:

```python
"your_process": {"tables": ("your_table", "your_other_table")},
```

Use explicit `tables` rather than a prefix unless the prefix is genuinely yours
alone. Two processes sharing a prefix is the exact case explicit lists exist for.

**Start in WARN mode.** Call `dm.set_namespace_mode("your_process", dm.MODE_WARN)`
and run against real traffic first. Warn mode performs the full check and logs
`WOULD DENY` for anything missing, without breaking the process. Grep the journal
for `WOULD DENY`; when it is silent across a representative period, switch to
`MODE_ENFORCE`. Static analysis of your SQL is a starting list, not a finished
one — f-strings, constants defined elsewhere, and conditional SQL all hide from it.

## 3. `process.py`

Replace `cycle()`. Keep it short and idempotent. Do not open `sqlite3` directly —
use `db()`, or the access control and the operation log are both bypassed with no
outward sign.

## 4. The unit

Rename `NAME.service.in` to `<unit_name>.service.in`. Placeholders are substituted
at install time. Give the process **its own OS user** — never reuse another
service's identity.

## 5. Verify, do not assume

- `systemctl show` reports CONFIGURED values. Effective privilege must be read
  from `/proc/<pid>/status` — several hardening directives silently imply others,
  and the two routinely disagree. `nemesis_privsep.attest()` already does this;
  set `NEMESIS_EXPECT_USER` in the unit to arm it.
- If the process writes to `/var/lib/nemesis`, the directory needs mode **0770**,
  not 0750 — SQLite's WAL sidecars require directory write, and 0750 reproduces a
  real outage from 2026-07-18.
- Deploying code does **not** deploy the unit. Reverting a process's directory
  leaves `/etc/systemd/system/` untouched; redeploy the unit and `daemon-reload`,
  or verify the installed one still matches. This gap caused the 2026-07-27
  production incident.
