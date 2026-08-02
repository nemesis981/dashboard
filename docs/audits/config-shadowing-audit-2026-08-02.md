# Config-shadowing audit — 2026-08-02

> Read-only audit (Rule 1). Prompted by the 2026-08-02 YARA-exclusions incident: a live
> `/etc/nemesis-yara-exclusions.conf` starter file, seeded as a verbatim copy of the in-code
> defaults, silently shadowed a corrected default for six weeks because the loader correctly
> prefers the file whenever it exists. This audit enumerates every `/etc/nemesis-*` config on
> this box plus everything `install.sh` writes, checking each against the same failure shape:
> **does stored content duplicate an in-code default, and does the loader prefer the stored
> value over that default?** Both true means a future change to the shipped default can never
> reach an existing install, silently. Findings only — fixes are a separate pass except where
> noted as already landed.

## Scope and method

- `ls /etc/nemesis*` — every live config file on this box.
- `grep` of `install.sh` for every file-write operation (`cat >`, heredocs, `cp`) targeting
  `/etc/` or a config path, then traced each write's consumer to see whether it's read back
  preferentially over a code-side default.
- For the two DB-backed settings tables already suspected of the same shape, live rows were
  queried directly against `alerts.db` and diffed against the code's own `DEFAULT_SETTINGS`
  dict — not assumed from reading the seeding code alone.

## Findings

### 1. `malware_settings` — 14/14 shadowing, zero real overrides. **Already fixed, verified live.**

`_init_db()` (`modules/malware_detection/module.py`) used `INSERT OR IGNORE` to seed every
`DEFAULT_SETTINGS` entry, and `_get_setting()` prefers the row over the code default whenever
one exists. Queried live `alerts.db` directly: all 14 rows were byte-identical to their code
defaults — every shipped default was frozen the moment the table was first created, with zero
genuine operator customization.

**Status: fixed same day, commit `cf6d439` ("stop malware_settings shadowing its own code
defaults")**, which replaced the seed with a prune: on every `_init_db()` run, delete any row
whose value equals the *current* code default. `dashboard` restarted at 13:38:01 (two minutes
after the fix commit); a fresh query of `malware_settings` immediately after confirms **0
rows** — all 14 were shadows, so pruning cleared the table entirely. `_get_setting()` falls
back to `DEFAULT_SETTINGS` with no row present, so behavior is unchanged today, but any future
change to a shipped default will now actually reach this install instead of being silently
frozen. Accepted tradeoff, stated directly in the fix's own comment: a value deliberately set
to *equal* the current default is now indistinguishable from never having been set, so "pin to
today's value" isn't expressible by choosing the default — nothing currently relies on that.

Note: `malware-canary` (a separate process loading the same module) had not restarted as of
this audit and is still running the pre-fix binary in memory. Not an active concern — it only
re-seeds at its own startup — but it means the fix isn't fully rolled out fleet-wide (i.e.
across every local process) until every consumer of this module restarts.

### 2. `diagnostics_settings` — 9/10 shadowing, 1 genuine override. **Still open.**

`modules/diagnostics/module.py:120-123` has the identical `INSERT OR IGNORE` seed loop,
unchanged as of this audit (`git log` shows no recent touch). Queried live `alerts.db`
directly against the code's `DEFAULT_SETTINGS`: 9 of 10 rows match exactly.
`watcher_enabled` is the one genuine override (code default `0`, live `1`) — the diagnostics
watcher was deliberately turned on for this box.

**Why the mix matters:** unlike `malware_settings` (zero real overrides, safe to prune
wholesale), this table has a live, deliberate customization sitting among the shadows. Any fix
has to distinguish "equals the default by coincidence" from "was deliberately set" — which the
seeding itself already destroyed the ability to tell apart from row content alone. The same
prune-on-init approach used for `malware_settings` would work here too (it only removes rows
that match the *current* default, so `watcher_enabled=1` — which differs from the code default
`0` — would correctly survive), but this has not been applied yet.

### 3. `/etc/nemesis.env` — one shadow on this box, three baked into every fresh install.

Only remaining live `/etc/nemesis-*` file (`/etc/nemesis-yara-exclusions.conf` no longer
exists — confirmed removed as part of resolving the original incident). Traced three values
end-to-end from `install.sh`'s hardcoded fallback → the config-first template's pre-filled
value → `write_env_file()`'s unconditional write → the runtime code's own `os.environ.get(...,
fallback)` default:

| Key | install.sh fallback | Runtime code fallback | Shadow? |
|---|---|---|---|
| `SMTP_PORT` | `587` (`install.sh:46`, `read_conf … "587"`) | `587` (`alert_manager/email_utils.py:24`) | **Yes** — confirmed live: this box's value is `587`, matching the default exactly |
| `ANTHROPIC_INPUT_PRICE_PER_MTOK` | `3.00` (`install.sh:51`) | `3.00` (`dashboard.py:3818`) | **Yes**, and structurally on every install — the pricing pair is what `install.sh`'s own generated file tells the operator to hand-maintain ("Update if Anthropic changes pricing"), which concedes the value must be manually tracked forever rather than following the shipped default |
| `ANTHROPIC_OUTPUT_PRICE_PER_MTOK` | `15.00` (`install.sh:52`) | `15.00` (`dashboard.py:3819`) | **Yes**, same as above |
| `SMTP_HOST` | `smtp.gmail.com` (illustrative placeholder in the template) | none — always operator-set | **No** — this box's value differs from the template default, confirming it as the genuine, expected-to-differ override it's designed to be |

`write_env_file()` (`install.sh:443-484`) writes every key unconditionally, regardless of
whether the operator touched it — there is no per-key "was this actually customized" check.
Because the config-first template (`install.sh:338-390`) pre-fills `SMTP_PORT`,
`ANTHROPIC_INPUT_PRICE_PER_MTOK`, and `ANTHROPIC_OUTPUT_PRICE_PER_MTOK` with the exact same
values as the fallback defaults, an operator who leaves those three lines untouched — the
overwhelmingly likely case, since they don't look like they need input — gets them written
into `/etc/nemesis.env` as fixed values on **every fresh install**, not just this box. Any
future change to the shipped Anthropic pricing constants (which the codebase already expects
to need updating — see `PUNCHLIST.md`'s live-pricing item) would need a second, separate
change to every already-installed `/etc/nemesis.env` to actually take effect; today it does
not.

**Status: not yet fixed.**

### Not in scope — checked and excluded

- **`/etc/sudoers.d/nemesis`** (`install.sh:1622-1628`) — a fixed OS permission grant
  (`NOPASSWD` for a hardcoded command list). No code-side "default" exists for it to shadow;
  sudoers isn't read back by application code at all. Doesn't fit the failure shape.
- **`/etc/nginx/sites-available/nemesis`** (`install.sh:1333+`) — a fully static template
  (single-quoted heredoc, zero variable interpolation), identical on every install. There is no
  alternate code-side default it could be shadowing; this file *is* the only source of truth
  for nginx's routing rules.

## The correct pattern already exists in this repo

`nemesis_agent/config.py:53-56` does `data = dict(DEFAULTS)` then overrides only the keys the
config file actually contains — an absent key transparently follows the shipped default,
because nothing ever wrote a copy of it in the first place. This is the model for both open
items below, and for `install.sh` generally.

## Suggested remediation, in order of cost

- [ ] **`diagnostics_settings`** — apply the same prune-on-init fix already shipped for
  `malware_settings` (`cf6d439` is the reference implementation). The settings UI already reads
  through `_get_setting()`, so it keeps working with zero rows present; verified for
  `malware_settings` that no other consumer reads either table directly.
- [ ] **`install.sh`'s `write_env_file()`** — write only the keys the operator actually
  supplied (non-empty in the parsed conf, or explicitly changed from the template's
  placeholder), omitting anything left at the shipped default so the code-side default stays
  live for that key on that install. `SMTP_HOST`/`WATCHDOG_EMAIL`/etc. (fields with no
  sensible universal default) are unaffected either way, since they're never blank-equal to a
  shipped constant.
- [ ] Decide, per already-existing `diagnostics_settings` row, whether it's deliberate
  (`watcher_enabled`) or accidental (the other nine) before applying the prune — the prune
  itself only removes rows equal to the *current* default, so this is close to self-resolving,
  but worth a conscious pass rather than assuming.

## Cross-references

- PUNCHLIST.md — "Never ship a starter config that duplicates the in-code defaults" and
  "`_load_exclusions()` should log when it is SHADOWING" (the originating incident and its two
  companion process fixes).
- `docs/roadmap/` — the live-Anthropic-pricing punchlist item this audit's finding #3
  reinforces (the pricing pair is exactly the value most likely to need a future update that
  today's `install.sh` would prevent from reaching existing installs).
