# Operational Notes (durable reference)

Durable, non-secret operational reference migrated from old `~/work` session notes.
Secrets (test-VM creds, host/LAN IPs, SMTP user) live **only** in the gitignored
`PRIVATE-credentials.md` and are never committed.

**See also:** `CLAUDE.md` (operating rules + the #1 f-string bug), `ARCHITECTURE.md`,
and `docs/architecture/` (ADR 0001 DB/module architecture, ADR 0002 VPN-aware DNS,
ADR 0003 resilience).

---

## Install-script bug history (VM install testing, Jun 22–23 2026)

Bugs found and fixed while testing `install.sh` on a fresh VM — keep as regression checklist:

1. **Hardcoded home paths** in 8 Python files → fixed with
   `os.path.dirname(os.path.abspath(__file__))` (no `/home/<user>` literals).
2. **`alerts` table never created on fresh install** → fixed by calling `database.init_db()`
   at startup.
3. **Port 80 unreachable** — `iptables-persistent` conflicted with `ufw` on Ubuntu 26.04;
   replaced with a `nemesis-port-redirect.service` systemd unit.
4. **Python import scanner tried to pip-install local Nemesis modules** (database, firewall,
   etc.) → fixed with an exclusion list.
5. **Pi-hole `--unattended` ncurses error over SSH** → fixed with `TERM=xterm` auto-detection.
6. **`PYTHONPATH` not set in `dashboard.service`** → fixed by adding an
   `Environment=PYTHONPATH` line.

---

## #1 recurring bug — JS syntax errors in Python f-strings

The single most common defect in this project (seen 4+ times). The rule lives in
`CLAUDE.md`; this is the operational detail.

**Root cause:** Python f-strings embedding values into JavaScript string literals without
escaping. Triggers: `\'` inside a triple-quoted f-string renders as a bare `'` in the HTML;
values containing newlines embedded in JS strings; nested quotes in `onclick="func('value')"`
where the value contains quotes.

**Symptoms:**
- Browser console: `Uncaught SyntaxError: unexpected token: string literal` or
  `string literal contains an unescaped line break`.
- All other JS on the page becomes `undefined` (ReferenceError); everything breaks from that
  line downward — clicks do nothing, modals don't open.

**Fix patterns (in order of preference):**
1. `data-` attributes: `data-key="{value}"` + `onclick="func(this.dataset.key)"` — no quote nesting.
2. `json.dumps()`: `onclick="func({{ {json.dumps(value)} }})"`.
3. Switch JS string delimiters to single quotes inside the f-string.
4. `.replace()` to escape problem characters before embedding.

**When investigating:** look ONLY at code added in the last commit — the bug is always in
recently added code, not the whole file. The `/settings` page is large and f-string-heavy —
extra vigilance there.

### Post-`dashboard.py`-change verification checklist
1. Restart dashboard: `sudo systemctl restart dashboard`.
2. Open the browser console (F12) **before** loading the page.
3. Hard refresh (Ctrl+Shift+R).
4. Check the console for ANY red errors before testing features.
5. If a SyntaxError appears — fix it first, don't test anything else.

**Uptime display note:** "Loading uptime…" on the first load after a restart is EXPECTED
(the JS fetch runs on load and may briefly show stale text). A hard refresh forces an
immediate fetch. Only a bug if it never resolves after a full reload.

---

## `nemesis` group permissions pattern

`/etc/nemesis.env` holds secrets (API keys, SMTP config) and is locked down. The install
must set this up (don't rely on manual steps):
- `groupadd nemesis` (created during install).
- `/etc/nemesis.env`: `chown root:nemesis`, `chmod 640`.
- Add the installing user to the group: `usermod -aG nemesis $SUDO_USER`.
- Without the group membership the dashboard gets `Permission denied` reading
  `/etc/nemesis.env`.

---

## Services running as root (known issue — fix post-v1)

`watchdog.py`, `hw_monitor.py`, `alert_watcher.py` run as `User=root` in their systemd unit
files. `dashboard.py` correctly runs as the install user (`User=<user>` in
`dashboard.service`). Tracked in `ROADMAP.md` as a security item.
**Fix approach:** `adm` group for log access, specific sudo rules for service restarts,
and group-membership-based sensor access — rather than blanket root.

---

## Email / SMTP configuration lesson (non-secret)

SMTP config: `/etc/nemesis.env` (running system); local reference at
`~/work/nemesis-private/local-config.md` (outside repo, never committed).
- `/etc/nemesis.env` is the **single source of truth** for SMTP config.
- A stale `/etc/watchdog.env` with old Gmail credentials was removed — don't reintroduce
  per-service env files.
- The diagnostics submit endpoint once hardcoded `smtp.gmail.com` separately from
  `email_utils.py` — all mail must route through `email_utils.py`, not ad-hoc SMTP.

---

## Troubleshooting: dashboard won't load / hangs (2026-07-26)

Symptom: the dashboard page hangs or won't load at all. Real diagnostic chain, in order —
don't skip to a restart without checking the log first, since the fix differs depending on
what's actually wrong.

**1. Check the service status and log first.**
```
sudo systemctl status dashboard
```
Look for a repeated `OSError: [Errno 24] Too many open files` in the log output. That
specific error points at a **known open bug**: the `anomaly_detection` module leaks a file
descriptor on `/var/log/suricata/eve.json` each detection cycle until the process runs out
of file handles and everything (including the dashboard's own requests) starts failing with
the same error. See PUNCHLIST for current status — **not yet fixed as of 2026-07-26.**

**2. Restart the service.**
```
sudo systemctl restart dashboard
```
This clears the immediate symptom (fresh process, fresh fd table) but is **not a fix** —
if the underlying leak is still open, the fd count will climb back up over time and the
same hang will recur. Restarting only buys time until the real fix lands.

**3. If the restart itself fails with "Start request repeated too quickly."**
That's **systemd's own rate limiter**, not a new bug — it kicks in after repeated failed
start attempts in a short window. Clear it before retrying:
```
sudo systemctl reset-failed dashboard.service
sudo systemctl restart dashboard
```

**4. If it still won't come up, check the real error before guessing further.**
```
sudo journalctl -xeu dashboard.service
```
Don't assume it's the same fd-leak bug — read the actual error. A different failure here
means a different fix.

**Two gotchas that will bite you if you're debugging this manually (found 2026-07-26):**

- **(a) Running the script manually with `sudo` for debugging leaves files owned by
  `root`.** If you `sudo python3 dashboard.py` (or similar) to watch output live while
  troubleshooting, any files it creates/touches during that run end up owned by `root`.
  The next time the service starts normally (as its own non-root user), it can hit a
  `PermissionError` on those same files. Fix: `chown` the affected files back to the
  service's actual user before restarting the service normally.
- **(b) Confirm which user the service actually runs as before trusting a "missing
  module" error from a manual run.** Check:
  ```
  grep "^User" /etc/systemd/system/dashboard.service
  ```
  `dashboard.service` runs as the install user (not root — see "Services running as root"
  above, `dashboard.py` is the one service that's already correct). If you run the script
  manually under a **different** user context than the service normally uses (e.g. plain
  `sudo` instead of `sudo -u <that-user>`), you can hit a false "module not found" error
  that has nothing to do with a real missing dependency — it's a different Python
  environment/user context than the one the service actually runs in. Match the user
  before concluding a module is really missing.

**Future robustness note (not urgent, not built):** the dashboard should ideally fail more
gracefully / self-report when it hits resource exhaustion (too-many-open-files) instead of
silently hanging — flagged as a future item on the PUNCHLIST, not something to fix today.

---

## Backup system notes

- Archives: `alerts.db`, `hw_map.json`, `/etc/nemesis.env` (+ historically `tickets.db` and
  the anomaly DBs — being superseded by the single-shared-DB model, see ADR 0001).
- The archive contains API keys → `chmod 600` on the `.tar.gz`.
- Scheduled via crontab (not a systemd timer): daily 3am, weekly Sunday 3am, monthly 1st 3am.
- Restore on reinstall: `install.sh` checks `~/nemesis-backup/` for a `.tar.gz` and offers to
  restore the most recent; `/etc/nemesis.env` is always restored (highest-value item — all
  API keys preserved).
- **Use a SQLite-safe copy** (backup API / `.backup`), never a raw `cp`/`tar` of a live WAL
  DB. (ADR 0001 Stage 5 reworks backup onto the single shared DB.)

---

## Module quick-reference

**AI Engine** (`modules/ai_engine/`) — all Anthropic API calls route through
`ai_engine.analyze()`; never import `anthropic` directly elsewhere. Teaching mode shows
copyable commands the user runs themselves; Automated mode has tiered approval gates
(LOW=click OK, MEDIUM=confirm, HIGH=type YES). Header status indicator: green=active,
grey=disabled/no key, red=invalid key.

**Community Queue** (`modules/community_queue/`) — items added when anomaly detection
confirms score ≥ 60 (HIGH/CRITICAL) and not dismissed. "Analyse Queue" needs the ai_engine
module enabled (batch AI review → High/Uncertain/Low). Submit currently shows a "coming soon"
modal; full incident detail is stored locally for retroactive submission when the backend
ships.

**Windows Agent** (`windows_agent/`) — reads LibreHardwareMonitor's HTTP API at
`localhost:8085` (must run as Administrator with the web server enabled). One-time discovery
saves `windows_hw_map.json` with locked sensor IDs; ongoing polling every 5 min POSTs
pre-labeled JSON to `<host>:5001`. `hw_monitor.py` detects `source="windows_agent"` in
`hw_map.json` and switches to listener mode on port 5001. The agent self-reports its own
health (psutil) in every payload.

---

## VPN-aware DNS (ship blocker → product feature)

Full design is in **ADR 0002** (`docs/architecture/0002-vpn-aware-dns-routing.md`). Durable
operational nugget: VPN killswitches (PIA/Mullvad/Proton/Nord) block Pi-hole's **upstream**
DNS forwarding, breaking resolution of uncached domains. Fix is preventive — route Pi-hole's
upstream through the tunnel when a VPN is active (reusing existing VPN detection), modifying
only Nemesis's own Pi-hole config, never the user's VPN.
- **Install/uninstall scripts must guarantee outbound DNS (UDP+TCP 53) stays allowed.**

---

## Not yet captured (expected by the migration brief but absent from the incoming notes)

The incoming scratch docs did **not** contain these — add them here when sourced (do not
fabricate):
- VirtualBox / VM gotchas (graphics controller, networking adapter settings).
- macOS dependency list.
- Windows/Mac dependency **download URLs** (only the Windows *agent* architecture was
  documented, not a dependency-with-URLs list).
