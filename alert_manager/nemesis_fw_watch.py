#!/usr/bin/env python3
"""ADR 0019 — out-of-band netfilter change detection.

WHY THIS IS A PREREQUISITE FOR INCREMENT 4, not a nicety. Increment 4 gives the
`nemesis_enforce` table real DROP authority. A table with authority that any
direct `nft` or `iptables` command can silently edit is not a hardening gap —
it is a way to defeat enforcement entirely while the audit trail shows nothing
happened. Demonstrated from the inside on 2026-08-01: issuing a test block
required going around the nemesis_fwd chokepoint (it authorises peers by uid),
and nothing anywhere recorded that a rule had changed.

COVERAGE IS TOTAL, AND THAT WAS VERIFIED RATHER THAN ASSUMED. `iptables -V`
reports `nf_tables` and /usr/sbin/iptables points at iptables-nft, so ufw's
rules live in the nftables compat tables (`ip filter`, `ip6 filter`, `ip nat`
...) — they show up in `nft list tables`. One netlink subscription therefore
sees ufw commands, direct iptables commands and direct nft commands alike.
Under legacy iptables this would have been a partial view and the design would
need rethinking; check again if that backend ever changes.

TWO RESPONSES, ONE EVENT STREAM:
  ufw's chains changed        -> legitimate; re-render the derived table (drift)
  nemesis_enforce changed     -> tamper; alert, do NOT silently repair
  nemesis_enforce deleted     -> enforcement loss; alert at CRITICAL

NO SILENT SELF-HEAL. Auto-restore is opt-in (NEMESIS_FW_WATCH_AUTORESTORE=1)
and off by default: a watcher that quietly repairs tampering destroys the
evidence of the event it exists to detect.

NOT A PURELY EVENT-DRIVEN DESIGN. Netlink multicast DROPS messages when the
receive buffer fills (ENOBUFS) — events are lost, not queued. So detection also
rests on periodic state comparison (REVERIFY_SECONDS) and on re-verification at
startup. Dropped events therefore cost detection LATENCY, bounded by the
re-verify interval, rather than causing a silent miss. This is why the reader
thread does nothing but enqueue, and why a worker pool was explicitly rejected:
measured peak load is ~5% of one core and the event rate is hard-capped by ufw's
own write throughput (see the 2026-08-01 scaling analysis).
"""
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TABLE_FAMILY = "inet"
TABLE_NAME = "nemesis_enforce"
LKG_DIR = os.environ.get("NEMESIS_FW_LKG_DIR", "/var/lib/nemesis/fw-lkg")
EXPECTED_HASH = os.path.join(LKG_DIR, "expected.sha256")
EXPECTED_META = os.path.join(LKG_DIR, "expected.meta")
#: MOVED OUT OF LKG_DIR, 2026-08-25, because the layer it exists for did not work.
#: `/var/lib/nemesis/fw-lkg` is root:root 0700 (measured, not assumed), so the watchdog
#: -- which runs as nemesis-watchdog -- could not stat a heartbeat written there. The
#: unit file has claimed since 2026-08-01 that "the existing watchdog service alerts if
#: it goes stale"; nothing read this file, and nothing COULD have.
#:
#: /run is the right home for it on the merits, not merely a permissions workaround:
#: a heartbeat is ephemeral runtime state, and /run is tmpfs cleared at boot, so a
#: timestamp written before a reboot cannot be mistaken afterwards for a live one. The
#: directory comes from the unit's own RuntimeDirectory=, so it is not shared with any
#: other service's lifecycle -- and systemd removes it when this service STOPS, which
#: turns "stopped and told not to restart" into a MISSING file rather than a slowly
#: ageing one. That is the clearest possible signal for the exact case this layer is
#: meant to catch.
HEARTBEAT = os.environ.get("NEMESIS_FW_HEARTBEAT",
                           "/run/nemesis-fw-watch/heartbeat")
DEGRADED_LOG = os.environ.get("NEMESIS_DEGRADED_LOG", "/var/lib/nemesis/degraded.jsonl")
RENDER = "/opt/nemesis/scripts/nemesis-fw-render"

#: Coalesce a burst into one action. ONE ufw command rewrites ~69 rules and so
#: emits a burst of netlink events; without this the watcher would re-render
#: once per rule. Debouncing is what makes the work rate-INDEPENDENT, and is the
#: reason elastic scaling was unnecessary.
DEBOUNCE_SECONDS = float(os.environ.get("NEMESIS_FW_WATCH_DEBOUNCE", "2"))
#: Periodic state comparison — the backstop for dropped netlink events.
REVERIFY_SECONDS = float(os.environ.get("NEMESIS_FW_WATCH_REVERIFY", "60"))
AUTORESTORE = os.environ.get("NEMESIS_FW_WATCH_AUTORESTORE", "0") == "1"

#: ── ADR 0026 step 4: the tailnet plain-HTTP guard ───────────────────────────
#:
#: SHIPS INERT, AND THAT IS NOT THE SAME AS AUTORESTORE BEING OFF BY DEFAULT.
#: AUTORESTORE governs whether a guard that ALREADY EXISTS gets repaired; leaving that
#: off is what this file's header argues for, because a silent repair destroys the
#: evidence of the tamper it exists to detect. This flag governs something else
#: entirely: whether the raw-table DROP should exist AT ALL on this box. Enabling it on
#: a machine where the operator has not yet made that decision would close plain HTTP
#: over the tailnet unilaterally -- no state snapshot, no operator go-ahead, and any
#: `http://<tailnet-ip>/...` link in use breaks -- which is a change to live network
#: behaviour arriving as a side effect of a code deploy. So the code lands dormant and
#: step 4's rollout turns it on, once the DROP has been deliberately applied.
#:
#: THERE IS DELIBERATELY NO SECOND "DETECT BUT DO NOT REPAIR" FLAG. Once enabled, the
#: repair and the alert are both unconditional. A detect-only mode would be the failure
#: this whole mechanism exists to prevent: something that reports healthy while the
#: guard is defeated. The alert is what preserves the evidence, not the absence of a fix.
GUARD_ENABLED = os.environ.get("NEMESIS_FW_GUARD", "0") == "1"
GUARD_IFACE = os.environ.get("NEMESIS_FW_GUARD_IFACE", "tailscale0")
GUARD_PORT = int(os.environ.get("NEMESIS_FW_GUARD_PORT", "80"))
GUARD_PROTO = "tcp"
IPTABLES_BIN = os.environ.get("NEMESIS_IPTABLES", "/usr/sbin/iptables")
IP6TABLES_BIN = os.environ.get("NEMESIS_IP6TABLES", "/usr/sbin/ip6tables")

#: A guard that is knocked out and repaired repeatedly is a DIFFERENT condition from one
#: that was knocked out once: something on this box is actively fighting the rule (PIA
#: rewriting its chains on every VPN state change is the known candidate). Repairing it
#: quietly on a loop would look healthy in every individual check while the box is in
#: fact contested, so a run of repairs escalates instead of being absorbed.
GUARD_FLAP_WINDOW = float(os.environ.get("NEMESIS_FW_GUARD_FLAP_WINDOW", "3600"))
GUARD_FLAP_THRESHOLD = int(os.environ.get("NEMESIS_FW_GUARD_FLAP_THRESHOLD", "3"))

ERR_TAMPERED = "NEM-FWW-0001"
ERR_DELETED = "NEM-FWW-0002"
ERR_NO_BASELINE = "NEM-FWW-0003"
ERR_RESTARTED = "NEM-FWW-0004"
ERR_GUARD_DEFEATED = "NEM-FWW-0005"
ERR_GUARD_UNDETERMINED = "NEM-FWW-0006"
ERR_GUARD_HEAL_FAILED = "NEM-FWW-0007"
ERR_GUARD_FLAPPING = "NEM-FWW-0008"

#: ufw's rules live in these nftables compat tables. A change here is expected
#: and means the derived table needs regenerating.
UFW_TABLES = {("ip", "filter"), ("ip6", "filter"), ("ip", "nat"), ("ip6", "nat"),
              ("ip", "mangle"), ("ip6", "mangle"), ("ip", "raw"), ("ip6", "raw")}

logging.basicConfig(format="%(levelname)s %(name)s: %(message)s", level=logging.INFO)
log = logging.getLogger("nemesis.fwwatch")

_COUNTER_RE = re.compile(rb"counter packets \d+ bytes \d+")


def normalise(raw: bytes) -> bytes:
    """Strip volatile counters before hashing.

    Counters change with every packet. Hashing the raw dump would produce a
    mismatch continuously and the watcher would alert forever — the failure mode
    that separates a working detector from an unusable one. What matters for
    tamper detection is the rule STRUCTURE: matches, verdicts and comments.
    """
    return _COUNTER_RE.sub(b"counter", raw)


def table_dump() -> bytes | None:
    """Current ruleset for our table, or None if the table does not exist."""
    try:
        r = subprocess.run(["nft", "list", "table", TABLE_FAMILY, TABLE_NAME],
                           capture_output=True, timeout=10)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        log.exception("fwwatch: could not read the table")
        return None


def table_hash() -> str | None:
    raw = table_dump()
    if raw is None:
        return None
    return hashlib.sha256(normalise(raw)).hexdigest()


def read_expected() -> str | None:
    try:
        with open(EXPECTED_HASH) as f:
            return (f.read().strip().split() or [None])[0]
    except FileNotFoundError:
        return None
    except Exception:
        log.exception("fwwatch: could not read the expected hash")
        return None


def write_expected(h: str, why: str) -> None:
    """Record a new baseline. Called after WE change the table legitimately."""
    try:
        os.makedirs(LKG_DIR, exist_ok=True)
        with open(EXPECTED_HASH, "w") as f:
            f.write(h + "\n")
        with open(EXPECTED_META, "w") as f:
            json.dump({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "recorded_by": "nemesis-fw-watch", "reason": why}, f)
    except Exception:
        log.exception("fwwatch: could not record the expected hash")


def _audit_row(action: str, detail: str) -> None:
    """DELIBERATELY A NO-OP. This process must never open the shared database.

    An earlier version wrote directly to `audit_log`. On the VM, 2026-08-01, that
    LOCKED THE DASHBOARD OUT OF ITS OWN DATABASE — measured, not theorised:

        nemesis-dash CANNOT write: attempt to write a readonly database

    Cause: this service runs as root with CAP_NET_ADMIN and nothing else, so it
    has no CAP_DAC_OVERRIDE. Opening alerts.db created the WAL sidecars
    (-wal/-shm) owned by ROOT, which nemesis-dash could then only read. The
    dashboard kept running and silently could not write.

    This is the same hazard HANDOFF §6 already records for core/manage.py. The
    established pattern was also already there and I walked past it: the degraded
    journal exists precisely because it is "deliberately a FILE, not a DB table"
    (nemesis_fwd.signal_degraded). A privileged component has no business holding
    a handle to the database the unprivileged dashboard owns.

    The audit_log requirement is not dropped — it moves. The dashboard ingests
    degraded.jsonl and writes the row itself, as the user that owns the database.
    That keeps the audit trail and keeps this process out of the DB entirely.
    """
    return


def _degraded(code: str, severity: str, message: str, context: dict) -> None:
    """Append to the degraded journal, byte-compatible with nemesis_fwd's shape."""
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "code": code,
           "severity": severity, "message": message, "context": context}
    try:
        fd = os.open(DEGRADED_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, (json.dumps(rec, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    except Exception:
        log.exception("fwwatch: could not append to the degraded log")


def _email_async(subject: str, body: str) -> None:
    """Off-thread so a 30s SMTP timeout cannot stall detection of the next event.

    DELIBERATELY STILL `send_email`, NOT `notify.notify()` — do not "finish" the
    2026-08-23 digest wiring by converting this. Every other alert path in the
    product now routes through `notify.notify()`, which makes this look like an
    oversight. It is not.

    In digest mode `notify.notify()` OPENS THE SHARED DATABASE to queue the event.
    This process must never do that, for the reason `_audit_row` above records in
    full: it runs as root with CAP_NET_ADMIN and no CAP_DAC_OVERRIDE, so opening
    alerts.db creates the WAL sidecars owned by ROOT, and the unprivileged
    dashboard is then silently locked out of writing to its own database. That
    happened on 2026-08-01 and was measured, not theorised.

    The trap is that it would look fine in testing: the shipped default
    (`notify_mode = "immediate"`) never opens the DB, so the fault stays latent
    until an operator switches to digest — at which point the FIRST firewall
    tamper alert breaks the dashboard's writes.

    If bundling these alerts is ever genuinely wanted, the route is the one
    `_audit_row` already uses: write to the degraded journal and let the dashboard
    ingest and enqueue it as the user that owns the database.
    """
    def _send():
        try:
            import email_utils
            email_utils.send_email(subject, body)
        except Exception:
            log.exception("fwwatch: alert email failed")
    try:
        threading.Thread(target=_send, name="fwwatch-mail", daemon=True).start()
    except Exception:
        log.exception("fwwatch: could not start the mail thread")


def alert(code: str, severity: str, message: str, **context) -> None:
    """Raise on every channel. No single channel is trusted to survive."""
    log.error("[%s] %s | %s", code, message,
              " ".join("%s=%s" % kv for kv in sorted(context.items())))
    _degraded(code, severity, message, context)
    _audit_row("fw_table_tampered" if code == ERR_TAMPERED else "fw_enforcement_alert",
               "%s %s" % (code, message))
    sev = "CRITICAL" if severity == "critical" else "HIGH"
    lines = ["The deterministic enforcement table (ADR 0019) raised an alert.", "",
             "  Detected:     %s (server local time)" % time.strftime("%Y-%m-%d %H:%M:%S"),
             "  Code:         %s" % code, "  Message:      %s" % message]
    for k in sorted(context):
        lines.append("  %-13s %s" % (k + ":", context[k]))
    lines += ["", "  Auto-restore: %s" % ("ENABLED" if AUTORESTORE else "disabled (detection only)"),
              "", "The table has NOT been repaired unless stated above. Inspect before changing anything:",
              "  sudo nft list table %s %s" % (TABLE_FAMILY, TABLE_NAME)]
    _email_async("[Nemesis] %s: enforcement table %s" % (sev, message), "\n".join(lines))


def rerender() -> None:
    """Regenerate the derived table from ufw's CURRENT state, then rebaseline.

    Calls the same render path the boot unit uses rather than reimplementing it —
    one definition of what the derived ruleset is.
    """
    try:
        out = "/run/nemesis-enforce.nft"
        r = subprocess.run([RENDER, "render", "-o", out], capture_output=True, timeout=30)
        if r.returncode != 0:
            log.error("fwwatch: render failed: %s", r.stderr.decode()[:200])
            return
        r = subprocess.run(["nft", "-f", out], capture_output=True, timeout=30)
        if r.returncode != 0:
            log.error("fwwatch: apply failed: %s", r.stderr.decode()[:200])
            return
        h = table_hash()
        if h:
            write_expected(h, "re-render after ufw change")
            log.info("fwwatch: re-rendered derived table; baseline updated")
    except Exception:
        log.exception("fwwatch: re-render failed")


def restore_from_lkg() -> bool:
    lkg = os.path.join(LKG_DIR, "lkg.nft")
    if not os.path.exists(lkg) or os.path.getsize(lkg) == 0:
        return False
    try:
        subprocess.run(["nft", "delete", "table", TABLE_FAMILY, TABLE_NAME],
                       capture_output=True, timeout=10)
        r = subprocess.run(["nft", "-f", lkg], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        log.exception("fwwatch: restore failed")
        return False


def _auto_restore(reason: str, expected: str | None) -> None:
    """Restore from LKG and PROVE it, rather than trusting `nft -f`'s exit code.

    Rule 13. `restore_from_lkg()`'s success condition is only that `nft -f`
    returned 0 (nemesis_fw_watch.py:243) — that says the file parsed, not that the
    live table now matches it. Both call sites previously logged
    "table auto-restored from last-known-good" unconditionally, outside the `if h:`
    that guarded the baseline write, so the claim fired even when the post-restore
    hash was unreadable. A false "restored" line is worse than silence here: the
    critical alert has already fired, and this is the line that stops anyone
    looking.

    Deliberately ONE definition shared by both call sites, matching `verify()`'s
    own reasoning about not letting two paths drift apart.

    Note on the baseline comparison: nothing in this repo writes `lkg.nft` (it is
    produced on the enforcement-engine side), so LKG content is NOT guaranteed to
    hash-equal the recorded baseline. When they differ we report it and do NOT
    adopt the observed hash — adopting it would silently bless whatever state the
    restore actually produced and blind every future tamper check.
    """
    if not restore_from_lkg():
        log.error("fwwatch: auto-restore did NOT apply last-known-good (%s) — "
                  "table remains in the alerted state", reason)
        return
    h = table_hash()
    if h is None:
        log.error("fwwatch: auto-restore ran but the table could NOT be read back "
                  "(%s) — treating as NOT restored; baseline left unchanged", reason)
        return
    if expected is None:
        # No baseline existed (the deleted-with-no-prior-baseline case). The table
        # is readable again, which is all that can honestly be claimed.
        write_expected(h, "auto-restore (no prior baseline to confirm against)")
        log.warning("fwwatch: table reloaded from last-known-good and is readable "
                    "(%s); no prior baseline existed, so it could not be confirmed "
                    "to match one", reason)
        return
    if h != expected:
        log.error("fwwatch: auto-restore reloaded the table but it does NOT match "
                  "the recorded baseline (%s): observed=%s expected=%s. NOT "
                  "claiming a restore and NOT adopting the observed hash.",
                  reason, h[:16], expected[:16])
        return
    write_expected(h, "auto-restore")
    log.warning("fwwatch: table auto-restored from last-known-good and verified "
                "against the recorded baseline (%s)", reason)


#: Last condition alerted on, so a persisting problem does not re-alert forever.
#: Measured on the VM 2026-08-01: an unresolved deletion produced four records in
#: two minutes and would have emailed every 60s indefinitely — alert fatigue, and
#: exactly what trains an operator to ignore the alert that matters most. Keyed
#: on (code, observed-state) so a CHANGE in the condition still alerts: an
#: attacker making a second, different edit must not be masked by the first.
_last_alert_key: tuple | None = None


def _alert_once(key: tuple, code: str, severity: str, message: str, **context) -> None:
    """Raise only on a transition into a new condition; log the rest."""
    global _last_alert_key
    if key == _last_alert_key:
        log.info("fwwatch: [%s] condition persists (%s) — already alerted, not repeating",
                 code, context.get("reason"))
        return
    _last_alert_key = key
    alert(code, severity, message, **context)


def _clear_alert_state() -> None:
    """Called when the table matches the baseline again, so a RECURRENCE alerts."""
    global _last_alert_key
    if _last_alert_key is not None:
        log.info("fwwatch: table matches baseline again — alert state cleared")
    _last_alert_key = None


def verify(reason: str) -> None:
    """THE discrete unit of work.

    Deliberately shared by three callers — startup, netlink events, and the
    periodic tick — so there is exactly one definition of "is the table what we
    expect". Splitting them would let the event path and the periodic path drift
    apart, and the periodic path is the one that has to be right when events
    have been dropped.
    """
    live = table_hash()
    expected = read_expected()

    if live is None:
        _alert_once(("deleted",), ERR_DELETED, "critical", "deleted or unreadable",
                    reason=reason, expected=expected or "none")
        if AUTORESTORE:
            _auto_restore(reason, expected)
        return

    if expected is None:
        _alert_once(("nobaseline", live), ERR_NO_BASELINE, "error",
                    "present but no baseline was recorded",
                    reason=reason, observed=live[:16])
        write_expected(live, "adopted existing table (no prior baseline)")
        return

    if live == expected:
        _clear_alert_state()
        return

    if live != expected:
        # Keyed on the OBSERVED hash: a further, different edit is a new
        # condition and must alert again rather than being swallowed.
        _alert_once(("tampered", live), ERR_TAMPERED, "error", "modified outside Nemesis",
                    reason=reason, expected=expected[:16], observed=live[:16])
        if AUTORESTORE:
            _auto_restore(reason, expected)


# ── ADR 0026 step 4: tailnet plain-HTTP guard ────────────────────────────────

#: Separate from `_last_alert_key`. The guard and the enforcement table are different
#: conditions and must not mask each other: a persisting table tamper must not swallow a
#: NEW guard failure, and vice versa.
_last_guard_alert_key: tuple | None = None
#: monotonic timestamps of successful repairs, for flap detection.
_guard_repairs: list[float] = []


def _guard_alert(code: str, severity: str, message: str, **context) -> None:
    """Raise on every channel, with a body written for THIS failure, not the table's."""
    log.error("[%s] guard: %s | %s", code, message,
              " ".join("%s=%s" % kv for kv in sorted(context.items())))
    _degraded(code, severity, message, context)
    sev = "CRITICAL" if severity == "critical" else "HIGH"
    lines = ["The tailnet plain-HTTP guard (ADR 0026 step 4) raised an alert.", "",
             "  Detected:  %s (server local time)" % time.strftime("%Y-%m-%d %H:%M:%S"),
             "  Code:      %s" % code,
             "  Message:   %s" % message,
             "  Guard:     drop inbound %s/%s arriving on %s"
             % (GUARD_PORT, GUARD_PROTO, GUARD_IFACE)]
    for k in sorted(context):
        lines.append("  %-10s %s" % (k + ":", context[k]))
    lines += ["",
              "What this protects: the dashboard is reachable over the tailnet on :443",
              "with TLS. This guard is what stops it also answering in the clear on :80.",
              "",
              "Inspect the live state:",
              "  sudo iptables -t raw -S PREROUTING",
              "  sudo ip6tables -t raw -S PREROUTING"]
    _email_async("[Nemesis] %s: tailnet HTTP guard %s" % (sev, message), "\n".join(lines))


def _guard_alert_once(key: tuple, code: str, severity: str, message: str, **context) -> None:
    """Same transition-only discipline as _alert_once, on its own condition space."""
    global _last_guard_alert_key
    if key == _last_guard_alert_key:
        log.info("fwwatch: guard [%s] condition persists — already alerted, not repeating", code)
        return
    _last_guard_alert_key = key
    _guard_alert(code, severity, message, **context)


def _guard_clear() -> None:
    global _last_guard_alert_key
    if _last_guard_alert_key is not None:
        log.info("fwwatch: guard healthy again — alert state cleared")
    _last_guard_alert_key = None


def _guard_note_repair() -> int:
    """Record a repair and return how many happened inside the flap window."""
    now = time.monotonic()
    _guard_repairs.append(now)
    del _guard_repairs[:max(0, len(_guard_repairs) - 100)]
    recent = [t for t in _guard_repairs if now - t <= GUARD_FLAP_WINDOW]
    _guard_repairs[:] = recent
    return len(recent)


def _guard_dump(binary: str):
    """(text, None) or (None, reason). A failed read is an EXPLICIT failure, never ''.

    An empty string would parse as a ruleset with no rules and classify as NOT_DROP --
    a read failure would then be indistinguishable from a defeated guard, and would
    trigger a repair on the strength of having learned nothing.
    """
    try:
        r = subprocess.run([binary, "-t", "raw", "-S", "PREROUTING"],
                           capture_output=True, text=True, timeout=10)
    except Exception as exc:                                       # noqa: BLE001
        return None, "%s could not be run (%s)" % (binary, exc)
    if r.returncode != 0:
        return None, "%s exited %d: %s" % (binary, r.returncode, (r.stderr or "").strip()[:120])
    return r.stdout, None


def _guard_heal(family: str, reason: str) -> bool:
    """Repair through the chokepoint, never with a direct iptables call.

    This process HAS CAP_NET_ADMIN and could edit the table itself in one line. It does
    not, deliberately: routing through nemesis_fwd is what puts the repair in the audit
    trail as `fw-healer`, and what keeps every rule change in this product going through
    the single reviewed path (ADR 0005). A repair nothing recorded is the same blind
    spot this watcher was built to close, reintroduced by the watcher itself.

    Repairs BOTH families in one call -- the helper op does v4 and v6 together -- so it
    runs once per check even when both are defeated.

    Goes through `firewall.py` rather than `fw_client` directly: firewall.py IS the
    chokepoint ADR 0005 names, and fw_client is only its transport. Verified safe to
    import from this process -- it pulls nothing DB-related, which matters here for the
    reason `_audit_row` records at length: this runs as root with CAP_NET_ADMIN and no
    CAP_DAC_OVERRIDE, so touching the database would create root-owned WAL siblings and
    silently lock the dashboard out of its own writes.
    """
    try:
        import firewall
    except Exception as exc:                                       # noqa: BLE001
        _guard_alert(ERR_GUARD_HEAL_FAILED, "critical",
                     "cannot repair: the firewall chokepoint is unavailable",
                     detail=str(exc)[:120], reason=reason, family=family)
        return False
    try:
        res = firewall.reassert_port_on_interface(GUARD_IFACE, GUARD_PORT, GUARD_PROTO)
    except Exception as exc:                                       # noqa: BLE001
        _guard_alert(ERR_GUARD_HEAL_FAILED, "critical",
                     "repair was REFUSED or failed -- the guard is still down",
                     detail=str(exc)[:160], reason=reason, family=family)
        return False
    log.warning("fwwatch: guard repaired via nemesis-fwd (%s): %s", reason, res)
    return True


def verify_tailnet_guard(reason: str) -> None:
    """Is plain HTTP over the tailnet actually refused -- and by OUR rule?

    Deliberately NOT `iptables -C`. Presence is not reachability: the failure mode this
    exists for is a rule that is still there and no longer reached, because something
    was inserted above it. `raw_traversal` answers reachability by walking the chain.

    BOTH conditions are required. `status == DROP` alone means the packet is blocked,
    which a chain policy of DROP or somebody else's rule can also produce while OUR
    guard is absent -- traffic blocked today by something that may be gone tomorrow.
    `by_our_rule` is what makes the check about the guard rather than about the weather.

    One shared definition of the discrete unit of work, called from startup, the event
    path and the periodic tick -- same reasoning as `verify()` above.
    """
    if not GUARD_ENABLED:
        return
    try:
        import raw_traversal
    except Exception as exc:                                       # noqa: BLE001
        _guard_alert_once(("noparser",), ERR_GUARD_UNDETERMINED, "error",
                          "cannot check: the traversal parser is unavailable",
                          detail=str(exc)[:120], reason=reason)
        return

    verdicts, needs_repair, undetermined = {}, [], []
    for family, binary in (("v4", IPTABLES_BIN), ("v6", IP6TABLES_BIN)):
        dump, err = _guard_dump(binary)
        if dump is None:
            undetermined.append((family, err))
            continue
        try:
            res = raw_traversal.classify(
                dump, raw_traversal.Packet(GUARD_IFACE, GUARD_PROTO, GUARD_PORT))
        except raw_traversal.SelfTestFailed as exc:
            # The instrument failed its own canaries. It must not vouch for anything,
            # and a repair on the strength of a broken check is worse than no check.
            _guard_alert_once(("selftest",), ERR_GUARD_UNDETERMINED, "critical",
                              "the guard checker FAILED ITS OWN SELF-TEST and will not "
                              "vouch for the ruleset", detail=str(exc)[:200], reason=reason)
            return
        verdicts[family] = res
        if res.status == raw_traversal.UNDETERMINED:
            undetermined.append((family, res.reason))
        elif not (res.status == raw_traversal.DROP and res.by_our_rule):
            needs_repair.append((family, res))

    if undetermined:
        # Not "probably fine". Something above our rule cannot be modelled, so whether
        # the packet reaches the DROP is genuinely unknown -- report it and do NOT
        # repair, because the repair target itself may not be what is wrong.
        _guard_alert_once(("undetermined", tuple(f for f, _ in undetermined)),
                          ERR_GUARD_UNDETERMINED, "error",
                          "guard state could NOT be determined",
                          families=",".join(f for f, _ in undetermined),
                          detail="; ".join(d for _, d in undetermined)[:300],
                          reason=reason)
        return

    if not needs_repair:
        _guard_clear()
        return

    fams = tuple(f for f, _ in needs_repair)
    first = needs_repair[0][1]
    # The key carries the REASON, not just the verdict. Two different defeats -- our
    # rule shadowed by an ACCEPT, versus our rule gone entirely -- are both
    # (NOT_DROP, by_our_rule=False), so a key built from the verdict alone would let a
    # second, different attack be swallowed as "already alerted". Same argument
    # _alert_once makes by keying on the observed hash rather than on "tampered".
    _guard_alert_once(("defeated", fams, first.status, first.by_our_rule,
                       (first.reason or "")[:120]),
                      ERR_GUARD_DEFEATED, "critical",
                      "plain HTTP over the tailnet is NOT being refused",
                      families=",".join(fams),
                      verdict=first.status,
                      by_our_rule=first.by_our_rule,
                      why=first.reason,
                      trace=" | ".join(first.trace[-3:]) or "(no rule matched)",
                      reason=reason)

    if not _guard_heal(",".join(fams), reason):
        return

    # Prove the repair rather than trusting the helper's return -- the same standard
    # _auto_restore applies to the enforcement table.
    still_bad = []
    for family, binary in (("v4", IPTABLES_BIN), ("v6", IP6TABLES_BIN)):
        dump, err = _guard_dump(binary)
        if dump is None:
            still_bad.append("%s: %s" % (family, err))
            continue
        res = raw_traversal.classify(
            dump, raw_traversal.Packet(GUARD_IFACE, GUARD_PROTO, GUARD_PORT))
        if not (res.status == raw_traversal.DROP and res.by_our_rule):
            still_bad.append("%s: %s/%s" % (family, res.status, res.by_our_rule))
    if still_bad:
        _guard_alert(ERR_GUARD_HEAL_FAILED, "critical",
                     "repair reported success but the guard is STILL not effective",
                     detail="; ".join(still_bad)[:200], reason=reason)
        return

    n = _guard_note_repair()
    log.warning("fwwatch: guard restored and verified (%s); repairs in the last %ds: %d",
                reason, int(GUARD_FLAP_WINDOW), n)
    if n >= GUARD_FLAP_THRESHOLD:
        _guard_alert(ERR_GUARD_FLAPPING, "critical",
                     "the guard keeps being knocked out and repaired",
                     repairs=n, window_seconds=int(GUARD_FLAP_WINDOW), reason=reason)
    _guard_clear()


def classify(evt: dict) -> str | None:
    """'ours' | 'ufw' | None — which table did this event touch?"""
    for _op, obj in evt.items():
        if not isinstance(obj, dict):
            continue
        for kind in ("rule", "chain", "table", "set", "element"):
            o = obj.get(kind)
            if not isinstance(o, dict):
                continue
            fam, tbl = o.get("family"), o.get("table") or o.get("name")
            if fam == TABLE_FAMILY and tbl == TABLE_NAME:
                return "ours"
            if (fam, tbl) in UFW_TABLES:
                return "ufw"
    return None


def reader(q: "queue.Queue[str]", stop: threading.Event) -> None:
    """Do NOTHING but enqueue.

    Netlink multicast drops when the socket buffer fills, so anything slow here
    costs events. All processing happens on the main loop.
    """
    while not stop.is_set():
        try:
            p = subprocess.Popen(["nft", "--json", "monitor"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 bufsize=1, text=True)
            log.info("fwwatch: subscribed to netfilter events (pid %s)", p.pid)
            for line in p.stdout:
                if stop.is_set():
                    break
                try:
                    q.put_nowait(line)
                except queue.Full:
                    # Bounded queue: shedding here is safe because the periodic
                    # re-verify still catches whatever was missed.
                    pass
            p.terminate()
        except Exception:
            log.exception("fwwatch: monitor subprocess failed")
        if not stop.is_set():
            log.warning("fwwatch: event stream ended — restarting in 2s")
            time.sleep(2)


def _write_heartbeat() -> None:
    """Stamp the liveness file. Shared by startup and the periodic tick so the two
    cannot drift -- same reasoning as verify() having exactly one definition."""
    try:
        os.makedirs(os.path.dirname(HEARTBEAT), exist_ok=True)
        with open(HEARTBEAT, "w") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S") + "\n")
    except Exception:
        log.exception("fwwatch: heartbeat write failed")


def main() -> int:
    os.makedirs(LKG_DIR, exist_ok=True)
    log.info("fwwatch: starting (autorestore=%s debounce=%ss reverify=%ss)",
             AUTORESTORE, DEBOUNCE_SECONDS, REVERIFY_SECONDS)
    log.info("fwwatch: tailnet guard %s (%s/%s on %s)",
             "ENABLED" if GUARD_ENABLED else "disabled — set NEMESIS_FW_GUARD=1 to arm",
             GUARD_PORT, GUARD_PROTO, GUARD_IFACE)

    # Write the heartbeat IMMEDIATELY, before anything slow. Until 2026-08-25 the first
    # write happened only when the loop reached its 60s interval, so for the first minute
    # after every boot the file did not exist while the service was perfectly healthy --
    # and the watchdog's consumer, which reads a missing file as "stopped, disabled or
    # masked", raised a false alert on EVERY reboot. Measured live: watchdog started
    # 10:17:15, alerted 10:17:22, fw-watch was running the whole time. A monitor that
    # cries wolf once per boot is worse than no monitor, because it trains the operator
    # to ignore the one alert that matters.
    _write_heartbeat()

    # Re-verify BEFORE subscribing. Without this, "stop the watcher, tamper,
    # start it" is a free bypass — the watcher cannot see what happened while it
    # was down, so it must compare state rather than trust the event stream.
    verify("startup")
    # The reboot case lands here: raw rules do not survive a restart, so on a box where
    # the guard is armed this is what puts it back before anything else runs.
    verify_tailnet_guard("startup")

    q: "queue.Queue[str]" = queue.Queue(maxsize=10000)
    stop = threading.Event()
    t = threading.Thread(target=reader, args=(q, stop), name="fwwatch-reader", daemon=True)
    t.start()

    pending_ours = pending_ufw = False
    last_action = last_reverify = last_beat = time.monotonic()
    try:
        while True:
            try:
                line = q.get(timeout=0.5)
                try:
                    kind = classify(json.loads(line))
                except Exception:
                    kind = None
                if kind == "ours":
                    pending_ours = True
                elif kind == "ufw":
                    pending_ufw = True
            except queue.Empty:
                pass

            now = time.monotonic()
            if (pending_ours or pending_ufw) and (now - last_action) >= DEBOUNCE_SECONDS:
                if pending_ufw:
                    rerender()          # rebaselines, so the paired 'ours' burst is expected
                    pending_ufw = False
                if pending_ours:
                    verify("netlink event")
                    pending_ours = False
                # Runs after EITHER kind of debounced change. PIA rewriting the raw
                # table arrives classified as "ufw" (UFW_TABLES covers ("ip","raw")),
                # so keying this off pending_ours alone would miss the exact event the
                # guard exists for. Cheap enough to run on both: two -S reads and a
                # pure-python walk.
                verify_tailnet_guard("netlink event")
                last_action = now

            if (now - last_reverify) >= REVERIFY_SECONDS:
                verify("periodic")      # backstop for dropped netlink events
                # The backstop that matters most here: a rule can be preempted with no
                # netlink event this watcher will recognise, and case 3 changes nothing
                # about our own rule at all.
                verify_tailnet_guard("periodic")
                last_reverify = now

            if (now - last_beat) >= 60:
                _write_heartbeat()
                last_beat = now
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
