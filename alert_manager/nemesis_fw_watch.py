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
HEARTBEAT = os.path.join(LKG_DIR, "watch.heartbeat")
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

ERR_TAMPERED = "NEM-FWW-0001"
ERR_DELETED = "NEM-FWW-0002"
ERR_NO_BASELINE = "NEM-FWW-0003"
ERR_RESTARTED = "NEM-FWW-0004"

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
    """Off-thread so a 30s SMTP timeout cannot stall detection of the next event."""
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
        if AUTORESTORE and restore_from_lkg():
            h = table_hash()
            if h:
                write_expected(h, "auto-restore")
            log.warning("fwwatch: table auto-restored from last-known-good")
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
        if AUTORESTORE and restore_from_lkg():
            h = table_hash()
            if h:
                write_expected(h, "auto-restore")
            log.warning("fwwatch: table auto-restored from last-known-good")


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


def main() -> int:
    os.makedirs(LKG_DIR, exist_ok=True)
    log.info("fwwatch: starting (autorestore=%s debounce=%ss reverify=%ss)",
             AUTORESTORE, DEBOUNCE_SECONDS, REVERIFY_SECONDS)

    # Re-verify BEFORE subscribing. Without this, "stop the watcher, tamper,
    # start it" is a free bypass — the watcher cannot see what happened while it
    # was down, so it must compare state rather than trust the event stream.
    verify("startup")

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
                last_action = now

            if (now - last_reverify) >= REVERIFY_SECONDS:
                verify("periodic")      # backstop for dropped netlink events
                last_reverify = now

            if (now - last_beat) >= 60:
                try:
                    with open(HEARTBEAT, "w") as f:
                        f.write(time.strftime("%Y-%m-%dT%H:%M:%S") + "\n")
                except Exception:
                    log.exception("fwwatch: heartbeat write failed")
                last_beat = now
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
