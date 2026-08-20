"""L2 — WinDivert reputation blocking on TCP handshake-initiation (Windows), with stall-watchdog.

Opens a WinDivert handle on a NARROW filter (outbound TCP SYN-flagged packets) and, for
each connection handshake, looks the peer IP up in the Feature-6 local reputation cache:
KNOWN-BAD -> drop the packet (handshake never completes); clean OR unknown -> reinject
unmodified (connection proceeds). The filter is BIDIRECTIONAL by design: tcp.Syn matches
both an outbound pure SYN (this host connecting OUT to a bad IP) AND an outbound SYN-ACK
(this host answering an INBOUND connection from a bad IP), so reputation blocking covers
both directions of connection initiation -- intentional, not outbound-only, because
blocking only outbound while accepting inbound from known-bad sources would be asymmetric
protection for a security product. Established flows carry no SYN and are never diverted.

DEFAULT OFF (l2_enforce_enabled=false). This is the only layer that can block real
traffic, so it is fail-open by construction:

  * pydivert/WinDivert handle fails to open  -> L2 is skipped entirely, no filtering.
  * ANY exception in the loop                -> finally: handle closes -> filter
                                                removed -> traffic flows.
  * process killed                           -> OS closes the handle -> filter removed.
  * verdict lookup error / unknown IP        -> ALLOW (reinject) — never block on doubt.
  * SILENT HANG mid-packet (the dangerous
    case flagged in scoping)                 -> STALL-WATCHDOG force-closes the handle,
                                                which unblocks recv and removes the
                                                filter -> traffic restored.

The watchdog distinguishes a hang (a packet stuck in processing past the timeout) from
normal idle (blocked in recv with nothing to process) via a _processing_since marker
that is set only while a packet is being handled.

Kill switch (agent-independent — works even if this process is dead/hung):
    sc stop WinDivert                      (stop the kernel driver service)
    taskkill /IM NemesisAgent.exe /F       (kill the agent)
    # a reboot also clears it (WinDivert is demand-start, not boot-start)
The exact service name is logged at startup ("L2 windivert service: <name>").
"""
import sys
import time
import threading
import logging

import agent_errors
log = logging.getLogger("nemesis_agent.l2_windivert")

# Narrow filter: outbound TCP SYN-flagged packets = connection handshakes in BOTH
# directions -- outbound SYN (we initiate to a peer) AND outbound SYN-ACK (we answer an
# inbound connect). Intentional bidirectional reputation coverage, NOT outbound-only.
# Established flows (no SYN), UDP, and non-IP are never diverted. Tradeoff: because
# SYN-ACK matches, a NEW inbound connection is briefly blocked during a stall (until the
# watchdog recovers, ~stall_timeout); established sessions are unaffected.
FILTER = "outbound and ip and tcp and tcp.Syn"
DEFAULT_STALL_TIMEOUT = 5.0     # seconds a packet may be in-processing before the watchdog fires
WATCHDOG_INTERVAL = 1.0

# ── module state (single L2 instance) ──────────────────────────────────────────
_running = False
_handle = None
_processing_since = None        # monotonic ts while a packet is mid-processing; None when idle
_stall_timeout = DEFAULT_STALL_TIMEOUT
_stalled = False
_stats = {"handled": 0, "blocked": 0, "allowed": 0, "errors": 0}
_inject = None                  # test hook: 'crash' | 'hang' (None in production)


def _is_blocked(ip):
    """Verdict from the Feature-6 local cache. Block only on a KNOWN HIGH/CRITICAL
    entry. FAIL-OPEN: any error, or an unknown/clean IP, returns False (allow)."""
    try:
        import reputation_cache
        row, _ = reputation_cache.lookup(ip)
        if not row:
            return False
        threat = (row[2] or "").upper()          # threat_level
        score = row[1] or 0                       # abuse_score
        return threat in ("HIGH", "CRITICAL") or score >= 50
    except Exception:
        return False                              # never block on a lookup failure


def _watchdog():
    """Force-close the handle if a packet stays in-processing past the timeout. This is
    the mandated fix for the silent-hang failure mode — closing the handle unblocks the
    recv loop AND removes the filter, so traffic flows again."""
    global _stalled
    while _running:
        time.sleep(WATCHDOG_INTERVAL)
        ps = _processing_since
        if ps is not None and (time.monotonic() - ps) > _stall_timeout:
            log.error("L2 STALL: packet in-processing %.1fs > %.1fs — force-closing "
                      "handle (FAIL-OPEN)", time.monotonic() - ps, _stall_timeout)
            agent_errors.record("E-AGENT-003", "stalled %.1fs > %.1fs, force-closed"
                                % (time.monotonic() - ps, _stall_timeout))
            _stalled = True
            try:
                if _handle is not None:
                    _handle.close()
            except Exception:
                pass
            return


def _loop(conf):
    """The divert loop. Wrapped so that EVERY exit path closes the handle."""
    global _handle, _processing_since, _running
    try:
        import pydivert
    except Exception as e:
        log.warning("L2 disabled: pydivert/WinDivert unavailable (%s) — traffic "
                    "untouched (fail-open)", e)
        agent_errors.record("E-AGENT-001", "pydivert/WinDivert unavailable: %s" % e)
        return

    try:
        _handle = pydivert.WinDivert(FILTER)
        _handle.open()
    except Exception as e:
        log.warning("L2 disabled: WinDivert handle failed to open (%s) — traffic "
                    "untouched (fail-open)", e)
        agent_errors.record("E-AGENT-002", "handle open failed: %s" % e)
        _handle = None
        return

    log.info("L2 windivert active: filter=%r stall_timeout=%.1fs. Kill switch: "
             "'sc stop WinDivert' + taskkill /IM NemesisAgent.exe /F", FILTER, _stall_timeout)
    _first = True
    try:
        for packet in _handle:
            _processing_since = time.monotonic()
            try:
                # ── test hooks (never set in production) ──
                if _inject == "crash" and _first:
                    raise RuntimeError("injected crash (test)")
                if _inject == "hang" and _first:
                    log.error("L2 injected HANG (test) — sleeping to trip the watchdog")
                    time.sleep(_stall_timeout * 3)

                dst = packet.dst_addr
                if _is_blocked(dst):
                    _stats["blocked"] += 1
                    log.info("L2 BLOCK: dropped SYN to %s (reputation)", dst)
                    # drop: do NOT reinject
                else:
                    _handle.send(packet)      # reinject unmodified — connection proceeds
                    _stats["allowed"] += 1
            except Exception as e:
                # Per-packet failure must never block: reinject best-effort, then continue.
                _stats["errors"] += 1
                log.warning("L2 per-packet error (%s) — reinjecting (fail-open)", e)
                agent_errors.record("E-AGENT-004", "per-packet error: %s" % e)
                try:
                    _handle.send(packet)
                except Exception:
                    pass
            finally:
                _processing_since = None
                _stats["handled"] += 1
                _first = False
            if not _running:
                break
    except Exception as e:
        log.warning("L2 loop exited on error (%s) — handle will close, traffic "
                    "restored (fail-open)", e)
    finally:
        try:
            if _handle is not None:
                _handle.close()
        except Exception:
            pass
        _handle = None
        log.info("L2 windivert stopped: %s", dict(_stats))


def start_background(conf):
    """Launch the watchdog + divert loop as daemon threads. Default entry from the
    agent. Returns immediately; never raises."""
    global _running, _stall_timeout, _stalled
    try:
        if _running:
            return
        _stall_timeout = float(conf.get("l2_stall_timeout_sec", DEFAULT_STALL_TIMEOUT))
        _stalled = False
        _running = True
        threading.Thread(target=_watchdog, name="l2-watchdog", daemon=True).start()
        threading.Thread(target=_loop, args=(conf,), name="l2-divert", daemon=True).start()
    except Exception:
        log.exception("L2 start failed — traffic untouched (fail-open)")
        _running = False


def stop():
    """Stop L2 and remove the filter. Idempotent; never raises."""
    global _running
    _running = False
    try:
        if _handle is not None:
            _handle.close()
    except Exception:
        pass


# ── standalone test harness (run on the VM; NOT used by the frozen agent) ───────
def _selftest(mode, seconds, conf):
    global _inject
    _inject = mode if mode in ("crash", "hang") else None
    print(f"[test] mode={_inject or 'normal'} duration={seconds}s filter={FILTER!r}")
    start_background(conf)
    time.sleep(seconds)
    stalled = _stalled
    stop()
    time.sleep(1.0)
    print(f"[test] result: stats={dict(_stats)} stalled={stalled} "
          f"handle_closed={_handle is None} running={_running}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    conf = {}
    try:
        import config
        conf = config.load()
    except Exception:
        pass
    arg = sys.argv[1] if len(sys.argv) > 1 else "--test-normal"
    secs = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    if arg == "--simulate-crash":
        _selftest("crash", secs, conf)
    elif arg == "--simulate-hang":
        _selftest("hang", max(secs, int(DEFAULT_STALL_TIMEOUT * 4)), conf)
    else:
        _selftest(None, secs, conf)
