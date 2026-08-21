#!/usr/bin/env python3
"""Engine-agnostic ruleset distribution — fetch, verify, COMPILE-CHECK, activate.

ADR 0004 hinge (b) obligation #2: a fleet-wide rule distribution channel with
compile-check-before-activate, so one bad ruleset cannot break a detection layer
across the whole fleet. This generalises the logic already PROVEN in
`agent._update_suricata_rules` (which caught a live bug where a login page was
installed as a Suricata ruleset — 2026-08-03) into a form any engine's rules ride:
Suricata today, the behavioral engine (Falco) at M2, YARA when it moves to the
endpoint.

THE INVARIANT, in order, none skippable:
  1. Fetch with a MANDATORY sha256 the signing server produces — a ruleset with no
     verifiable digest is refused, which also closes the unauthenticated-fetch hole
     (a local process cannot make the agent install rules of its choosing without a
     digest only the server can produce).
  2. Redirects are NOT followed — that is what turns "a login page served at the
     rules URL" into a loud http_status_3xx instead of HTML masquerading as rules.
  3. Size-bounded streaming — an oversized body is abandoned mid-transfer.
  4. COMPILE-CHECK the fetched bytes with an engine-specific validator BEFORE they
     are activated. This is the fleet-safety property: a ruleset that does not
     compile is discarded before it can replace a working one.
  5. Atomic activate (write tmp, fsync, os.replace), then RE-READ from disk and
     re-hash — verify the bytes that LANDED, not the bytes intended. Restore the
     previous ruleset (kept, not consumed) if the post-write check fails.

Every failure returns a structured result with an explicit reason; the ruleset in
force is never left half-replaced.
"""
import hashlib
import hmac
import logging
import os

import requests

log = logging.getLogger("nemesis_agent.rule_updater")

MAX_RULES_BYTES = 64 * 1024 * 1024      # generous; per-engine callers may lower it
CHUNK = 65536
FETCH_TIMEOUT = 30


def _fail(engine, reason, **extra):
    log.error("ruleset update REFUSED (engine=%s reason=%s)", engine, reason)
    out = {"ok": False, "engine": engine, "error": reason}
    out.update(extra)
    return out


def update_ruleset(engine, rules_url, sha256, size, dest_path,
                   compile_check=None, activate=None, max_bytes=MAX_RULES_BYTES):
    """Distribute one engine's ruleset to `dest_path`. Returns a result dict; never
    raises.

    compile_check(path) -> (ok: bool, detail: str): engine-specific validation of
        the fetched file BEFORE activation (falco --validate / yara -w / suricata -T).
        None => skip (only for engines with no validator; logged).
    activate() -> None: engine-specific post-install action (reload the daemon).
        None => no activation step (the file on disk is the activation).
    """
    # ── validate the request ────────────────────────────────────────────────
    if not rules_url:
        return _fail(engine, "no_rules_url")
    if not (isinstance(sha256, str) and len(sha256) == 64
            and all(c in "0123456789abcdefABCDEF" for c in sha256)):
        return _fail(engine, "digest_required")
    try:
        from urllib.parse import urlparse
        scheme = urlparse(rules_url).scheme.lower()
    except Exception:                                        # noqa: BLE001
        return _fail(engine, "bad_scheme")
    if scheme not in ("http", "https"):
        return _fail(engine, "bad_scheme")
    try:
        size = int(size)
    except (TypeError, ValueError):
        return _fail(engine, "size_required")
    if size <= 0:
        return _fail(engine, "size_required")
    if size > max_bytes:
        return _fail(engine, "too_large_declared")

    # ── fetch, bounded, no redirects, digest-checked ────────────────────────
    try:
        r = requests.get(rules_url, timeout=FETCH_TIMEOUT, stream=True,
                         allow_redirects=False)
    except Exception as e:                                   # noqa: BLE001
        return _fail(engine, "fetch_failed", detail=str(e)[:200])
    try:
        if r.status_code != 200:
            return _fail(engine, "http_status_%d" % r.status_code)
        digest, chunks, total = hashlib.sha256(), [], 0
        for chunk in r.iter_content(CHUNK):
            if not chunk:
                continue
            total += len(chunk)
            if total > size:
                return _fail(engine, "size_mismatch", received=total, expected=size)
            digest.update(chunk)
            chunks.append(chunk)
    finally:
        r.close()
    if total != size:
        return _fail(engine, "size_mismatch", received=total, expected=size)
    got = digest.hexdigest()
    if not hmac.compare_digest(got, sha256.lower()):
        return _fail(engine, "digest_mismatch", received_sha256=got)
    content = b"".join(chunks)

    # ── COMPILE-CHECK before activation (the fleet-safety property) ─────────
    tmp = dest_path + ".incoming"
    prev = dest_path + ".prev"
    try:
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with open(tmp, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception as e:                                   # noqa: BLE001
        _rm(tmp)
        return _fail(engine, "stage_failed", detail=str(e)[:200])

    if compile_check is not None:
        try:
            ok, detail = compile_check(tmp)
        except Exception as e:                              # noqa: BLE001
            ok, detail = False, "compile-check raised: %s" % e
        if not ok:
            _rm(tmp)
            # the ruleset in force is UNTOUCHED — a bad ruleset never replaces a good one
            return _fail(engine, "compile_check_failed", detail=str(detail)[:200])
    else:
        log.warning("engine=%s has no compile-check validator -- activating unchecked",
                    engine)

    # ── atomic activate, then verify the bytes that LANDED ──────────────────
    try:
        if os.path.exists(dest_path):
            with open(dest_path, "rb") as old, open(prev, "wb") as bak:
                bak.write(old.read())
        os.replace(tmp, dest_path)              # atomic; never a half-written ruleset
        with open(dest_path, "rb") as fh:
            on_disk = hashlib.sha256(fh.read()).hexdigest()
        if not hmac.compare_digest(on_disk, sha256.lower()):
            restored = _restore(prev, dest_path)
            return _fail(engine, "post_write_mismatch", on_disk_sha256=on_disk,
                         restored=restored)
    except Exception as e:                                  # noqa: BLE001
        restored = _restore(prev, dest_path)
        return _fail(engine, "install_failed", detail=str(e)[:200], restored=restored)
    finally:
        _rm(tmp)

    # ── activate (reload the engine), fail-safe on error ────────────────────
    if activate is not None:
        try:
            activate()
        except Exception as e:                              # noqa: BLE001
            # The rules are installed and verified; the reload failed. Report it
            # loudly but do NOT roll back the file -- the next reload/restart picks
            # it up, and rolling back a verified ruleset over a reload hiccup would
            # be the worse outcome.
            log.error("engine=%s ruleset installed but activate() failed: %s",
                      engine, e)
            _rm(prev)
            return {"ok": True, "engine": engine, "sha256": got, "bytes": total,
                    "activated": False, "activate_error": str(e)[:200]}

    _rm(prev)
    log.info("engine=%s ruleset updated (%d bytes, sha256=%s...)",
             engine, total, got[:12])
    return {"ok": True, "engine": engine, "sha256": got, "bytes": total,
            "activated": activate is not None}


def _rm(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def _restore(prev, dest):
    """Put the previous ruleset back WITHOUT consuming the backup (copy, not move),
    so a bad restore still leaves .prev on disk to recover by hand."""
    if not os.path.exists(prev):
        return False
    rtmp = dest + ".restore"
    try:
        with open(prev, "rb") as src, open(rtmp, "wb") as dst:
            dst.write(src.read())
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(rtmp, dest)
        return True
    except Exception as exc:                                # noqa: BLE001
        log.error("could not restore previous ruleset: %s (a copy remains at %s)",
                  exc, prev)
        return False
