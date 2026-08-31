"""Sensitive-value AND network/personal-identifier redaction for diagnostic output.

Reads /etc/nemesis.env at call time (not at import time) so it always uses
the current on-disk values.  Any non-empty env value longer than 7 characters
is treated as a secret and replaced with [REDACTED] in output text.

Beyond known secrets, `redact()` also strips: known device/host names (read
live from the devices/agent_devices tables), IP and MAC addresses, LAN/mDNS/
Tailscale FQDNs (*.local / *.lan / *.ts.net), and email addresses. This is the
scrubber for text that may leave the box (e.g. Submit-to-Support) — see
diagnostics-and-access-master-plan.md §2.1 for why the narrower secrets-only
version of this module was a privacy gap, not just an incompleteness.

NOT `alert_manager/nemesis_pseudonymize.py`. That module maps addresses/names
to STABLE, REVERSIBLE tokens because the AI call it protects needs relational
reasoning to survive ("host-A is scanning host-B"). This module DESTROYS
matches with [REDACTED] because its output goes to a human outside the
network who has no way to reverse a token and no need to — the report just
needs to not carry the household's addressing and names on the wire. The two
modules share address/name-recognition logic (imported from
nemesis_pseudonymize, not re-derived) precisely so the two "what counts as
identifying" answers cannot drift apart, even though what each does with a
match differs.
"""

import logging
import os
import re
import sqlite3
import sys

log = logging.getLogger("nemesis.diagnostics.redact")

_ENV_FILE = "/etc/nemesis.env"
_MIN_SECRET_LEN = 8

# ── structured error codes (alert_manager/nemesis_errors.py) ─────────────────
# Deferred registration via make_recorder: this module may run standalone
# (`python3 -m diagnostics.disk_space`-style invocation) where the shared DB
# path is not registered yet, so import/registration is done on first use, not
# at import time. Shares the "diagnostics" namespace with
# modules/diagnostics/module.py (batch3's classification: same namespace, two
# packages). get_data_manager() can raise if the shared path was never
# published (standalone run) — the recorder's own try/except below swallows
# that the same way it swallows every other recording failure.
_ERR_CODES = {
    "E-REDACT-001": ("secret list could not be read from /etc/nemesis.env; "
                     "output withheld rather than under-redacted (fail closed)",
                     "HIGH", "fail-open-secret-leak"),
    "E-REDACT-002": ("known device/host names could not be read from the "
                     "devices database; output withheld rather than "
                     "under-redacted (fail closed)",
                     "HIGH", "fail-open-secret-leak"),
    "E-REDACT-003": ("address-matching pattern module could not be loaded; "
                     "output withheld rather than under-redacted (fail closed)",
                     "HIGH", "fail-open-secret-leak"),
}
_recorder = None


def _errors_record(code, context):
    """Record one structured error occurrence. Never raises into the caller."""
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors
            from modules import get_data_manager
            _recorder = nemesis_errors.make_recorder(
                "diagnostics", lambda: get_data_manager().connect("diagnostics"),
                _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:
        return None


class RedactionUnavailable(RuntimeError):
    """Some source `redact()` needs (secrets, known names, or the address
    pattern module) could not be determined, so nothing can be certified
    scrubbed.

    Distinct from "there is nothing from this source": an empty set is a real
    answer, this is the absence of one. Raised only when a source that should
    be readable could not be — see each loader for its own legitimate-empty
    vs fail-closed distinction.
    """


# Returned instead of under-redacted text. Deliberately long and unmistakable:
# the failure mode this replaces was silent, and a subtle marker would just be
# the same problem in a different font.
_WITHHELD = ("[OUTPUT WITHHELD — redaction unavailable: one of the redaction "
             "sources (secrets, known device names, or the address-matching "
             "module) could not be read, so this text cannot be certified "
             "free of secrets or identifying network data. Check that the "
             "reading process can read /etc/nemesis.env (mode 640 "
             "root:nemesis) and the devices database; see the "
             "nemesis.diagnostics.redact log for the exact cause.]")

# Keys that are definitely secrets even if short
_SECRET_KEYS = {
    "ABUSEIPDB_KEY", "IPINFO_TOKEN", "ANTHROPIC_API_KEY",
    "WATCHDOG_EMAIL", "WATCHDOG_PASSWORD", "PIHOLE_PASSWORD",
}

# Pattern for things that look like API keys even if not in env file
_KEY_PATTERN = re.compile(
    r'(sk-ant-[A-Za-z0-9\-_]{20,}|[A-Za-z0-9+/]{32,}={0,2})'
)

# Standard-shaped email: local-part@domain-with-a-dot. Deliberately requires a
# dotted domain (rejects "user@localhost") — narrower catches fewer false
# positives, and a bare-hostname email is not a realistic shape in diagnostic
# output.
_EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?'
    r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\b'
)

# LAN/mDNS/Tailscale FQDNs specifically — NOT a bare hostname regex. A generic
# "looks like a hostname" pattern has no reliable syntax to distinguish it
# from ordinary dotted words in diagnostic text (rejected during scoping,
# see diagnostics-and-access-master-plan.md §2.1). These three suffixes are
# unambiguous, so matching on them carries far less over-redaction risk.
_HOSTNAME_SUFFIX_PATTERN = re.compile(
    r'\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*'
    r'\.(?:local|lan|ts\.net)\b',
    re.IGNORECASE,
)

# Known device/host name sources — mirrors modules/ai_engine/module.py's
# _known_device_names() sourcing exactly (same two tables, same columns, same
# reasoning): a name is not pattern-recognisable the way an address is, so the
# only way to catch one is to already know it.
_DEVICES_TABLES = (
    ("devices", ("friendly_name", "hostname")),
    ("agent_devices", ("device_name",)),
)


def _resolve_devices_db():
    """Shared DB location — same resolution diagnostics/network_devices.py
    already uses, duplicated here rather than imported: these diagnostics
    modules are documented to run standalone by file path, and a cross-import
    between sibling check modules would reintroduce the sys.path fragility
    this resolver exists to route around."""
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _legacy = os.path.join(_root, "alert_manager", "alerts.db")
    try:
        sys.path.insert(0, os.path.join(_root, "alert_manager"))
        import nemesis_paths
        return nemesis_paths.db_path(_legacy)
    except Exception:
        return _legacy


_DEVICES_DB = _resolve_devices_db()


def _load_secrets() -> set:
    """The set of literal values `redact()` will strip.

    Raises RedactionUnavailable when the env file exists but cannot be read —
    see the fail-closed clause below for why that is not a silent partial answer.
    """
    secrets = set()
    try:
        with open(_ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                if not val:
                    continue
                # Always redact known-secret keys regardless of length
                if key in _SECRET_KEYS or len(val) >= _MIN_SECRET_LEN:
                    secrets.add(val)
    except FileNotFoundError:
        # LEGITIMATELY EMPTY, not a failure. No env file means no file-derived
        # secrets exist, so continuing with the environment-only set below is a
        # correct and COMPLETE answer. Kept distinct from the clause after it
        # precisely because conflating the two is what made this fail open.
        pass
    except Exception as exc:                      # noqa: BLE001 - re-raised
        # FAIL CLOSED. The file is there and we could not read it, so we do not
        # know what needs redacting. Falling through would hand the caller a set
        # that LOOKS like a real answer while covering only the few _SECRET_KEYS
        # that happen to be in this process's own environment — every other
        # secret in the file would pass through unredacted, into output whose
        # entire purpose is to be shareable.
        #
        # The realistic trigger is mundane, which is the point: this file is
        # mode 640 root:nemesis, so any reader outside that group gets
        # PermissionError right here. Ordinary group membership, not corruption.
        #
        # best_effort, not record_error: about to raise out of this handler,
        # and a raising recorder here would replace RedactionUnavailable with
        # the error system's own failure.
        _errors_record("E-REDACT-001", {"fn": "_load_secrets",
                                        "error": f"{type(exc).__name__}: {exc}"})
        raise RedactionUnavailable("cannot read %s: %s" % (_ENV_FILE, exc)) from exc
    # Also pull from current process environment (systemd may have loaded them)
    for k in _SECRET_KEYS:
        v = os.environ.get(k, "")
        if v and len(v) >= _MIN_SECRET_LEN:
            secrets.add(v)
    return secrets


def _load_known_names() -> set:
    """Every device/host name this deployment knows, for redaction.

    Raises RedactionUnavailable when the database exists but a query against
    it fails — same fail-closed reasoning as `_load_secrets`, and unlike that
    function's env-file case, there is no legitimate-absent variant here:
    alerts.db is a core, always-present file for a working install (ADR 0001),
    so a connection failure means something is genuinely wrong, not that this
    install simply has no DB-derived names.

    A single TABLE or COLUMN being absent, however, is schema drift, not a
    failure — that source is skipped and the other still contributes real
    coverage, exactly mirroring modules/ai_engine/module.py's
    _known_device_names(), which this deliberately sources the same way.
    """
    names = set()
    try:
        # mode=ro: a bare sqlite3.connect() on a path that does not exist
        # silently CREATES an empty database rather than failing — which would
        # make a missing/misresolved DB path look exactly like "zero devices
        # enrolled", the same failed-read-as-legal-value shape this codebase
        # keeps getting burned by. mode=ro raises instead.
        conn = sqlite3.connect(
            "file:%s?mode=ro" % _DEVICES_DB, uri=True, timeout=5)
        try:
            for table, cols in _DEVICES_TABLES:
                try:
                    have = {r[1] for r in
                            conn.execute("PRAGMA table_info(%s)" % table)}
                except sqlite3.Error:
                    continue
                wanted = [c for c in cols if c in have]
                if not wanted:
                    continue
                rows = conn.execute(
                    "SELECT %s FROM %s" % (", ".join(wanted), table)).fetchall()
                for row in rows:
                    for value in row:
                        if value:
                            names.add(str(value))
        finally:
            conn.close()
    except sqlite3.Error as exc:
        _errors_record("E-REDACT-002", {"fn": "_load_known_names",
                                        "error": f"{type(exc).__name__}: {exc}"})
        raise RedactionUnavailable(
            "cannot read known device/host names from %s: %s"
            % (_DEVICES_DB, exc)) from exc
    return names


def _load_pseudonymize_helpers():
    """(ADDR_RE, is_real_address, scrubbable_names) from nemesis_pseudonymize.

    Deferred, not a top-level import: this module is documented to run
    standalone (see the module docstring) where alert_manager may not yet be
    on sys.path. Reusing that module's already-tested pattern/validation/
    name-filtering rather than re-deriving them here is deliberate (see the
    module docstring) — it is what keeps "what counts as an address / an
    identifying name" from drifting between the two modules over time.

    Raises RedactionUnavailable on failure rather than letting an ImportError
    propagate as a generic crash or — worse — being swallowed somewhere and
    silently skipping the whole address/name pass.
    """
    try:
        _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, os.path.join(_root, "alert_manager"))
        import nemesis_pseudonymize as _pseudo
        return _pseudo.ADDR_RE, _pseudo.is_real_address, _pseudo.scrubbable_names
    except Exception as exc:                      # noqa: BLE001 - re-raised
        _errors_record("E-REDACT-003", {"fn": "_load_pseudonymize_helpers",
                                        "error": f"{type(exc).__name__}: {exc}"})
        raise RedactionUnavailable(
            "cannot load address-matching pattern module: %s" % exc) from exc


def redact(text: str) -> str:
    """Replace all known secrets, device/host names, IP/MAC addresses,
    LAN/mDNS/Tailscale FQDNs, and email addresses in `text` with [REDACTED].

    WITHHOLDS the text entirely if any redaction source could not be
    determined. Under-redacted output is strictly worse than no output: the
    caller believes scrubbing happened either way, and only one of those
    beliefs is survivable.
    """
    if not text:
        return text

    try:
        secrets = _load_secrets()
        raw_names = _load_known_names()
        addr_re, is_real_address, scrubbable_names = _load_pseudonymize_helpers()
    except RedactionUnavailable as exc:
        # Loud, not silent — this is a security-relevant degradation and the
        # operator needs to be able to find it. The returned marker says the
        # same thing to whoever is reading the output itself.
        log.error("redaction unavailable, WITHHOLDING output rather than "
                  "emitting it unscrubbed: %s", exc)
        return _WITHHELD

    # 1. Known secrets — exact literal substring. Runs first: a secret value
    #    could itself contain digits/dots that a later pattern pass might
    #    otherwise partially consume.
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, "[REDACTED]")

    # 2. Known device/host names — longest first, case-insensitive,
    #    boundary-anchored. Mirrors nemesis_pseudonymize.pseudonymize()'s own
    #    name pass, and for the same reason: replacing a SHORTER name first
    #    can strand a distinguishing suffix ("Reception-Laptop" ->
    #    "[REDACTED]-Laptop", a partial leak wearing a redacted label).
    #    Runs before addresses/FQDNs for the same reason nemesis_pseudonymize
    #    does names first: a name can itself contain digits and dots.
    for name in scrubbable_names(raw_names):
        pattern = re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])",
                              re.IGNORECASE)
        text = pattern.sub("[REDACTED]", text)

    # 3. IP / MAC — pattern match, then validated. The validation is what
    #    rejects a version-number-shaped near-miss ("build 1.2.3.4") that the
    #    regex alone would over-redact — same two-stage approach
    #    nemesis_pseudonymize.pseudonymize() uses for the identical reason.
    def _addr_sub(match):
        raw = match.group(0)
        return "[REDACTED]" if is_real_address(raw) else raw
    text = addr_re.sub(_addr_sub, text)

    # 4. LAN/mDNS/Tailscale FQDNs.
    text = _HOSTNAME_SUFFIX_PATTERN.sub("[REDACTED]", text)

    # 5. Email addresses.
    text = _EMAIL_PATTERN.sub("[REDACTED]", text)

    # 6. Key-shaped strings not already caught above (an unknown API key, or
    #    one whose value changed since the env file was last read). Runs last,
    #    as a catch-all: everything before this is a more specific, more
    #    confident match. KNOWN, ACCEPTED OVER-REDACTION RISK, not introduced
    #    by wiring this in — the roadmap doc flagged it before this pattern
    #    was ever active: a bare 32+ char base64-ish run also matches a
    #    legitimate long hash (a SHA-256 hex digest, a git commit hash) with
    #    no way to tell the two apart from the string alone. Fail-closed-on-
    #    ambiguity, same family as the IPv4/version-string tradeoff above —
    #    see test_redact.py for both pinned explicitly.
    text = _KEY_PATTERN.sub("[REDACTED]", text)

    return text


def redact_result(result: dict) -> dict:
    """Apply redaction to the 'output' and 'summary' fields of a check result dict."""
    out = dict(result)
    out["output"] = redact(out.get("output", ""))
    out["summary"] = redact(out.get("summary", ""))
    return out
