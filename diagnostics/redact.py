"""Sensitive-value redaction for diagnostic output.

Reads /etc/nemesis.env at call time (not at import time) so it always uses
the current on-disk values.  Any non-empty env value longer than 7 characters
is treated as a secret and replaced with [REDACTED] in output text.
"""

import logging
import os
import re

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
    """The secret list could not be determined, so nothing can be certified scrubbed.

    Distinct from "there are no secrets": an empty set is a real answer, this is
    the absence of one. Raised only when the env file EXISTS but could not be
    read — an absent file genuinely means no file-derived secrets.
    """


# Returned instead of under-redacted text. Deliberately long and unmistakable:
# the failure mode this replaces was silent, and a subtle marker would just be
# the same problem in a different font.
_WITHHELD = ("[OUTPUT WITHHELD — redaction unavailable: the secret list could not be read, "
             "so this text cannot be certified free of secrets. Check that the reading "
             "process can read /etc/nemesis.env (mode 640 root:nemesis); see the "
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


def _load_secrets() -> set:
    """The set of values `redact()` will strip.

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


def redact(text: str) -> str:
    """Replace all known secret values in `text` with [REDACTED].

    WITHHOLDS the text entirely if the secret list could not be determined.
    Under-redacted output is strictly worse than no output: the caller believes
    scrubbing happened either way, and only one of those beliefs is survivable.
    """
    if not text:
        return text
    try:
        secrets = _load_secrets()
    except RedactionUnavailable as exc:
        # Loud, not silent — this is a security-relevant degradation and the
        # operator needs to be able to find it. The returned marker says the
        # same thing to whoever is reading the output itself.
        log.error("redaction unavailable, WITHHOLDING output rather than "
                  "emitting it unscrubbed: %s", exc)
        return _WITHHELD
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, "[REDACTED]")
    return text


def redact_result(result: dict) -> dict:
    """Apply redaction to the 'output' and 'summary' fields of a check result dict."""
    out = dict(result)
    out["output"] = redact(out.get("output", ""))
    out["summary"] = redact(out.get("summary", ""))
    return out
