"""Sensitive-value redaction for diagnostic output.

Reads /etc/nemesis.env at call time (not at import time) so it always uses
the current on-disk values.  Any non-empty env value longer than 7 characters
is treated as a secret and replaced with [REDACTED] in output text.
"""

import os
import re

_ENV_FILE = "/etc/nemesis.env"
_MIN_SECRET_LEN = 8

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
    except Exception:
        pass
    # Also pull from current process environment (systemd may have loaded them)
    for k in _SECRET_KEYS:
        v = os.environ.get(k, "")
        if v and len(v) >= _MIN_SECRET_LEN:
            secrets.add(v)
    return secrets


def redact(text: str) -> str:
    """Replace all known secret values in `text` with [REDACTED]."""
    if not text:
        return text
    for secret in _load_secrets():
        if secret in text:
            text = text.replace(secret, "[REDACTED]")
    return text


def redact_result(result: dict) -> dict:
    """Apply redaction to the 'output' and 'summary' fields of a check result dict."""
    out = dict(result)
    out["output"] = redact(out.get("output", ""))
    out["summary"] = redact(out.get("summary", ""))
    return out
