"""Domain & IP Lookup — the module wrapper (routes, card, error codes).

All lookup logic lives in `lookup_core.py`, which has no Flask and no DB so it
can be tested directly. This file is the framework half: the NemesisModule
contract, one POST route, the dashboard card, and the error-code recorder.

WHY POST AND NOT GET — this is the route-security decision, made deliberately
    A lookup changes no server state, so the usual "GET-as-write is CSRF-able"
    rule does not obviously apply. It is still POST, for a different reason: a
    GET route would let any page the operator visits trigger appliance-side
    lookups with a plain `<img src="/api/lookup/domain?target=...">`. That does
    not corrupt anything, but it turns the appliance into an unauthenticated
    lookup proxy driven by whoever the operator happens to be browsing, and every
    such lookup emits a real DNS/whois query attributable to this box. POST plus
    the dashboard's default-deny auth gate closes it.

AUTH — by absence, deliberately
    Neither endpoint is added to `_AUTH_EXEMPT`. The dashboard gate covers every
    route including module-registered ones, so absence IS the auth. This is
    recorded explicitly because the standing route audit names the opposite
    mistake — a route intended to be public that is silently swallowed by the
    gate — and the reader should be able to see the decision was made rather than
    inferred.

RULE 8 — this tool's output is addresses BY DESIGN
    Every other diagnostic keeps addresses out of its output. This one exists to
    show them, so redaction would defeat it. What matters instead is that the
    result never reaches an external surface: it is NOT a `diagnostics/` check,
    so `/api/diagnostics/submit` — which emails check output to an external
    support address — cannot sweep it up. Verified: the submit path iterates
    `_diag.CHECKS`, and this module is not in it.
"""

import html
import json
import os
import sys

from flask import jsonify, request

from modules import NemesisModule

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))

# Bare import off alert_manager/, the idiom every service here uses: the
# dashboard unit's PYTHONPATH does not include the repo root.
sys.path.insert(0, os.path.join(_REPO_ROOT, "alert_manager"))




import logging                                                     # noqa: E402
log = logging.getLogger("nemesis.lookup")

MODULE = "lookup"

def _sibling(mod_name):
    """Import a sibling file beside this one, WITHOUT a relative import.

    `modules_loader._load_module` loads module.py via
    `spec_from_file_location("nemesis_module_<name>", ...)` — a top-level module
    with NO parent package — so `from . import x` raises
    "attempted relative import with no known parent package" and the module
    never loads at all.

    Found 2026-08-22 by loading through the REAL loader. It was invisible to
    every earlier check because a direct `spec_from_file_location` import of
    this file (which is how the card render was first verified) DOES give the
    module a resolvable location, so the relative form worked in the test and
    only ever failed in production.
    """
    import importlib.util                                       # noqa: PLC0415
    path = os.path.join(_HERE, mod_name + ".py")
    spec = importlib.util.spec_from_file_location(
        "nemesis_%s_%s" % (MODULE, mod_name), path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load %s from %s" % (mod_name, path))
    sib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sib)
    return sib

core = _sibling("lookup_core")
tls_core = _sibling("tls_core")


# ── Structured error codes ───────────────────────────────────────────────────
# Prefix `E-LOOKUP-` claimed 2026-08-23; verified free against the range-claim
# table in docs/audits/error-code-classification-batch1-2026-08-08.md before use.
# Severities are on nemesis_severity.CANONICAL — register_error_code REFUSES
# anything else rather than coercing it.
#
# Registration is DEFERRED to first use by `make_recorder`, never done at import:
# this module is loaded before the error tables are guaranteed to exist, and a
# failed registration at import would take a diagnostic facility down entirely.
_ERR_CODES = {
    "E-LOOKUP-001": ("dig is not installed; DNS lookups cannot run and the tool "
                     "reports no records for every target",
                     "MEDIUM", "missing-external-binary"),
    "E-LOOKUP-002": ("a DNS lookup timed out; the resolver did not answer within "
                     "the deadline", "LOW", "external-query-timeout"),
    "E-LOOKUP-003": ("whois is not installed; registration and ownership detail "
                     "is unavailable for every domain",
                     "MEDIUM", "missing-external-binary"),
    "E-LOOKUP-004": ("a whois lookup timed out; the registry server did not "
                     "answer within the deadline", "LOW", "external-query-timeout"),
    # Certificate inspection. Separate prefix, verified free before use, because
    # these are a different failure MECHANISM from a DNS/whois miss: a TLS
    # failure is about reaching and reading a certificate, not about a registry
    # answering. Sharing a prefix would put two unrelated mechanisms behind one
    # error class and make `resolve_causes()` ranking meaningless.
    "E-TLS-001": ("a TLS connection timed out before a certificate could be read",
                  "LOW", "external-query-timeout"),
    "E-TLS-002": ("no certificate could be retrieved from the host",
                  "LOW", "tls-unreachable"),
    "E-TLS-003": ("a certificate was retrieved but could not be parsed",
                  "MEDIUM", "tls-unparseable"),
}
_recorder = None


def _errors_record(code, context):
    """Record one structured error occurrence. Never raises into the caller."""
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors                              # noqa: PLC0415
            from modules import get_data_manager               # noqa: PLC0415
            _recorder = nemesis_errors.make_recorder(
                MODULE, lambda: get_data_manager().connect(MODULE),
                _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:                                          # noqa: BLE001
        return None


# ── Routes ───────────────────────────────────────────────────────────────────

def _api_lookup():
    """POST /api/lookup/domain  {target, rrtype} -> the tiered result.

    Returns 400 for a refused target — the operator mistyped something, which is
    not a server error and should not read as one.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    rrtype = (data.get("rrtype") or "A").upper()
    try:
        result = core.lookup_domain(target, rrtype=rrtype)
    except core.LookupRefused as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:                                   # noqa: BLE001
        log.exception("lookup: unexpected failure for %r", target)
        return jsonify({"ok": False, "error": "lookup failed: %s"
                        % type(exc).__name__}), 500

    # Fold any tool-level problems into the error ledger. Reported to the caller
    # too: "whois is not installed" is the difference between "this domain has no
    # owner recorded" and "we could not ask", and the operator must not have to
    # guess which they are looking at.
    for code, detail in result.get("problems", []):
        _errors_record(code, {"fn": "_api_lookup", "target": result["target"]})
    return jsonify({"ok": True, "result": result})


def _api_tls():
    """POST /api/lookup/tls  {host, port} -> the tiered certificate result.

    POST for the same reason as the lookup route, and one more: this opens a TCP
    connection to a host of the caller's choosing. A GET would let any page the
    operator visits cause the appliance to connect outward on their behalf.
    """
    data = request.get_json(silent=True) or {}
    try:
        result = tls_core.inspect_tls(data.get("host", ""), data.get("port"))
    except tls_core.TLSRefused as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:                                   # noqa: BLE001
        log.exception("lookup/tls: unexpected failure")
        return jsonify({"ok": False, "error": "inspection failed: %s"
                        % type(exc).__name__}), 500
    for code, _detail in result.get("problems", []):
        _errors_record(code, {"fn": "_api_tls", "host": result["host"],
                              "port": result["port"]})
    return jsonify({"ok": True, "result": result})


def _api_tls_ports():
    """GET /api/lookup/tls_ports -> the allowlist. No input, returns a constant.

    Served rather than hardcoded in the page so the UI cannot offer a port the
    backend will refuse — and so the allowlist has exactly one definition.
    """
    return jsonify({"ports": list(tls_core.PORT_ALLOWLIST),
                    "default": tls_core.DEFAULT_PORT})


def _api_rrtypes():
    """GET /api/lookup/rrtypes -> the closed set of offered record types.

    A GET is correct here: it takes no input, touches nothing, and returns a
    constant. The set is served rather than hardcoded in the page so the UI
    cannot offer a type the backend will refuse.
    """
    return jsonify({"rrtypes": list(core.RRTYPES)})


# ── Dashboard card ───────────────────────────────────────────────────────────

def _card_html() -> str:
    """The card. Tier-aware via Method 2 (data-attributes), NOT tierText().

    Method 2 is required, not preferred: the result is injected into the DOM
    after page load, and `tierText()` evaluates once at render time, so a result
    built with it would freeze at whatever tier was selected when the page
    loaded. The server sends ALL THREE variants and the browser picks — the tier
    preference lives in `localStorage` and never reaches the server, so a single
    tier-aware string is not possible by design.

    `applyTierText()` MUST be called after every injection or the newly-inserted
    span keeps its placeholder text.
    """
    rrtypes = "".join('<option value="%s">%s</option>' % (t, t)
                      for t in core.RRTYPES)
    # Rendered FROM the allowlist, never hardcoded: the UI must not be able to
    # offer a port `parse_port` will refuse, and the allowlist must have exactly
    # one definition (it is a security boundary — see tls_core).
    ports = "".join(
        '<option value="%d"%s>%d</option>'
        % (p, " selected" if p == tls_core.DEFAULT_PORT else "", p)
        for p in tls_core.PORT_ALLOWLIST)
    return (
        '<div class="card" id="section-lookup">'
        '<h2>&#128269; <span class="tier-text"'
        ' data-beginner="Look Up a Website or Address"'
        ' data-intermediate="Domain &amp; IP Lookup"'
        ' data-pro="Lookup (dig / whois)">Domain &amp; IP Lookup</span></h2>'
        '<p class="tier-text" style="color:#bbb;font-size:0.86em;margin:0 0 10px"'
        ' data-beginner="Type a website address to find out what it is, who owns'
        ' it, and whether your network is already blocking it."'
        ' data-intermediate="Resolve a domain or IP and read its registration'
        ' detail. Read-only — the query runs from this appliance."'
        ' data-pro="dig +answer and whois --. Read-only, appliance-side, no'
        ' remote tasking.">'
        'Resolve a domain or IP and read its registration detail.</p>'
        '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">'
        '<input id="lkTarget" type="text" placeholder="example.com or 192.0.2.5"'
        ' maxlength="253" style="flex:1;min-width:220px;background:#0d1117;'
        'border:1px solid #00d4ff;color:#eee;padding:6px;border-radius:3px">'
        '<select id="lkType" style="background:#0d1117;border:1px solid #333;'
        'color:#eee;padding:6px;border-radius:3px">' + rrtypes + '</select>'
        '<button onclick="lkRun()" style="background:#00d4ff;color:#1a1a2e;'
        'border:none;padding:6px 16px;cursor:pointer;border-radius:3px;'
        'font-weight:bold">Look up</button>'
        '</div>'
        '<div id="lkStatus" style="font-size:0.82em;color:#bbb;margin-top:6px"></div>'
        '<div id="lkResult" style="margin-top:10px"></div>'

        # ── Certificate inspection ───────────────────────────────────────────
        # Same card, second tool: an operator investigating a host wants both
        # questions in one place, and splitting them into two cards would make
        # "what is this host, and is its certificate sound" a two-stop journey.
        '<hr style="border:0;border-top:1px solid #222;margin:14px 0">'
        '<h3 style="font-size:0.95em;margin:0 0 6px"><span class="tier-text"'
        ' data-beginner="Check a Site&#39;s Security Certificate"'
        ' data-intermediate="TLS Certificate Inspection"'
        ' data-pro="TLS: cert, chain, SAN, expiry">TLS Certificate Inspection</span></h3>'
        '<p class="tier-text" style="color:#bbb;font-size:0.86em;margin:0 0 8px"'
        ' data-beginner="See whether a website&#39;s security certificate is still'
        ' in date and whether your machine actually trusts it."'
        ' data-intermediate="Reads the presented certificate and separately tests'
        ' whether the chain validates."'
        ' data-pro="Unverified read for cert detail; separate verifying connect'
        ' for the trust verdict. Allowlisted TLS ports only.">'
        'Check a certificate&#39;s expiry, issuer and trust.</p>'
        '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">'
        '<input id="tlsHost" type="text" placeholder="example.com"'
        ' maxlength="253" style="flex:1;min-width:220px;background:#0d1117;'
        'border:1px solid #00d4ff;color:#eee;padding:6px;border-radius:3px">'
        '<select id="tlsPort" style="background:#0d1117;border:1px solid #333;'
        'color:#eee;padding:6px;border-radius:3px">' + ports + '</select>'
        '<button onclick="tlsRun()" style="background:#00d4ff;color:#1a1a2e;'
        'border:none;padding:6px 16px;cursor:pointer;border-radius:3px;'
        'font-weight:bold">Check certificate</button>'
        '</div>'
        '<div id="tlsStatus" style="font-size:0.82em;color:#bbb;margin-top:6px"></div>'
        '<div id="tlsResult" style="margin-top:10px"></div>'
        '</div>'
    )


def _card_js() -> str:
    """The card's script. Kept separate so the quoting rules are easy to see.

    #1 RECURRING BUG in this codebase: JS string literals inside Python
    f-strings. This function returns a PLAIN string (no f-prefix, no
    interpolation) and every JS string uses single quotes, so there is nothing
    for an apostrophe or a brace to break. Values from the server are inserted
    via textContent / setAttribute, never by string-concatenating HTML.
    """
    return """
<script>
function lkEsc(s) { return (s === null || s === undefined) ? '' : String(s); }

function lkRun() {
    var target = document.getElementById('lkTarget').value;
    var rrtype = document.getElementById('lkType').value;
    var status = document.getElementById('lkStatus');
    var out = document.getElementById('lkResult');
    out.innerHTML = '';
    if (!target.trim()) { status.textContent = 'Enter a domain or IP address.'; return; }
    status.textContent = 'Looking up ' + target + '...';
    fetch('/api/lookup/domain', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target, rrtype: rrtype})
    }).then(function (r) {
        return r.json().then(function (d) { return {ok: r.ok, body: d}; });
    }).then(function (res) {
        if (!res.ok || !res.body.ok) {
            status.textContent = res.body.error || 'Lookup failed.';
            return;
        }
        status.textContent = '';
        lkRender(res.body.result);
    }).catch(function (e) {
        status.textContent = 'Lookup failed: ' + e;
    });
}

function lkRender(r) {
    var out = document.getElementById('lkResult');
    out.innerHTML = '';

    // The tiered explanation. Method 2: all three variants ride along as
    // data-attributes and the browser picks. The element's initial text is the
    // intermediate variant so the card reads correctly even if tier.js is slow.
    var span = document.createElement('span');
    span.className = 'tier-text';
    span.setAttribute('data-beginner', lkEsc(r.explanation.beginner));
    span.setAttribute('data-intermediate', lkEsc(r.explanation.intermediate));
    span.setAttribute('data-pro', lkEsc(r.explanation.pro));
    span.textContent = lkEsc(r.explanation.intermediate);
    span.style.whiteSpace = 'pre-wrap';

    var box = document.createElement('div');
    box.style.cssText = 'background:#0d0d1e;border:1px solid #222;border-radius:8px;'
        + 'padding:10px 12px;font-size:0.86em;line-height:1.5';
    box.appendChild(span);
    out.appendChild(box);

    if (r.problems && r.problems.length) {
        var warn = document.createElement('div');
        warn.style.cssText = 'color:#ffcc00;font-size:0.82em;margin-top:6px';
        warn.textContent = r.problems.map(function (p) { return p[1]; }).join('; ');
        out.appendChild(warn);
    }

    // MUST run after injection, or the span keeps its placeholder text and the
    // beginner/pro variants never appear. This is the whole reason Method 2 is
    // used here rather than tierText().
    if (window.applyTierText) { window.applyTierText(); }
}

function tlsRun() {
    var host = document.getElementById('tlsHost').value;
    var port = document.getElementById('tlsPort').value;
    var status = document.getElementById('tlsStatus');
    var out = document.getElementById('tlsResult');
    out.innerHTML = '';
    if (!host.trim()) { status.textContent = 'Enter a hostname.'; return; }
    status.textContent = 'Checking the certificate for ' + host + '...';
    fetch('/api/lookup/tls', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({host: host, port: port})
    }).then(function (r) {
        return r.json().then(function (d) { return {ok: r.ok, body: d}; });
    }).then(function (res) {
        if (!res.ok || !res.body.ok) {
            status.textContent = res.body.error || 'Certificate check failed.';
            return;
        }
        status.textContent = '';
        tlsRender(res.body.result);
    }).catch(function (e) {
        status.textContent = 'Certificate check failed: ' + e;
    });
}

function tlsRender(r) {
    var out = document.getElementById('tlsResult');
    out.innerHTML = '';

    // Method 2 again: all three variants ride as data-attributes and the browser
    // picks. tierText() would freeze at page-render time, and this result is
    // injected long after that.
    var span = document.createElement('span');
    span.className = 'tier-text';
    span.setAttribute('data-beginner', lkEsc(r.explanation.beginner));
    span.setAttribute('data-intermediate', lkEsc(r.explanation.intermediate));
    span.setAttribute('data-pro', lkEsc(r.explanation.pro));
    span.textContent = lkEsc(r.explanation.intermediate);
    span.style.whiteSpace = 'pre-wrap';

    // The border colour carries the verdict at a glance. Expired or untrusted is
    // red; expiring soon is amber; anything we could not determine is amber too,
    // deliberately — 'unknown' must never render as the same green as 'fine'.
    var colour = '#4caf50';
    if (r.expiry_bucket === 'expired' || r.validates === false) { colour = '#ff4444'; }
    else if (r.expiry_bucket === 'expiring_soon' || r.expiry_bucket === 'unknown'
             || r.validates === null) { colour = '#ffcc00'; }

    var box = document.createElement('div');
    box.style.cssText = 'background:#0d0d1e;border:1px solid ' + colour + ';'
        + 'border-radius:8px;padding:10px 12px;font-size:0.86em;line-height:1.5';
    box.appendChild(span);
    out.appendChild(box);

    if (r.problems && r.problems.length) {
        var warn = document.createElement('div');
        warn.style.cssText = 'color:#ffcc00;font-size:0.82em;margin-top:6px';
        warn.textContent = r.problems.map(function (p) { return p[1]; }).join('; ');
        out.appendChild(warn);
    }

    // MUST run after injection — same reason as lkRender.
    if (window.applyTierText) { window.applyTierText(); }
}

// Re-apply when the operator changes tier while a result is on screen.
// NOTE: window.onTierChange is a single global slot — assigning it blindly would
// clobber another page's handler. Chained instead.
(function () {
    var prev = window.onTierChange;
    window.onTierChange = function () {
        if (typeof prev === 'function') { prev(); }
        if (window.applyTierText) { window.applyTierText(); }
    };
})();
</script>
"""


class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)

    def start(self) -> None:
        # Nothing to start: every lookup is driven by an operator request. The
        # binaries are checked lazily so a missing one is reported per-lookup as
        # a structured error rather than preventing the module from loading.
        log.info("lookup: enabled (read-only, operator-driven)")

    def stop(self) -> None:
        log.info("lookup: disabled")

    def status(self) -> dict:
        missing = [b for b in ("dig", "whois")
                   if core._run([b, "--version"])[0] == 127]
        if missing:
            return {"running": True,
                    "detail": "missing: %s — lookups will be incomplete"
                              % ", ".join(missing)}
        return {"running": True, "detail": "dig and whois available"}

    def get_dashboard_card(self) -> str:
        try:
            return _card_html() + _card_js()
        except Exception as exc:                               # noqa: BLE001
            log.exception("lookup: card render failed")
            return ('<div class="card"><h2>&#128269; Domain &amp; IP Lookup</h2>'
                    '<p style="color:#888">Unavailable: %s</p></div>'
                    % html.escape(str(exc), quote=True))

    def get_routes(self):
        # POST for the lookup (see the module docstring), GET for the constant.
        # Neither is added to _AUTH_EXEMPT — the dashboard's default-deny gate
        # covers module routes, so absence is the auth.
        return [
            ("/api/lookup/domain", _api_lookup, {"methods": ["POST"]}),
            ("/api/lookup/rrtypes", _api_rrtypes, {"methods": ["GET"]}),
            ("/api/lookup/tls", _api_tls, {"methods": ["POST"]}),
            ("/api/lookup/tls_ports", _api_tls_ports, {"methods": ["GET"]}),
        ]
