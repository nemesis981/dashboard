"""Device Reachability — the module wrapper (routes, card, error codes).

All probe logic lives in `probe_core.py`, which has no Flask and no live DB so
it can be tested directly. This file is the framework half.

WHY THIS IS A SEPARATE MODULE FROM `lookup`
    `lookup` documents itself as read-only: it queries from the appliance and
    tasks no remote machine. Ping and traceroute break that — they emit packets
    at a chosen host. Folding them in would have made that module's central
    safety claim a comment rather than a fact. Two modules keeps each claim
    literally true and lets an operator disable the active one alone.

THE SECURITY MODEL — the TARGET is constrained, because the CALLER cannot be
    The diagnostics master plan gates anything that tasks a remote machine
    behind an authorization + consent layer. That layer does not exist:
    `require_role` / `ROLE_*` / `is_admin` return nothing repo-wide, and the
    dashboard gate is binary — logged in or not. So the control that IS
    available is applied instead: `authorise()` refuses any target absent from
    the LAN inventory or the enrolled-agent list, before anything reaches a
    subprocess. An operator can ping their own printer; nobody can point this at
    the internet.

    This is a real constraint, not a fig leaf, but it is also NOT the same
    control the master plan asks for, and it is not sufficient for every tool:
    port scanning and packet capture are deliberately absent (a port scan
    against a known host is still a port scan). See the handoff's separated open
    item on the gating-layer decision.

WHY POST, AND WHY THE TARGET LIST IS A GET
    Both probe routes are POST. Unlike lookup — where POST was about not
    becoming an unauthenticated lookup proxy — here a GET would let any page the
    operator visits make the appliance emit packets at a LAN device via a plain
    `<img src=...>`. The target constraint bounds the damage; POST plus the
    default-deny gate removes the trigger. `/api/netprobe/targets` is a GET: it
    takes no input and reads state.

AUTH — by absence, deliberately
    No endpoint here is added to `_AUTH_EXEMPT`. The dashboard gate covers every
    route including module-registered ones, so absence IS the auth. Recorded
    explicitly because the standing route audit names the opposite mistake — a
    route intended to be public that the gate silently swallows.

RULE 8 — this tool's output names devices BY DESIGN
    A reachability result is about a specific device, so redaction would defeat
    it. What matters is that it never reaches an external surface: this is NOT a
    `diagnostics/` check, so `/api/diagnostics/submit` — which emails check
    output to an external support address — cannot sweep it up. Verified: that
    path iterates `_diag.CHECKS`, and this module is not in it.
"""

import html
import logging
import os
import sys

from flask import jsonify, request

from modules import NemesisModule, get_data_manager

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))

# Bare import off alert_manager/, the idiom every service here uses: the
# dashboard unit's PYTHONPATH does not include the repo root.
sys.path.insert(0, os.path.join(_REPO_ROOT, "alert_manager"))



log = logging.getLogger("nemesis.netprobe")

MODULE = "netprobe"

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

core = _sibling("probe_core")


# ── Structured error codes ───────────────────────────────────────────────────
# Prefix `E-NETPROBE-` claimed 2026-08-22; verified free against the range-claim
# tables in docs/audits/error-code-classification-batch{1,2,3}-2026-08-08.md
# before use. Severities are on nemesis_severity.CANONICAL — register_error_code
# REFUSES anything else rather than coercing it.
#
# Registration is DEFERRED to first use by `make_recorder`, never done at import:
# this module loads before the error tables are guaranteed to exist, and a failed
# registration at import would take the facility down entirely.
_ERR_CODES = {
    "E-NETPROBE-001": ("ping is not installed; reachability cannot be tested and "
                       "every device reports as untestable",
                       "MEDIUM", "missing-external-binary"),
    "E-NETPROBE-002": ("a ping probe exceeded its deadline without returning",
                       "LOW", "probe-timeout"),
    "E-NETPROBE-003": ("neither mtr nor traceroute is installed; path tracing is "
                       "unavailable", "MEDIUM", "missing-external-binary"),
    # 004/005 are distinct MECHANISMS, deliberately not one code: a trace that
    # timed out is a slow path; an unreadable inventory is a broken appliance
    # refusing every probe. Sharing a code would make resolve_causes() ranking
    # meaningless -- the same reason lookup split E-TLS- off from E-LOOKUP-.
    "E-NETPROBE-005": ("a path trace exceeded its deadline without completing",
                       "LOW", "probe-timeout"),
    "E-NETPROBE-004": ("the device inventory could not be read, so no probe "
                       "target could be authorised and all probes were refused",
                       "HIGH", "inventory-unreadable"),
}
_recorder = None


def _errors_record(code, context):
    """Record one structured error occurrence. Never raises into the caller."""
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors                              # noqa: PLC0415
            _recorder = nemesis_errors.make_recorder(
                MODULE, lambda: get_data_manager().connect(MODULE),
                _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:                                          # noqa: BLE001
        return None


def _conn():
    return get_data_manager().connect(MODULE)


# ── Routes ───────────────────────────────────────────────────────────────────

def _probe(kind):
    """Shared body for both probe routes — one authorisation path, not two.

    Two routes with two copies of the security check is the exact divergence
    shape the standing route audit treats as a finding in itself, independent of
    whether either copy looks wrong. There is one copy.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    try:
        runner = core.run_ping if kind == "ping" else core.run_trace
        result = runner(target, _conn())
    except core.ProbeRefused as exc:
        # 400, not 403: the operator picked something not on the list, which is
        # a bad request rather than a privilege failure. Nothing was sent.
        return jsonify({"ok": False, "error": str(exc)}), 400
    except core.InventoryUnavailable as exc:
        # Fail closed and say so. This is NOT "the device is unknown" — the
        # difference matters, because one is a typo and the other is a broken
        # appliance that is currently refusing every probe.
        _errors_record("E-NETPROBE-004", {"fn": "_probe", "kind": kind})
        return jsonify({"ok": False, "error": str(exc)}), 503
    except Exception as exc:                                   # noqa: BLE001
        log.exception("netprobe: unexpected failure (%s)", kind)
        return jsonify({"ok": False, "error": "probe failed: %s"
                        % type(exc).__name__}), 500

    for code, _detail in result.get("problems", []):
        _errors_record(code, {"fn": "_probe", "kind": kind,
                              "source": result.get("source")})
    return jsonify({"ok": True, "result": result})


def _api_ping():
    """POST /api/netprobe/ping  {target} -> the tiered reachability result."""
    return _probe("ping")


def _api_trace():
    """POST /api/netprobe/trace  {target} -> the tiered path result."""
    return _probe("trace")


def _api_targets():
    """GET /api/netprobe/targets -> the devices a probe may be aimed at.

    Served rather than built in the page so the UI cannot offer a target the
    backend will refuse, and so the permitted set has exactly one definition —
    `load_inventory()`. A dropdown built from this list makes the constraint
    visible to the operator instead of surfacing only as a rejection.

    Returns 503 rather than an empty list when the inventory cannot be read. An
    empty list would render as "no devices" — indistinguishable from a genuinely
    empty inventory, and the exact defaults-that-mean-something shape this
    codebase keeps finding.
    """
    try:
        inv = core.load_inventory(_conn())
    except core.InventoryUnavailable as exc:
        _errors_record("E-NETPROBE-004", {"fn": "_api_targets"})
        return jsonify({"ok": False, "error": str(exc)}), 503

    seen, out = set(), []
    for _ident, (ip, source, label) in sorted(inv.items()):
        if ip in seen:
            continue
        seen.add(ip)
        out.append({"ip": ip, "label": label, "source": source})
    return jsonify({"ok": True, "targets": out})


# ── Dashboard card ───────────────────────────────────────────────────────────

def _card_html() -> str:
    """The card. Tier-aware via Method 2 (data-attributes), NOT tierText().

    Method 2 is required, not preferred: results are injected into the DOM after
    page load, and `tierText()` evaluates once at render time, so a result built
    with it would freeze at whatever tier was selected when the page loaded. The
    server sends ALL THREE variants and the browser picks — the tier preference
    lives in `localStorage` and never reaches the server.

    `applyTierText()` MUST be called after every injection or the newly-inserted
    span keeps its placeholder text.

    The target control is a SELECT populated from `/api/netprobe/targets`, not a
    text input. That is a UX decision carrying a security intent: the operator
    sees the permitted set rather than discovering it by being refused, and the
    page cannot offer something `authorise()` will reject.
    """
    return (
        '<div class="card" id="section-netprobe">'
        '<h2>&#128225; <span class="tier-text"'
        ' data-beginner="Check if a Device is Responding"'
        ' data-intermediate="Device Reachability"'
        ' data-pro="Reachability (ping / mtr)">Device Reachability</span></h2>'
        '<p class="tier-text" style="color:#bbb;font-size:0.86em;margin:0 0 10px"'
        ' data-beginner="Pick one of your devices to see whether it is switched'
        ' on and responding, and how quickly. You can only pick devices this'
        ' system already knows about."'
        ' data-intermediate="Test reachability and path to a device on your'
        ' network. Targets are limited to the LAN inventory and enrolled agents."'
        ' data-pro="ping -c4 / mtr --report, bounded. Target space restricted to'
        ' inventory + enrolled agents; arbitrary hosts refused pre-exec.">'
        'Test reachability and path to a device on your network.</p>'
        '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">'
        '<select id="npTarget" style="flex:1;min-width:240px;background:#0d1117;'
        'border:1px solid #00d4ff;color:#eee;padding:6px;border-radius:3px">'
        '<option value="">Loading devices...</option></select>'
        '<button onclick="npRun(&#39;ping&#39;)" style="background:#00d4ff;'
        'color:#1a1a2e;border:none;padding:6px 16px;cursor:pointer;'
        'border-radius:3px;font-weight:bold">Test response</button>'
        '<button onclick="npRun(&#39;trace&#39;)" style="background:#0d1117;'
        'color:#00d4ff;border:1px solid #00d4ff;padding:6px 16px;cursor:pointer;'
        'border-radius:3px">Trace path</button>'
        '</div>'
        '<div id="npStatus" style="font-size:0.82em;color:#bbb;margin-top:6px"></div>'
        '<div id="npResult" style="margin-top:10px"></div>'
        '<p class="tier-text" style="color:#666;font-size:0.78em;margin:10px 0 0"'
        ' data-beginner="This only works on your own devices — it cannot be'
        ' pointed at anything else on the internet."'
        ' data-intermediate="Only devices listed above can be probed; arbitrary'
        ' addresses are refused."'
        ' data-pro="Target allowlist is enforced server-side in authorise(),'
        ' before exec. UI restriction is convenience, not the control.">'
        'Only devices listed above can be probed.</p>'
        '</div>'
    )


def _card_js() -> str:
    """The card's script.

    #1 RECURRING BUG in this codebase: JS string literals inside Python
    f-strings. This returns a PLAIN string — no f-prefix, no interpolation — and
    every JS string uses single quotes, so there is nothing an apostrophe or a
    brace can break. Server values are inserted via textContent / setAttribute,
    never by string-concatenating HTML.
    """
    return """
<script>
function npEsc(s) { return (s === null || s === undefined) ? '' : String(s); }

function npLoadTargets() {
    var sel = document.getElementById('npTarget');
    if (!sel) { return; }
    fetch('/api/netprobe/targets').then(function (r) {
        return r.json().then(function (d) { return {ok: r.ok, body: d}; });
    }).then(function (res) {
        sel.innerHTML = '';
        if (!res.ok || !res.body.ok) {
            // An unreadable inventory must NOT render as an empty device list.
            // Empty reads as 'you have no devices'; this reads as 'we could not
            // ask', which is what actually happened.
            var bad = document.createElement('option');
            bad.value = '';
            bad.textContent = res.body.error || 'Device list unavailable';
            sel.appendChild(bad);
            sel.disabled = true;
            return;
        }
        sel.disabled = false;
        if (!res.body.targets.length) {
            var none = document.createElement('option');
            none.value = '';
            none.textContent = 'No devices known yet';
            sel.appendChild(none);
            return;
        }
        res.body.targets.forEach(function (t) {
            var o = document.createElement('option');
            o.value = t.ip;
            o.textContent = npEsc(t.label) + ' (' + npEsc(t.ip) + ')'
                + (t.source === 'enrolled-agent' ? ' - agent' : '');
            sel.appendChild(o);
        });
    }).catch(function (e) {
        sel.innerHTML = '';
        var bad = document.createElement('option');
        bad.value = '';
        bad.textContent = 'Device list unavailable: ' + e;
        sel.appendChild(bad);
        sel.disabled = true;
    });
}

function npRun(kind) {
    var target = document.getElementById('npTarget').value;
    var status = document.getElementById('npStatus');
    var out = document.getElementById('npResult');
    out.innerHTML = '';
    if (!target) { status.textContent = 'Pick a device first.'; return; }
    status.textContent = (kind === 'ping' ? 'Testing ' : 'Tracing the path to ')
        + target + '...';
    fetch('/api/netprobe/' + kind, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target})
    }).then(function (r) {
        return r.json().then(function (d) { return {ok: r.ok, body: d}; });
    }).then(function (res) {
        if (!res.ok || !res.body.ok) {
            status.textContent = res.body.error || 'Probe failed.';
            return;
        }
        status.textContent = '';
        npRender(res.body.result);
    }).catch(function (e) {
        status.textContent = 'Probe failed: ' + e;
    });
}

function npRender(r) {
    var out = document.getElementById('npResult');
    out.innerHTML = '';

    // Method 2: all three variants ride along as data-attributes and the browser
    // picks. The initial text is the intermediate variant so the card still
    // reads correctly if tier.js is slow.
    var span = document.createElement('span');
    span.className = 'tier-text';
    span.setAttribute('data-beginner', npEsc(r.explanation.beginner));
    span.setAttribute('data-intermediate', npEsc(r.explanation.intermediate));
    span.setAttribute('data-pro', npEsc(r.explanation.pro));
    span.textContent = npEsc(r.explanation.intermediate);
    span.style.whiteSpace = 'pre-wrap';

    // Colour carries the verdict at a glance. A probe we could not RUN is amber,
    // never the same red as a device that genuinely did not answer -- those are
    // different findings and must not look identical.
    var colour = '#4caf50';
    if (r.verdict === 'unreachable') { colour = '#ff4444'; }
    else if (r.verdict === 'degraded') { colour = '#ffcc00'; }
    else if (r.verdict === 'untested') { colour = '#ffcc00'; }

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

    // MUST run after injection, or the span keeps its placeholder text and the
    // beginner/pro variants never appear.
    if (window.applyTierText) { window.applyTierText(); }
}

// Re-apply when the operator changes tier while a result is on screen.
// window.onTierChange is a single global slot -- assigning it blindly would
// clobber another card's handler. Chained instead.
(function () {
    var prev = window.onTierChange;
    window.onTierChange = function () {
        if (typeof prev === 'function') { prev(); }
        if (window.applyTierText) { window.applyTierText(); }
    };
})();

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', npLoadTargets);
} else {
    npLoadTargets();
}
</script>
"""


class Module(NemesisModule):

    def start(self) -> None:
        # Nothing to start: every probe is driven by an operator request. The
        # binaries are checked lazily so a missing one is reported per-probe as a
        # structured error rather than preventing the module from loading.
        log.info("netprobe: enabled (operator-driven, inventory-restricted)")

    def stop(self) -> None:
        log.info("netprobe: disabled")

    def status(self) -> dict:
        have_ping = core._run(["ping", "-V"], 5)[0] != 127
        trace = core.available_trace_tool()
        if not have_ping and trace is None:
            return {"running": True,
                    "detail": "ping and traceroute both missing — no probe can run"}
        if not have_ping:
            return {"running": True, "detail": "ping missing; path tracing only"}
        if trace is None:
            return {"running": True, "detail": "no traceroute/mtr; ping only"}
        return {"running": True, "detail": "ping and %s available" % trace}

    def get_dashboard_card(self) -> str:
        try:
            return _card_html() + _card_js()
        except Exception as exc:                               # noqa: BLE001
            log.exception("netprobe: card render failed")
            return ('<div class="card"><h2>&#128225; Device Reachability</h2>'
                    '<p style="color:#888">Unavailable: %s</p></div>'
                    % html.escape(str(exc), quote=True))

    def get_routes(self):
        # POST for anything that emits packets (see the module docstring), GET
        # for the target list, which only reads. None is added to _AUTH_EXEMPT —
        # the dashboard's default-deny gate covers module routes, so absence is
        # the auth.
        return [
            ("/api/netprobe/ping", _api_ping, {"methods": ["POST"]}),
            ("/api/netprobe/trace", _api_trace, {"methods": ["POST"]}),
            ("/api/netprobe/targets", _api_targets, {"methods": ["GET"]}),
        ]
