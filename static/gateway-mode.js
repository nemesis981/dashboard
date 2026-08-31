/* Gateway Mode switch control.
 *
 * WHY THIS IS A FILE AND NOT INLINE MARKUP FROM dashboard.py.
 * The dashboard renders HTML from Python f-strings, and the single most common
 * defect in this codebase is an apostrophe or quote inside embedded JS breaking
 * the render with a silent SyntaxError. core/gateway_mode.py's capability table
 * carries no JS at all for exactly that reason. This control needs behaviour, so
 * the behaviour lives here where no f-string can ever touch it.
 *
 * What this is NOT: a security control. Every decision that matters is made by
 * nemesis-fwd -- that the interface exists, that the CIDR is private IPv4, and
 * whether the credential is real. The confirm dialog below is a courtesy against
 * a mis-click, not a gate.
 */
(function () {
    "use strict";

    function _status(msg, bad) {
        var el = document.getElementById("gwStatus");
        if (!el) { return; }
        el.textContent = msg;
        el.style.color = bad ? "#e06c6c" : "#8fbf8f";
    }

    function _post(enable, iface, cidr, password) {
        return fetch("/api/gateway/switch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                enable: enable, iface: iface, cidr: cidr, password: password
            })
        }).then(function (r) {
            return r.json().then(function (d) { return { ok: r.ok, data: d }; });
        });
    }

    window.gwSwitch = function (enable) {
        var iface = "", cidr = "";
        if (enable) {
            var ifEl = document.getElementById("gwIface");
            var cdEl = document.getElementById("gwCidr");
            iface = ifEl ? ifEl.value.trim() : "";
            cidr = cdEl ? cdEl.value.trim() : "";
            if (!iface || !cidr) {
                _status("Both the LAN interface and its CIDR are required.", true);
                return;
            }
        }

        /* This re-roles the box's network stack. Say so plainly before doing it. */
        var warn = enable
            ? "Enable Gateway Mode?\n\nThis turns on IP forwarding and installs a "
              + "source-NAT rule for " + cidr + " leaving any interface other than "
              + iface + ".\n\nIf this box is not actually the gateway for that "
              + "network, devices may lose connectivity."
            : "Disable Gateway Mode?\n\nForwarding stops first, then the NAT rule is "
              + "removed. Anything currently routing through this box will lose its "
              + "path out.";
        if (!window.confirm(warn)) { return; }

        _status("Waiting for admin password…", false);
        window.fwPrompt(enable ? "enable Gateway Mode" : "disable Gateway Mode")
            .then(function (password) {
                if (!password) { _status("Cancelled. Nothing was changed.", false); return; }
                _status("Switching… this takes a few seconds.", false);
                return _post(enable, iface, cidr, password).then(function (res) {
                    var d = res.data || {};
                    if (res.ok && d.ok) {
                        _status(d.reason || "Done.", false);
                        setTimeout(function () { window.location.reload(); }, 1200);
                        return;
                    }
                    /* A failed switch is not a generic error: the helper reports
                       which step failed and whether the box was measurably put
                       back. "restored" and "NOT restored" need different
                       responses from the operator, so never flatten them. */
                    if (d.phase && d.reason) {
                        var restored = (d.restored === false)
                            ? " — THE PRIOR STATE WAS NOT RESTORED. Manual recovery needed."
                            : " (prior state restored)";
                        _status("Failed at " + d.phase + ": " + d.reason
                                + (d.phase === "plan" ? "" : restored), true);
                        return;
                    }
                    if (window.fwHandleError) {
                        window.fwHandleError(d, "Gateway switch failed.");
                    }
                    _status(d.error || "Gateway switch failed.", true);
                });
            })
            .catch(function (e) {
                _status("Gateway switch failed: " + e, true);
            });
    };
}());
