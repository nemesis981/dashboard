/* Shared admin-credential prompt for privileged actions.
 *
 * Extracted from dashboard.py on 2026-07-31. It previously existed only inside
 * dashboard()'s rendered template, which meant settings_page() could not reach
 * it — and settings_page() is where Settings-save and Restart live, both of
 * which became privileged operations when they moved to the nemesis-fwd helper.
 *
 * Duplicating a password dialog is the wrong answer: two copies drift, and the
 * one that drifts is the one that stops clearing the field or stops handling a
 * refusal correctly. One file, loaded by both templates.
 *
 * The modal markup is injected by this script rather than pasted into each
 * template, for the same reason. Nothing to keep in sync.
 *
 * What this is NOT: a security control. The password is verified by nemesis-fwd
 * against the stored bcrypt hash, in a separate process. This is only the way a
 * human supplies it — a compromised page can bypass this dialog entirely and
 * still gets nowhere without the actual password.
 */
(function () {
    var _fwCredResolve = null;

    function _ensureModal() {
        if (document.getElementById("fwCredModal")) return;
        var d = document.createElement("div");
        d.id = "fwCredModal";
        d.setAttribute("onclick", "if(event.target===this)fwCredCancel()");
        d.style.cssText = "display:none;position:fixed;top:0;left:0;width:100%;" +
                          "height:100%;background:rgba(0,0,0,0.75);z-index:2000";
        d.innerHTML =
            '<div style="background:#0d1117;border:1px solid #1e2d4e;border-radius:8px;' +
                 'padding:24px;max-width:420px;margin:12% auto;position:relative">' +
              '<h3>&#128274; Confirm Admin Password</h3>' +
              '<p id="fwCredWhat" style="color:#ccc;font-size:0.9em;margin:4px 0 10px"></p>' +
              '<label style="color:#aaa;font-size:0.85em">Admin password</label>' +
              '<input type="password" id="fwCredInput" autocomplete="current-password" ' +
                     'placeholder="Password" ' +
                     'style="width:100%;padding:8px;margin-top:4px;background:#161b22;' +
                            'color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-size:1em" ' +
                     'onkeydown="if(event.key===\'Enter\')fwCredOk();' +
                                'if(event.key===\'Escape\')fwCredCancel()">' +
              '<p id="fwCredErr" style="color:#ff6666;font-size:0.85em;min-height:1.1em;margin:6px 0 0"></p>' +
              '<div style="margin-top:16px;display:flex;gap:8px">' +
                '<button type="button" onclick="fwCredOk()" ' +
                        'style="background:#1f6feb;color:#fff;border:none;border-radius:4px;' +
                               'padding:8px 18px;font-size:0.95em;cursor:pointer">Confirm</button>' +
                '<button type="button" onclick="fwCredCancel()" ' +
                        'style="background:#30363d;color:#e6edf3;border:none;border-radius:4px;' +
                               'padding:8px 18px;font-size:0.95em;cursor:pointer">Cancel</button>' +
              '</div>' +
            '</div>';
        document.body.appendChild(d);
    }

    function _close() {
        var m = document.getElementById("fwCredModal");
        if (m) m.style.display = "none";
        /* Never leave the password sitting in the DOM. */
        var i = document.getElementById("fwCredInput");
        if (i) i.value = "";
    }

    window.fwPrompt = function (actionLabel) {
        _ensureModal();
        document.getElementById("fwCredWhat").textContent =
            "This action requires re-entering your admin password: " + actionLabel + ".";
        document.getElementById("fwCredErr").textContent = "";
        var inp = document.getElementById("fwCredInput");
        inp.value = "";
        document.getElementById("fwCredModal").style.display = "flex";
        setTimeout(function () { inp.focus(); }, 30);
        return new Promise(function (resolve) { _fwCredResolve = resolve; });
    };

    window.fwCredOk = function () {
        var v = document.getElementById("fwCredInput").value;
        if (!v) {
            document.getElementById("fwCredErr").textContent = "Password required.";
            return;
        }
        _close();
        if (_fwCredResolve) { var r = _fwCredResolve; _fwCredResolve = null; r(v); }
    };

    window.fwCredCancel = function () {
        _close();
        /* Resolve null rather than reject: cancelling is a normal outcome, and
           callers already treat a falsy password as "user backed out". */
        if (_fwCredResolve) { var r = _fwCredResolve; _fwCredResolve = null; r(null); }
    };

    window.fwHandleError = function (d, fallback) {
        if (d && d.kind === "unavailable") {
            alert("Privileged helper unavailable — nothing was changed.");
        } else if (d && d.kind === "credential_denied") {
            alert("Incorrect password. Nothing was changed.");
        } else if (d && d.kind === "locked_out") {
            alert("Account is locked out. Nothing was changed.");
        } else if (d && d.kind === "never_block") {
            alert(d.error || "That address cannot be blocked.");
        } else {
            alert(fallback + ": " + ((d && d.error) || "unknown"));
        }
    };
})();
