/* Nemesis — idle-lock client layer.
 *
 * WHAT THIS IS NOT: the control. The server locks the session on its own clock
 * (_enforce_setup_and_auth), and it does so whether or not this file runs. A
 * client that never loads, is throttled in a background tab, or is hostile still
 * gets locked out — it simply gets locked out by a redirect instead of by this
 * overlay. Nothing here may be relied on for security.
 *
 * WHAT IT IS FOR: keeping the lock from costing work. A server-side lock is a
 * 302, and a 302 reloads the page and discards whatever was typed into it. This
 * shows an in-page overlay instead — the DOM is never torn down, so unsaved
 * input survives the lock and is still there after unlocking.
 *
 * ACTIVITY IS REAL INTERACTION, NOT ELAPSED TIME. The heartbeat only fires when
 * a genuine input event has occurred since the last one. A timer that beat
 * unconditionally would hold a walked-away session open forever — the same
 * defect an unmarked background poller causes, arrived at from the other end.
 *
 * The heartbeat endpoint is itself subject to the lock, so once locked this
 * script cannot beat its way back in; only a correct password can.
 */
(function () {
    'use strict';

    /* ── health-block extraction ──────────────────────────────────────────────
     * Pulls the .health div out of a fetched /account/unlock page.
     *
     * DELIBERATELY DOM-FREE. A DOMParser version would be shorter, but this is
     * the only piece of this file with logic that can be silently wrong, and a
     * DOM-dependent version cannot be executed by any harness available on this
     * box (node is present but has no HTML parser — DOMParser is undefined and
     * jsdom/linkedom/parse5 are all absent). Keeping it a pure string function
     * is what lets a real test run it against real captured HTML instead of
     * someone reading it and declaring it correct.
     *
     * Depth-counts <div>/</div> from the opening tag: the block nests several
     * levels (.health-verdict, .health-grid, and one .hc per tile), so "find
     * the next </div>" would truncate it after the verdict line.
     *
     * FAILS CLOSED — returns null, never a partial string, on an absent or
     * unbalanced block. A truncated fragment would inject broken markup that
     * looks like a rendering bug rather than a fetch problem. The POST error
     * paths of /account/unlock render WITHOUT the health block by design, so
     * "absent" is an ordinary outcome here, not an error.
     *
     * Assumes no "<div" appears inside an HTML comment or attribute value
     * within the block. True of templates/unlock.html, which is the only page
     * this ever parses, and which is version-controlled beside it.
     */
    function extractHealth(htmlText) {
        if (typeof htmlText !== 'string') { return null; }
        var start = htmlText.indexOf('<div class="health health-');
        if (start < 0) { return null; }
        var tag = /<(\/?)div\b/g;
        tag.lastIndex = start;
        var depth = 0;
        var m;
        while ((m = tag.exec(htmlText)) !== null) {
            depth += m[1] ? -1 : 1;
            if (depth === 0) {
                var close = htmlText.indexOf('>', m.index);
                return close < 0 ? null : htmlText.slice(start, close + 1);
            }
        }
        return null;
    }

    /* Exported for the node harness BEFORE a single browser global is touched —
     * the bootstrap below references window/document at IIFE top level, so a
     * require() that fell through to it would throw ReferenceError instead of
     * handing back the function. */
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { extractHealth: extractHealth };
        return;
    }

    var TOUCH_MIN_INTERVAL_MS = 30000;   // never beat more often than this
    var WARN_SECONDS          = 60;      // banner appears this long before lock
    var TICK_MS               = 1000;
    /* Must equal REFRESH_MS in templates/unlock.html. Both show the SAME data
     * from the same endpoint, and header-status.js polls it at 30s on the
     * unlocked dashboard — a locked screen refreshing on a different cadence
     * would be a third number to explain with nothing to justify it. */
    var HEALTH_REFRESH_MS     = 30000;

    var interacted   = false;
    var lastTouch    = 0;
    var deadline     = null;   // epoch ms when the session locks
    var endsSession  = false;  // absolute cap: unlocking will NOT help
    var locked       = false;
    var healthTimer  = null;   // only runs while the overlay is up
    var overlay, banner, pwInput, errBox, countdownEl, healthEl;

    /* ── interaction tracking ─────────────────────────────────────────────── */
    ['mousedown', 'keydown', 'touchstart', 'scroll', 'mousemove'].forEach(function (evt) {
        window.addEventListener(evt, function () { interacted = true; },
                                { passive: true, capture: true });
    });

    /* ── heartbeat ────────────────────────────────────────────────────────── */
    function touch(force) {
        var now = Date.now();
        if (locked) return;
        if (!force) {
            if (!interacted) return;                       // nobody is here
            if (now - lastTouch < TOUCH_MIN_INTERVAL_MS) return;
        }
        interacted = false;
        lastTouch = now;
        fetch('/api/session/touch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: '{}'
        })
            .then(function (r) {
                if (r.status === 401) { showOverlay(); return null; }
                return r.ok ? r.json() : null;
            })
            .then(function (d) {
                if (!d) return;
                deadline = Date.now() + (d.expires_in * 1000);
                endsSession = !!d.ends_session;
            })
            .catch(function () { /* transient — the countdown just keeps running */ });
    }

    /* ── the overlay ──────────────────────────────────────────────────────── */
    function build() {
        if (overlay) return;
        overlay = document.createElement('div');
        overlay.id = 'nemIdleOverlay';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.style.cssText =
            'display:none;position:fixed;inset:0;z-index:99999;background:rgba(5,5,15,0.92);' +
            'backdrop-filter:blur(3px);align-items:center;justify-content:center;' +
            'font-family:-apple-system,Segoe UI,Roboto,sans-serif;';
        overlay.innerHTML =
            '<div style="background:#16213e;border:1px solid #00d4ff55;border-radius:12px;' +
                        'padding:28px 30px;max-width:380px;width:90%;box-shadow:0 8px 40px #000a">' +
              '<h2 style="color:#00d4ff;margin:0 0 6px;font-size:1.2em">&#128274; Session locked</h2>' +
              '<p style="color:#8a98b3;font-size:0.85em;margin:0 0 16px;line-height:1.5">' +
                'Locked after a period of inactivity. Nothing has been lost &mdash; ' +
                'enter your password to carry on exactly where you left off.</p>' +
              /* Empty until the first refreshHealth() lands. Starts absent rather
                 than showing a placeholder row of zeros: a zero here reads as a
                 real "all clear" measurement, which is exactly the failure this
                 codebase keeps finding — a default that means something. */
              '<div id="nemIdleHealth" class="nem-health-scope"></div>' +
              '<div id="nemIdleErr" style="display:none;background:#ff444422;border:1px solid #ff4444;' +
                   'color:#ff8888;border-radius:8px;padding:9px 11px;margin-bottom:12px;font-size:0.82em"></div>' +
              '<input id="nemIdlePw" type="password" autocomplete="current-password" ' +
                     'placeholder="Password" style="width:100%;box-sizing:border-box;background:#0d0d1e;' +
                     'border:1px solid #334;color:#eee;padding:9px 11px;border-radius:7px;font-size:0.95em">' +
              '<button id="nemIdleGo" style="width:100%;margin-top:14px;background:#00d4ff;color:#062;' +
                      'border:none;border-radius:8px;padding:10px;font-size:0.95em;font-weight:bold;' +
                      'cursor:pointer">Unlock</button>' +
              '<p style="margin:14px 0 0;text-align:center;font-size:0.72em;color:#6b7689">' +
                '<a href="/logout" style="color:#00d4ff;text-decoration:none">Sign out instead</a></p>' +
            '</div>';
        document.body.appendChild(overlay);

        banner = document.createElement('div');
        banner.id = 'nemIdleWarn';
        banner.style.cssText =
            'display:none;position:fixed;top:0;left:0;right:0;z-index:99998;background:#3a2d00;' +
            'border-bottom:1px solid #ffaa00;color:#ffd479;padding:8px 14px;font-size:0.83em;' +
            'text-align:center;font-family:-apple-system,Segoe UI,Roboto,sans-serif;';
        document.body.appendChild(banner);

        /* The health markup is styled by classes that live in the lock-screen
           stylesheet, not on the dashboard page. Injected once, here, rather
           than added to every template that might host the overlay. /static is
           on _IDLE_LOCK_ALLOWED, so a locked session can still load it. */
        if (!document.getElementById('nemLockHealthCss')) {
            var css = document.createElement('link');
            css.id = 'nemLockHealthCss';
            css.rel = 'stylesheet';
            css.href = '/static/lock-health.css';
            document.head.appendChild(css);
        }

        pwInput  = document.getElementById('nemIdlePw');
        errBox   = document.getElementById('nemIdleErr');
        healthEl = document.getElementById('nemIdleHealth');
        document.getElementById('nemIdleGo').addEventListener('click', submit);
        pwInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') submit();
        });
    }

    /* ── health summary ───────────────────────────────────────────────────────
     * Re-requests the one page a locked session is already allowed to fetch and
     * lifts the health block out of it.
     *
     * NO NEW SERVER SURFACE, deliberately. /api/header/status — which is what
     * header-status.js polls for this same data on the dashboard — is NOT on
     * _IDLE_LOCK_ALLOWED and correctly 401s a locked session. Re-rendering the
     * one allowed page is the mechanism, exactly as templates/unlock.html
     * already does for the standalone lock screen.
     *
     * THIS CANNOT DEFEAT THE LOCK. _enforce_setup_and_auth() only stamps
     * last_activity inside its `ep not in _IDLE_LOCK_ALLOWED` branch, so these
     * requests never refresh the idle clock however long they run. That is a
     * property of the server, not of this timer — but it is why polling here is
     * safe at all, and it is asserted directly by C2 of the control harness
     * rather than taken on trust.
     */
    function refreshHealth() {
        if (!locked || !healthEl) { return; }
        fetch('/account/unlock', {
            headers: { 'Accept': 'text/html' },
            credentials: 'same-origin'
        })
            .then(function (r) { return r.ok ? r.text() : null; })
            .then(function (html) {
                var block = extractHealth(html);
                /* Leave the previous summary in place on a miss rather than
                   blanking it. A transient failure must not look like "nothing
                   is wrong"; the stale-but-real block is the safer thing to
                   show, and the note under it already says it is a snapshot. */
                if (block && healthEl) { healthEl.innerHTML = block; }
            })
            .catch(function () { /* transient — the next tick tries again */ });
    }

    function showOverlay() {
        build();
        if (locked) return;
        locked = true;
        banner.style.display = 'none';
        overlay.style.display = 'flex';
        try { pwInput.focus(); } catch (e) { /* not focusable yet */ }
        /* Immediately, THEN on the interval. Waiting a full period would leave
           the first thing the operator sees blank — which is the original bug
           this fix exists for, just with a shorter duration. */
        refreshHealth();
        if (healthTimer === null) {
            healthTimer = setInterval(refreshHealth, HEALTH_REFRESH_MS);
        }
    }

    function hideOverlay() {
        locked = false;
        if (healthTimer !== null) { clearInterval(healthTimer); healthTimer = null; }
        if (!overlay) return;
        overlay.style.display = 'none';
        errBox.style.display = 'none';
        pwInput.value = '';
    }

    function submit() {
        var pw = pwInput.value;
        if (!pw) return;
        var btn = document.getElementById('nemIdleGo');
        btn.disabled = true;
        btn.textContent = 'Unlocking…';
        fetch('/account/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ password: pw })
        })
            .then(function (r) { return r.json().then(function (d) { return { s: r.status, d: d }; }); })
            .then(function (res) {
                btn.disabled = false;
                btn.textContent = 'Unlock';
                if (res.s === 200 && res.d.ok) {
                    hideOverlay();
                    touch(true);                       // resync the countdown
                    return;
                }
                if (res.d && res.d.session_ended) {
                    /* The lockout budget is spent — there is no session left to
                       return to, so the page must go to login. Unsaved work is
                       gone either way at that point. */
                    window.location = '/login';
                    return;
                }
                errBox.textContent = (res.d && res.d.error) || 'Unlock failed.';
                errBox.style.display = 'block';
                pwInput.value = '';
                pwInput.focus();
            })
            .catch(function () {
                btn.disabled = false;
                btn.textContent = 'Unlock';
                errBox.textContent = 'Could not reach the server.';
                errBox.style.display = 'block';
            });
    }

    /* ── countdown ────────────────────────────────────────────────────────── */
    function tick() {
        touch(false);
        if (deadline === null || locked) return;
        var left = Math.round((deadline - Date.now()) / 1000);
        if (left <= 0) { showOverlay(); return; }
        if (left <= WARN_SECONDS) {
            build();
            banner.textContent = endsSession
                ? 'Session ends in ' + left + 's (maximum length reached) — you will need to sign in again.'
                : 'Locking in ' + left + 's due to inactivity — move the mouse or press a key to stay signed in.';
            banner.style.display = 'block';
        } else if (banner) {
            banner.style.display = 'none';
        }
    }

    /* Any other request that comes back "locked" flips the overlay on
       immediately, so a background poll discovers the lock before the local
       countdown would have. */
    var nativeFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
        return nativeFetch(input, init).then(function (r) {
            if (r.status === 401 && !locked) {
                var probe = r.clone();
                probe.json().then(function (d) {
                    if (d && d.session_locked) showOverlay();
                }).catch(function () { /* not our 401 */ });
            }
            return r;
        });
    };

    function start() {
        build();
        touch(true);                                   // page load = a human arrived
        setInterval(tick, TICK_MS);
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
