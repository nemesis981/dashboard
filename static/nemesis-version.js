/* Nemesis — stale-page signal.
 *
 * Tells you when the page in your browser is older than the code now serving it.
 *
 * THE FAILURE THIS EXISTS FOR (2026-09-05). The idle-lock bypass was fixed and
 * deployed (be72fdb, 09:39:25), and then reproduced by the operator anyway. Not a
 * regression: a tab loaded at 07:53 was still running pre-fix markup, five hours
 * later, and nothing anywhere said so. A client-side security fix takes effect
 * only on the next page load, and until this file there was no signal that a
 * page had been superseded. "Confirmed fixed" and "confirmed fixed for the person
 * using it" are different claims, and the gap between them was invisible.
 *
 * ⛔ IT NEVER RELOADS FOR YOU. Same reason the idle-lock overlay never navigates:
 * a reload discards unsaved work, and doing that to someone without asking is a
 * worse outcome than the staleness it would cure. It offers; the human decides.
 */
(function () {
    'use strict';

    var POLL_MS = 300000;              // 5 min — this is a nudge, not a heartbeat
    var self = document.currentScript ||
               document.querySelector('script[src*="nemesis-version.js"]');
    var mine = self && self.getAttribute('data-build');
    if (!mine) { return; }             // no stamp, nothing to compare — stay silent

    var shown = false;

    function banner() {
        if (shown) { return; }
        shown = true;
        var d = document.createElement('div');
        d.id = 'nemVersionBanner';
        d.setAttribute('role', 'status');
        d.style.cssText =
            'position:fixed;left:0;right:0;bottom:0;z-index:2147483000;' +
            'background:#12122a;border-top:1px solid #00d4ff;color:#eee;' +
            'font:14px system-ui,sans-serif;padding:10px 14px;display:flex;' +
            'gap:12px;align-items:center;justify-content:center';
        /* Built with DOM calls, not innerHTML: nothing here is user data today,
           and keeping it that way means it cannot become an injection point if
           someone later interpolates something into it. */
        var msg = document.createElement('span');
        msg.textContent = 'Nemesis has been updated since this page was opened. ' +
                          'Reload to get the latest version.';
        var reload = document.createElement('button');
        reload.type = 'button';
        reload.textContent = 'Reload';
        reload.style.cssText = 'background:#00d4ff;border:0;border-radius:4px;' +
                               'padding:5px 12px;cursor:pointer;font-weight:600';
        reload.addEventListener('click', function () { location.reload(); });
        var later = document.createElement('button');
        later.type = 'button';
        later.textContent = 'Not now';
        later.style.cssText = 'background:transparent;border:1px solid #555;' +
                              'border-radius:4px;color:#aaa;padding:5px 12px;cursor:pointer';
        /* Dismiss hides it for THIS page only. It does not remember: the page is
           still stale after dismissing, and a fresh load is the only thing that
           actually fixes it. Persisting the dismissal would let someone silence
           a real warning permanently by accident. */
        later.addEventListener('click', function () { d.remove(); });
        d.appendChild(msg); d.appendChild(reload); d.appendChild(later);
        (document.body || document.documentElement).appendChild(d);
    }

    function look() {
        fetch('/api/build', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (j) {
                /* A 401 (locked or expired) is not staleness — say nothing. The
                   idle-lock overlay owns that conversation. */
                if (j && j.build && j.build !== mine) { banner(); }
            })
            .catch(function () { /* transient; ask again next tick */ });
    }

    /* Marked as a background poll — belt and braces, NOT the load-bearing part.
     * /api/build is in dashboard.py's _IDLE_LOCK_ALLOWED, so it cannot stamp
     * last_activity whether or not this mark survives. That matters because this
     * script is injected into EVERY authenticated page, including ones that do
     * not load nemesis-activity.js, where window.nemPoll is undefined. Without
     * the exemption, this feature would keep every session alive forever and
     * defeat the very walk-away lock it exists to make visible.
     * No console warning on the fallback, deliberately: on those pages the
     * absence is expected and correct, and a warning there would train people to
     * ignore the one nemesis-activity.js emits where it does matter. */
    setInterval((window.nemPoll || function (fn) { return fn; })(look), POLL_MS);
})();
