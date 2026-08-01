/* Nemesis — request activity classification.
 *
 * Background polling must not read as human presence. This dashboard refreshes
 * itself as often as every 5 seconds, so if any authenticated request counted
 * as activity, an idle session would keep itself alive indefinitely and a
 * walk-away lock could never fire — while still appearing fully implemented.
 * That is the failure this file exists to prevent, and it is why this landed
 * BEFORE the server-side enforcement rather than alongside it.
 *
 * Marked at the CALL SITE, never on the function. Every polled function
 * (loadDevices, pollActiveScans, loadPendingScans, loadFindings, loadAllHw,
 * loadHwDevices, refreshDashboard) is ALSO invoked by user actions and on first
 * paint — 2 to 6 call sites each. Marking the function would classify genuine
 * activity as background, which fails in the dangerous direction: the session
 * would lock while someone is actively working in it.
 *
 * The inverse rule — a request that OMITS the header counts as human activity —
 * is deliberate. A misbehaving or hostile client can then only ever make itself
 * lock SOONER, never later, so the worst case of this mechanism is
 * inconvenience rather than a defeated control.
 *
 * On its own this file changes nothing observable: the server does not read the
 * header until the enforcement commit lands.
 */
(function () {
    'use strict';

    var pollDepth = 0;
    var nativeFetch = window.fetch.bind(window);

    window.fetch = function (input, init) {
        if (pollDepth > 0) {
            init = init || {};
            var headers = new Headers(
                init.headers || (input && input.headers) || {});
            headers.set('X-Nemesis-Poll', '1');
            init.headers = headers;
        }
        return nativeFetch(input, init);
    };

    /* Wrap a setInterval callback so every fetch STARTED inside it is marked.
     *
     * A counter rather than a boolean: overlapping or nested poll callbacks
     * must not clear one another's mark.
     *
     * Raised and lowered SYNCHRONOUSLY around the call, which is what makes
     * this correct — every current poll target issues its fetch() synchronously
     * before returning (verified: none are declared async, none await first).
     * A future poll target that awaited before fetching would escape the mark
     * and silently read as human activity, so preserve that property when
     * adding one.
     */
    window.nemPoll = function (fn) {
        return function () {
            pollDepth++;
            try {
                return fn.apply(this, arguments);
            } finally {
                pollDepth--;
            }
        };
    };
})();
