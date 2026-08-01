/* Nemesis header status light — polls /api/header/status every 30s and updates
 * the leftmost header indicator (colorblind-friendly shape + color + count + a
 * tiered tooltip). No page refresh; DOM update only. */
(function () {
  var SHAPE = { red: '■', amber: '▲', green: '●' };   // ■ ▲ ●
  var COLOR = { red: '#e74c3c', amber: '#f39c12', green: '#2ecc71' };

  function poll() {
    fetch('/api/header/status')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var shape = document.getElementById('hdrStatusShape');
        var light = document.getElementById('hdrStatusLight');
        var count = document.getElementById('hdrStatusCount');
        if (!shape) return;
        var st = d.status || 'green';
        var k = d.counts || {};
        var total = (k.critical || 0) + (k.high || 0) + (k.medium || 0) +
                    (k.services_down || 0) + (k.open_tickets || 0) + (k.canary_trips || 0);

        shape.textContent = SHAPE[st] || SHAPE.green;
        if (light) light.style.color = COLOR[st] || COLOR.green;
        if (count) count.textContent = total > 0 ? (' ' + total) : '';

        if (light) {
          var beginner = total > 0
            ? (total + ' item' + (total === 1 ? '' : 's') + ' need your attention — click to see them')
            : 'All systems healthy — nothing needs your attention';
          var intermediate =
            (k.critical || 0) + ' CRITICAL, ' + (k.high || 0) + ' HIGH, ' + (k.medium || 0) +
            ' MEDIUM alert(s), ' + (k.services_down || 0) + ' service(s) down — click to review';
          var pro =
            'crit=' + (k.critical || 0) + ' high=' + (k.high || 0) + ' med=' + (k.medium || 0) +
            ' svc_down=' + (k.services_down || 0) + ' open_tickets=' + (k.open_tickets || 0) +
            ' canary=' + (k.canary_trips || 0);
          light.title = (typeof tierText === 'function')
            ? tierText(beginner, intermediate, pro)
            : (total > 0 ? beginner : 'All systems healthy');
        }
        if (window.console && console.debug) {
          console.debug('[header-status] poll @ ' + new Date().toISOString() + ' -> ' + st +
                        ' (' + total + ')');
        }
      })
      .catch(function () { /* transient — keep last known state */ });
  }

  // Fire immediately on load, then every 30s.
  //
  // The interval is wrapped so its fetch is marked as a BACKGROUND poll and does
  // not count as human presence. Without this the header widget alone — present
  // on the dashboard page and firing every 30s — keeps the session alive
  // indefinitely and idle-lock can never trigger there. See
  // static/nemesis-activity.js.
  //
  // The first paint below is deliberately NOT wrapped: a page load IS a human
  // arriving, and should refresh the clock.
  //
  // Guarded rather than assuming nemPoll exists, so this file stays usable on a
  // page without the shim — but it warns instead of degrading silently, because
  // a silent fallback is exactly how this defect went unnoticed the first time.
  if (document.readyState !== 'loading') poll();
  else document.addEventListener('DOMContentLoaded', poll);
  setInterval((window.nemPoll || function (fn) {
    if (window.console && console.warn) {
      console.warn('[header-status] window.nemPoll missing — this poll will ' +
                   'count as user activity and can defeat idle-lock');
    }
    return fn;
  })(poll), 30000);
})();
