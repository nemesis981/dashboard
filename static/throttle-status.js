/* Throttle status card -- fetches /api/throttle-status and renders one badge
 * row per component. Kept as its own static file, not inline in dashboard.py:
 * that file's own comments name JS-string-inside-a-Python-f-string escaping as
 * its single most common defect (see the diagnostics-page check-card comment),
 * so any JS with real logic belongs here, never built as an f-string.
 *
 * Built entirely with textContent/createElement, never innerHTML with
 * interpolated values -- component/reason/source strings come from the
 * server, and there is no reason to trust them more than any other API
 * response just because today's callers happen to be internal. */
(function () {
  var COLOR = {
    throttleable: '#00d4ff',
    unthrottled:  '#888888',
    unavailable:  '#ffaa00',
    active:       '#ff8800',
    error:        '#ff4444'
  };
  var LABEL = { throttleable: 'throttleable', unthrottled: 'unthrottled', unavailable: 'unavailable' };

  function badge(text, color) {
    var span = document.createElement('span');
    span.textContent = text;
    span.style.cssText = 'display:inline-block;padding:2px 8px;border-radius:10px;' +
      'font-size:0.75em;margin-right:4px;margin-bottom:4px;border:1px solid ' + color +
      ';color:' + color + ';background:' + color + '18';
    return span;
  }

  function row(component, info) {
    var div = document.createElement('div');
    div.style.cssText = 'display:flex;align-items:center;flex-wrap:wrap;padding:6px 0;' +
      'border-bottom:1px solid #22262e';

    var name = document.createElement('span');
    name.textContent = component;
    name.style.cssText = 'color:#eee;font-size:0.85em;min-width:140px;margin-right:8px';
    div.appendChild(name);

    div.appendChild(badge(LABEL[info.status] || info.status, COLOR[info.status] || '#888'));

    if (info.throttled) {
      div.appendChild(badge((info.factor || 1) + 'x active', COLOR.active));
      if (info.reason) {
        var why = document.createElement('span');
        why.textContent = info.reason + (info.source ? ' (' + info.source + ')' : '');
        why.style.cssText = 'color:#999;font-size:0.75em;margin-left:6px';
        div.appendChild(why);
      }
    }

    if (!info.registered && info.status === 'throttleable') {
      div.appendChild(badge('not registered', '#666666'));
    }

    return div;
  }

  function render(data) {
    var container = document.getElementById('throttle-status-card');
    if (!container) return;
    container.textContent = '';   // clear the "Loading..." placeholder, safely

    var comps = data.components || {};
    var names = Object.keys(comps).sort();
    if (names.length === 0) {
      var empty = document.createElement('p');
      empty.textContent = 'No components reporting.';
      empty.style.cssText = 'color:#888;font-size:0.85em';
      container.appendChild(empty);
      return;
    }
    names.forEach(function (name) {
      container.appendChild(row(name, comps[name]));
    });
  }

  function renderError(msg) {
    var container = document.getElementById('throttle-status-card');
    if (!container) return;
    container.textContent = '';
    var p = document.createElement('p');
    p.textContent = msg;
    p.style.cssText = 'color:' + COLOR.error + ';font-size:0.85em';
    container.appendChild(p);
  }

  function load() {
    var container = document.getElementById('throttle-status-card');
    if (!container) return;   // this page doesn't have the card -- nothing to do
    fetch('/api/throttle-status', { cache: 'no-store' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (d) {
        if (d.error) { renderError('Throttle status unavailable: ' + d.error); return; }
        render(d);
      })
      .catch(function (e) {
        renderError('Could not load throttle status (' + e.message + ')');
      });
  }

  // The first paint is deliberately NOT wrapped: a page load IS a human arriving.
  // Only the repeating timer is background.
  if (document.readyState !== 'loading') load();
  else document.addEventListener('DOMContentLoaded', load);

  // MUST be marked as a background poll. /api/throttle-status is an ordinary
  // authenticated endpoint and is NOT in dashboard.py's _IDLE_LOCK_ALLOWED, so an
  // unmarked poll here stamps `last_activity` every 30s against a 15-minute idle
  // timeout. This card renders on the main dashboard, so unwrapped it was enough on
  // its own to stop that page ever idle-locking -- the walk-away lock could never
  // fire while still appearing fully implemented. Found 2026-09-04; see
  // static/nemesis-activity.js for why the marking lives at the CALL SITE.
  // Guarded rather than assuming nemPoll exists, and it WARNS rather than degrading
  // silently, because a silent fallback is how this went unnoticed.
  setInterval((window.nemPoll || function (fn) {
    if (window.console && console.warn) {
      console.warn('[throttle-status] window.nemPoll missing -- this poll will ' +
                   'count as user activity and can defeat idle-lock');
    }
    return fn;
  })(load), 30000);
})();
