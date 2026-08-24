/* Role-aware presentation.
 *
 * THIS IS NOT A SECURITY CONTROL AND MUST NEVER BE TREATED AS ONE.
 *
 * Every route is enforced server-side at the before_request gate in
 * dashboard.py, which reads alert_manager/roles.py. Anyone can delete an
 * attribute in dev-tools and reveal a hidden button; pressing it still gets a
 * 403 from the server. The value here is that a view-only user sees a coherent
 * product instead of a page full of controls that all fail.
 *
 * Usage: put data-min-role="admin" (or "user") on any element that should only
 * appear for that role or above. Elements with no attribute are always shown.
 *
 * Deliberately mirrors tier.js's shape (a data-attribute pass over the DOM,
 * re-runnable after injection) so there is one idiom to learn, not two. It is
 * ORTHOGONAL to tier.js, though: tier is how much explanation the reader wants
 * and lives in localStorage; role is a server-side security boundary the reader
 * cannot change. Never derive one from the other.
 */
(function () {
  'use strict';

  /* MUST mirror ROLES in alert_manager/roles.py, in order and by name.
   *
   * This is the second source of truth for one ordering, which is a drift risk
   * by construction -- and it drifted: `sub_admin` was inserted server-side on
   * 2026-08-22 and this map was not updated until 2026-08-24. An unlisted role
   * yields rankOf() === -1, and -1 is below EVERY minimum, so a sub_admin was
   * shown less of the product than a view-only account. The server was correct
   * throughout; only the presentation was wrong, which is exactly why nothing
   * caught it -- no request was refused and no error was logged.
   *
   * test_roles.py now parses this literal and reconciles it against roles.ROLES,
   * the same way it already reconciles _AUTH_EXEMPT against UNAUTHENTICATED. Add
   * a role in roles.py without adding it here and that test fails.
   */
  var RANK = {viewonly: 0, user: 1, sub_admin: 2, admin: 3};

  // Deliberately NOT initialised to a role. Until the server has answered, we
  // know nothing -- and guessing 'admin' would flash every admin control to a
  // view-only user before hiding it again, while guessing 'viewonly' would hide
  // the whole product from an admin for a moment. `null` means "not yet known",
  // and applyRole() leaves the DOM alone until it is.
  window.nemesisRole = null;

  function rankOf(role) {
    return Object.prototype.hasOwnProperty.call(RANK, role) ? RANK[role] : -1;
  }

  function applyRole() {
    var role = window.nemesisRole;
    if (role === null) { return; }          // not known yet -- change nothing
    var have = rankOf(role);
    var nodes = document.querySelectorAll('[data-min-role]');
    for (var i = 0; i < nodes.length; i++) {
      var need = rankOf(nodes[i].getAttribute('data-min-role'));
      // An unrecognised data-min-role value yields need === -1, which would
      // make everything visible. Treat it as admin instead: a typo should hide
      // the control, matching the server's fail-closed default for an
      // unregistered endpoint.
      if (need < 0) { need = RANK.admin; }
      nodes[i].style.display = (have >= need) ? '' : 'none';
    }
  }

  function loadRole() {
    return fetch('/api/header/status', {credentials: 'same-origin'})
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.role) { return; }
        window.nemesisRole = d.role;
        applyRole();
      })
      .catch(function () {
        /* Leave nemesisRole null. A failed lookup must not reveal admin
         * controls to someone who may not be an admin -- and must not hide the
         * product from someone who is. Showing the page unchanged and letting
         * the server refuse what it refuses is the honest failure mode. */
      });
  }

  window.applyRole = applyRole;
  window.reloadRole = loadRole;
  window.roleAtLeast = function (minimum) {
    return window.nemesisRole !== null
      && rankOf(window.nemesisRole) >= rankOf(minimum);
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadRole);
  } else {
    loadRole();
  }
})();
