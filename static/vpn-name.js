/* Settings -> VPN Names: label a tunnel whose provider cannot be auto-detected.
 *
 * A separate static file, not f-string-embedded, for the same reason as
 * admin-approval.js: JS inside a Python f-string is this codebase's #1 recurring
 * bug and fails as a SILENT SyntaxError that takes the whole page down.
 */
function vpnSaveName(iface) {
  var el = document.getElementById('vpnname-' + iface);
  if (!el) { alert('Could not find the input for ' + iface); return; }
  fetch('/api/vpn/name', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ iface: iface, name: el.value })
  }).then(function (r) { return r.json(); })
    .then(function (j) {
      if (!j.ok) { alert('Could not save: ' + (j.error || 'unknown error')); return; }
      /* Reload so the dashboard row and this field agree. Leaving the page
         showing a saved value while the dashboard still renders the old one is
         the kind of split state that reads as "it did not save". */
      location.reload();
    })
    .catch(function () { alert('Could not reach the server.'); });
}
