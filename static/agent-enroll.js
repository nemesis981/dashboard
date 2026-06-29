/* Settings -> Devices: approve/reject pending agent enrollments. */
function agentApprove(id) {
  fetch('/api/agent/' + encodeURIComponent(id) + '/approve', { method: 'POST' })
    .then(function () { location.reload(); })
    .catch(function () { alert('Approve failed — try again.'); });
}
function agentReject(id) {
  if (!confirm('Reject this device enrollment?')) return;
  fetch('/api/agent/' + encodeURIComponent(id) + '/reject', { method: 'POST' })
    .then(function () { location.reload(); })
    .catch(function () { alert('Reject failed — try again.'); });
}
/* Generate a single-use Windows installer link (token auto-approve). */
function genWindowsInstaller() {
  var hint = (document.getElementById('installerHint') || {}).value || 'Windows Device';
  var out = document.getElementById('installerResult');
  if (out) { out.textContent = 'Generating...'; out.style.color = '#888'; }
  fetch('/api/agent/installer/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_name_hint: hint })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (!d || !d.ok) { throw new Error((d && d.error) || 'failed'); }
      var when = new Date(d.expires_at * 1000).toLocaleString();
      out.style.color = '#ddd';
      out.innerHTML =
        'Installer generated. Send the link below to the user. Link expires ' + when + '.<br>' +
        '<a href="' + d.ps1_url + '" style="color:#00d4ff">Download installer (.ps1)</a> &nbsp; ' +
        '<a href="' + d.exe_url + '" style="color:#00d4ff">Windows .exe</a> &nbsp; ' +
        '<button onclick="navigator.clipboard.writeText(\'' + d.ps1_url + '\')" ' +
        'style="background:#222;color:#aaa;border:1px solid #444;border-radius:5px;' +
        'padding:3px 10px;cursor:pointer">Copy download link</button>';
    })
    .catch(function () {
      if (out) { out.style.color = '#ff6666'; out.textContent = 'Could not generate installer — try again.'; }
    });
}

/* Findings present: extra confirmation before granting network access. */
function agentApproveAnyway(id) {
  if (!confirm('This device has security findings. Approving it will grant it access to your network. Are you sure?')) return;
  fetch('/api/agent/' + encodeURIComponent(id) + '/approve', { method: 'POST' })
    .then(function () { location.reload(); })
    .catch(function () { alert('Approve failed — try again.'); });
}
