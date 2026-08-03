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
/* Withdraw an already-approved device. Distinct from reject (which denies a
   pending enrollment) so the audit trail keeps the two apart. The device stops
   reporting within one heartbeat interval; its key material is unchanged, so a
   re-approve restores access without re-enrolling. */
function agentRevoke(id) {
  if (!confirm('Revoke this device? It will stop reporting until re-approved.')) return;
  fetch('/api/agent/' + encodeURIComponent(id) + '/revoke', { method: 'POST' })
    .then(function () { location.reload(); })
    .catch(function () { alert('Revoke failed — try again.'); });
}
/* Robust clipboard copy: navigator.clipboard needs HTTPS/localhost, so on plain-HTTP
   LAN access fall back to a hidden textarea + execCommand (FIX: copy button worked
   only in secure contexts before). */
function nemesisFallbackCopy(text, ok) {
  try {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.top = '-1000px'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    if (ok) ok();
  } catch (e) { window.prompt('Copy this link:', text); }
}
function nemesisCopyText(text, btn) {
  function ok() {
    if (!btn) return;
    var t = btn.textContent; btn.textContent = '✓ Copied';
    setTimeout(function () { btn.textContent = t; }, 1500);
  }
  if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(ok, function () { nemesisFallbackCopy(text, ok); });
  } else {
    nemesisFallbackCopy(text, ok);
  }
}

/* The copy button always copies the /zip link (exe + docs bundled). */
var _nemesisZipUrl = '';
function nemesisCopyZip(btn) { if (_nemesisZipUrl) nemesisCopyText(_nemesisZipUrl, btn); }

/* Generate a single-use Windows installer link (frozen-exe bundle + baked conf). */
function genWindowsInstaller() {
  var hint = (document.getElementById('installerHint') || {}).value || 'Windows Device';
  var pre = (document.getElementById('installerPreauth') || {}).value || '';
  var auto = !!(document.getElementById('installerAutoApprove') || {}).checked;
  var poll = ((document.getElementById('installerPoll') || {}).value || '').trim();
  var out = document.getElementById('installerResult');
  if (out) { out.textContent = 'Generating...'; out.style.color = '#888'; }
  fetch('/api/agent/installer/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_name_hint: hint, preauth_key: pre, auto_approve: auto,
                           poll_interval: poll })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (!d || !d.ok) { throw new Error((d && d.error) || 'failed'); }
      _nemesisZipUrl = d.zip_url || '';
      var when = new Date(d.expires_at * 1000).toLocaleString();
      var keyNote = d.preauth_key_baked
        ? ' A single-use Tailscale pre-auth key is baked in (the agent self-joins the tailnet).'
        : ' No pre-auth key baked &mdash; the device must join the tailnet by hand.';
      if (d.preauth_warning) {
        keyNote = ' ⚠ ' + d.preauth_warning;
      }
      out.style.color = '#ddd';
      out.innerHTML =
        '<div style="color:#aaa;font-size:0.82em;margin-bottom:4px">Share this link with your user ' +
        '(self-contained Windows installer; expires ' + when + ').' + keyNote + '</div>' +
        '<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">' +
        '<input readonly value="' + d.zip_url + '" onclick="this.select()" ' +
        'style="background:#11111f;border:1px solid #00d4ff55;color:#00d4ff;border-radius:6px;' +
        'padding:5px 8px;font-size:0.82em;width:340px">' +
        '<button onclick="nemesisCopyZip(this)" style="background:#00d4ff22;color:#00d4ff;' +
        'border:1px solid #00d4ff;border-radius:6px;padding:5px 12px;cursor:pointer">📋 Copy link</button>' +
        '</div>' +
        '<div style="color:#666;font-size:0.78em;margin-top:6px">Advanced: ' +
        '<a href="' + d.exe_url + '" style="color:#888">generic .exe only (no baked config)</a></div>';
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
