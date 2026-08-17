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
   pending enrollment) so the audit trail keeps the two apart.

   Two things happen, and they can succeed independently (2026-08-16):
     1. The device is blocked in Nemesis and stops reporting within one
        heartbeat interval. This always happens.
     2. The device is REMOVED FROM THE VPN. This needs the Tailscale API and an
        OAuth client carrying the devices:core scope, so it can fail on its own.

   Re-adding the device afterwards therefore requires issuing a NEW key -- the
   old one no longer gets it onto the network. That is deliberate: it makes key
   generation an enforcement point for the remote-device cap, not just a
   one-time gate at first enrollment.

   This deliberately does NOT reload on an unconfirmed removal. Reloading would
   show a device sitting in "Revoked" and looking finished, while it was in fact
   still on the VPN -- a partial result rendered as a complete one. */
function agentRevoke(id) {
  if (!confirm('Revoke this device? It will be blocked in Nemesis and removed '
             + 'from your VPN. Re-adding it later needs a NEW installer key.')) return;
  fetch('/api/agent/' + encodeURIComponent(id) + '/revoke', { method: 'POST' })
    .then(function (r) {
      /* fetch does not reject on 4xx/5xx, so status is checked explicitly --
         without this an error response reloaded the page and looked like it
         had worked.

         Read the BODY on failure too. The route returns {"error": "..."} with
         its 500, and the first version threw before reading it -- so a real
         TypeError surfaced to the user as "Revoke failed - try again" and to the
         journal as a bare 500. The message existed; nothing displayed it. */
      if (!r.ok) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          throw new Error((j && j.error) ? j.error : ('HTTP ' + r.status));
        });
      }
      return r.json();
    })
    .then(function (j) {
      var t = j && j.tailnet;
      if (t && t.confirmed) { location.reload(); return; }
      alert('Device blocked in Nemesis, but it was NOT confirmed removed from '
          + 'your VPN.\n\n' + ((t && t.detail) || 'No detail returned.')
          + '\n\nThe device cannot report to Nemesis, but it may still reach '
          + 'your network. Check Tailscale.');
      location.reload();
    })
    .catch(function (e) {
      alert('Revoke failed.\n\n' + (e && e.message ? e.message : 'Unknown error')
          + '\n\nThe device was NOT revoked. Nothing was changed.');
    });
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
      /* Transport verdict for this specific link. Shown as its own banner rather
         than appended to keyNote: it is about whether the download and this
         device's future reporting are encrypted at all, which is a different
         (and louder) concern than whether a tailnet key was baked in. */
      var transportNote = '';
      if (d.transport_warning) {
        transportNote =
          '<div style="background:#ff444422;border:1px solid #ff4444;color:#ff9999;' +
          'border-radius:6px;padding:6px 10px;margin-bottom:6px;font-size:0.82em">' +
          '⚠ ' + d.transport_warning + '</div>';
      }
      out.style.color = '#ddd';
      out.innerHTML = transportNote +
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
