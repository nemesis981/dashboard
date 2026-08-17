/* Licensing page: activate a key, issue/redeem backup codes.
 *
 * A separate .js file rather than markup inside a Python f-string, deliberately.
 * The dashboard's single most common defect is JS strings inside f-strings —
 * an apostrophe or a stray newline produces a silent SyntaxError and the page
 * simply never loads. Nothing here can cause that.
 *
 * Every handler shows the SERVER's message rather than a generic one. These
 * flows fail in ways the user has to act on differently — a mistyped key, an
 * expired licence, a key bound to other hardware, and an exhausted code set all
 * need different responses, and "something went wrong" tells them none of it.
 */

function licSetNote(el, cls, html) {
  el.innerHTML = '<div class="note ' + cls + '">' + html + '</div>';
}

function licEscape(s) {
  var d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

/* fetch does not reject on 4xx/5xx, so the body is read on BOTH paths. Throwing
   on !ok before reading it would discard the server's explanation — the exact
   failure that made a real revoke bug undiagnosable earlier. */
function licPost(url, payload) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function (r) {
    return r.json().catch(function () { return {}; }).then(function (j) {
      return { ok: r.ok, status: r.status, body: j };
    });
  });
}

function licActivate() {
  var el = document.getElementById('licresult');
  var key = (document.getElementById('lickey').value || '').trim();
  if (!key) { licSetNote(el, 'warn', 'Paste a licence key first.'); return; }
  licSetNote(el, '', 'Checking&hellip;');
  licPost('/api/license/activate', { license_key: key }).then(function (r) {
    if (r.body && r.body.ok) {
      licSetNote(el, 'good', 'Licence activated. Tier: '
                 + licEscape(r.body.tier || 'commercial') + '. Reloading&hellip;');
      setTimeout(function () { location.reload(); }, 1200);
      return;
    }
    var d = (r.body && r.body.detail) || ('HTTP ' + r.status);
    licSetNote(el, 'err', licEscape(d));
  }).catch(function () {
    licSetNote(el, 'err', 'Could not reach the server. The licence was not changed.');
  });
}

function licGenerate() {
  var el = document.getElementById('newcodes');
  /* Destructive: it supersedes any codes the operator has already written down.
     Confirm before, not after. */
  if (!confirm('Issue 5 new backup codes?\n\nAny codes you already have will '
             + 'stop working immediately. Make sure you can write the new ones down.')) {
    return;
  }
  licSetNote(el, '', 'Issuing&hellip;');
  licPost('/api/license/backup-codes/generate', {}).then(function (r) {
    if (!(r.body && r.body.ok)) {
      var d = (r.body && r.body.detail) || ('HTTP ' + r.status);
      licSetNote(el, 'err', licEscape(d));
      return;
    }
    var html = '<div class="note good"><strong>Write these down now.</strong> '
             + 'They are shown once and cannot be recovered afterwards.</div>'
             + '<code class="codes">';
    r.body.codes.forEach(function (c) { html += licEscape(c) + '<br>'; });
    html += '</code>';
    el.innerHTML = html;
  }).catch(function () {
    licSetNote(el, 'err', 'Could not reach the server. No codes were issued.');
  });
}

function licRedeem() {
  var el = document.getElementById('redeemresult');
  var code = (document.getElementById('redeemcode').value || '').trim();
  if (!code) { licSetNote(el, 'warn', 'Enter a backup code first.'); return; }
  licSetNote(el, '', 'Checking&hellip;');
  licPost('/api/license/backup-codes/redeem', { code: code }).then(function (r) {
    if (r.body && r.body.ok) {
      /* Deliberately NOT "done". The code is spent, but a replacement key comes
         from the issuer, which is manual today. Saying "activated" here would be
         a lie the user discovers only when the tier does not change. */
      licSetNote(el, 'good',
        licEscape(r.body.next_step || 'Code accepted.')
        + '<br><br>' + licEscape(r.body.message || ''));
      return;
    }
    var d = (r.body && r.body.detail) || ('HTTP ' + r.status);
    licSetNote(el, r.body && r.body.exhausted ? 'err' : 'warn', licEscape(d));
  }).catch(function () {
    licSetNote(el, 'err', 'Could not reach the server. No code was used.');
  });
}

/* Copy the full installation ID. The customer must send this to the vendor to
   get a key, and it is a 64-char hex string — retyping it is an error waiting to
   happen, and a truncated display would produce a key bound to nothing.
   navigator.clipboard needs a secure context, and this dashboard is plain HTTP
   on the LAN, so the textarea fallback is the path that actually runs here —
   the same reason nemesisFallbackCopy exists in agent-enroll.js. */
function licCopyInstallId() {
  var el = document.getElementById('iid');
  if (!el) { return; }
  var text = el.textContent.trim();
  function done() {
    var b = event && event.target;
    if (!b) { return; }
    var t = b.textContent; b.textContent = 'Copied';
    setTimeout(function () { b.textContent = t; }, 1500);
  }
  if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, function () { licFallbackCopy(text, done); });
  } else {
    licFallbackCopy(text, done);
  }
}

function licFallbackCopy(text, ok) {
  try {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.top = '-1000px';
    document.body.appendChild(ta); ta.focus(); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    if (ok) { ok(); }
  } catch (e) {
    window.prompt('Copy this installation ID:', text);
  }
}
