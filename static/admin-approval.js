/* Admin Approval Protocol v1 (ADR 0026 §D3) — the browser half.
 *
 * Pairing (settings) and the approval ceremony (dashboard). Everything this
 * calls already existed and was tested server-side against a SYNTHETIC
 * authenticator; this file is the first code path that involves a real device
 * and a real human touch.
 *
 * ⚠ A SEPARATE .js FILE, DELIBERATELY, AND NOT NEGOTIABLE.
 * This codebase's #1 recurring bug is JS strings inside Python f-strings: a raw
 * apostrophe or a stray brace in rendered JS causes a SILENT SyntaxError and the
 * page simply fails to load. ~200 lines of new JS with WebAuthn's brace-heavy
 * option objects is the worst possible candidate for f-string embedding. Served
 * statically instead, which removes the entire bug class rather than dodging it.
 * Do not inline this into dashboard.py later.
 *
 * ⚠ WEBAUTHN NEEDS A SECURE CONTEXT. navigator.credentials is undefined over
 * plain HTTP on a non-localhost origin. The appliance has a TLS front door
 * serving its MagicDNS name (Stage 0, 2026-08-24) and the RP ID derives to that
 * SAME name, which is the property that makes this work at all. Reached over
 * plain HTTP, every call here fails — and it fails in a way that looks like a
 * broken button, so `aapGuardContext()` says so explicitly instead.
 */

/* ── shared helpers ─────────────────────────────────────────────────────── */

/* base64url -> ArrayBuffer. WebAuthn speaks base64url; our API speaks standard
   base64. Converting in ONE place so the two never get mixed up silently. */
function aapB64uToBuf(s) {
  var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  var raw = atob(b64);
  var buf = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}

/* The tagged-bytes wrapper key, and it MUST equal admin_approval.BYTES_TAG.
 *
 * Stated once as a constant rather than inline at each use: the first live
 * pairing attempt failed because two call sites both spelled it 'b64', and a
 * wrong value here fails in a way that names the wrong thing entirely (see
 * aapBytes below). One place to change, one place to be wrong. */
var AAP_BYTES_TAG = '__bytes_b64__';

/* Wrap an ArrayBuffer as the tagged-JSON bytes object the server decodes.
 *
 * ⚠ IF THIS TAG IS WRONG THE ERROR WILL NOT SAY SO. `untag_bytes()` only treats
 * a dict as wrapped bytes when its ONLY key is BYTES_TAG; anything else falls
 * through to the integer-label loop, and because TagError subclasses ValueError
 * the resulting failure is reported as "bad integer label 'int:-2'" — pointing
 * at the label, which is always valid, instead of at the value. Observed live
 * 2026-08-30. Do not trust that message if this ever fails again. */
function aapBytes(buf) {
  var o = {};
  o[AAP_BYTES_TAG] = aapBufToB64(buf);
  return o;
}

/* ArrayBuffer -> standard base64, which is what every route here expects. */
function aapBufToB64(buf) {
  var bytes = new Uint8Array(buf), s = '';
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/* Refuse early and legibly rather than throwing an opaque TypeError.
   Returns true when the ceremony can proceed. */
function aapGuardContext(where) {
  if (!window.isSecureContext || !navigator.credentials) {
    alert('Security keys need an HTTPS connection.\n\n' +
          'You are on ' + location.protocol + '//' + location.host + '.\n' +
          'Open the dashboard over its https:// address and try again.\n\n' +
          '(' + where + ')');
    return false;
  }
  return true;
}

/* Surface the server's own error text. Every route here returns {ok,error} and
   the errors are written to be actionable ("the original path is occupied",
   "approval authorises proposal 41, not 42") — replacing them with a generic
   message would throw away the only useful part. */
function aapFail(prefix, payload) {
  var msg = (payload && payload.error) ? payload.error : 'unknown error';
  alert(prefix + '\n\n' + msg);
}

/* ── pairing (settings page) ────────────────────────────────────────────── */

/* Assemble a COSE_Key from what the browser gives us, in the tagged-JSON form
   the pairing route decodes with the protocol's own untag_bytes().
 *
 * ⚠ WHY THIS IS DONE HERE AND NOT SERVER-SIDE. WebAuthn's registration response
 * carries an attestationObject in CBOR, and there is deliberately NO CBOR
 * decoder anywhere in this codebase — adding a trusted parser on an input path
 * to accept attestation blobs was judged the wrong trade. getPublicKey() hands
 * back SPKI DER and getPublicKeyAlgorithm() the COSE alg id, which is everything
 * needed for ES256 without parsing attestation at all.
 *
 * ⚠ ES256 ONLY, AND IT REFUSES ANYTHING ELSE. The server supports Ed25519 too,
 * but extracting an Ed25519 key from SPKI needs different offsets and this has
 * never been exercised against a real device. Refusing loudly beats emitting a
 * malformed key that fails much later as an unexplained signature rejection.
 */
function aapCoseFromCredential(cred) {
  var alg = cred.response.getPublicKeyAlgorithm();
  if (alg !== -7) {
    throw new Error('This security key uses algorithm ' + alg +
                    '; only ES256 (-7) is supported by this pairing flow. ' +
                    'Try a different key, or pair from a device that offers ES256.');
  }
  var spki = new Uint8Array(cred.response.getPublicKey());
  /* An uncompressed P-256 point is 65 bytes starting 0x04, and it sits at the
     END of the SPKI wrapper. Located by searching from the end rather than by a
     fixed offset: the ASN.1 prefix length is stable in practice but a fixed
     offset would fail silently on any variation, and a wrong offset produces a
     key that looks valid and never verifies. */
  var idx = -1;
  for (var i = spki.length - 65; i >= 0; i--) {
    if (spki[i] === 0x04) { idx = i; break; }
  }
  if (idx < 0 || spki.length - idx !== 65) {
    throw new Error('Could not read the public key from this security key ' +
                    '(unexpected SPKI layout). Nothing was registered.');
  }
  var x = spki.slice(idx + 1, idx + 33);
  var y = spki.slice(idx + 33, idx + 65);
  /* Tagged-JSON: integer COSE labels as "int:N", byte values as {"b64": ...}.
     Matches admin_approval.tag_bytes() exactly — the same shape the
     authenticator table stores and the agent's pinned store holds. */
  return {
    'int:1': 2,        /* kty: EC2   */
    'int:3': -7,       /* alg: ES256 */
    'int:-1': 1,       /* crv: P-256 */
    // ⚠ THE TAG IS `__bytes_b64__`, NOT `b64`. It must match
    // admin_approval.BYTES_TAG exactly — untag_bytes() only treats a dict as
    // wrapped bytes when its ONLY key is that literal string, and anything else
    // falls through to the label loop and is rejected as an untyped key.
    // Got this wrong on the first live pairing attempt (2026-08-30); see
    // AAP_BYTES_TAG below, which exists so the constant is stated once.
    'int:-2': aapBytes(x.buffer),
    'int:-3': aapBytes(y.buffer)
  };
}

function aapPair() {
  if (!aapGuardContext('pairing')) return;
  var name = prompt('A short name for this security key or device:');
  if (!name) return;

  var challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  /* The registration challenge is NOT server-issued, deliberately. §5 pairing is
     an authenticated admin action establishing a NEW key; there is no prior key
     to bind a server challenge to, and the server never verifies attestation
     here — it validates the COSE key by constructing it. A random local
     challenge satisfies the API without implying a guarantee we do not make. */
  navigator.credentials.create({
    publicKey: {
      challenge: challenge,
      rp: { name: 'Nemesis', id: location.hostname },
      user: {
        id: new TextEncoder().encode(name),
        name: name,
        displayName: name
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'preferred' },
      timeout: 60000,
      attestation: 'none'
    }
  }).then(function (cred) {
    var cose;
    try {
      cose = aapCoseFromCredential(cred);
    } catch (e) {
      alert('Pairing failed.\n\n' + e.message);
      return null;
    }
    return fetch('/api/admin-approval/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        authenticator_id: cred.id,
        user_id: name,
        mode: 1,          /* MODE_WEBAUTHN */
        cose_alg: -7,
        public_key: cose
        /* rp_id_hash_b64 deliberately omitted: the server derives AND PINS its
           own RP ID on first pairing, which is the one place that may happen.
           Sending ours would let the browser choose what credentials are bound
           to. */
      })
    }).then(function (r) { return r.json(); });
  }).then(function (j) {
    if (!j) return;
    if (!j.ok) { aapFail('Pairing was refused.', j); return; }
    var msg = 'Registered.';
    if (j.rp_id_pinned_now) {
      msg += '\n\nThis appliance pinned its security-key identity as "' +
             j.rp_id_pinned_now + '". Keys registered here are bound to that ' +
             'name and will not work if it changes.';
    }
    if (!j.can_unlock) {
      msg += '\n\n' + (j.unlock_refusal || 'A second key is still required.');
    }
    alert(msg);
    location.reload();
  }).catch(function (e) {
    /* NotAllowedError is the user cancelling or the timeout elapsing — not a
       fault, and saying "failed" for it trains people to ignore real errors. */
    if (e && e.name === 'NotAllowedError') return;
    alert('Pairing failed.\n\n' + (e && e.message ? e.message : e));
  });
}

/* ── the approval ceremony (dashboard) ──────────────────────────────────── */

/* Approve or reject a pending proposal. Recording the DECISION is separate from
   EXECUTING it, on purpose and at the server too — the audit trail needs both
   moments, so this only records. */
function aapRespond(pid, response) {
  if (response === 'rejected' && !confirm('Reject this proposal?')) return;
  fetch('/api/ai/proposal/' + encodeURIComponent(pid) + '/respond', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ response: response })
  }).then(function (r) { return r.json(); })
    .then(function (j) {
      if (!j.ok) { aapFail('Could not record that decision.', j); return; }
      location.reload();
    })
    .catch(function () { alert('Could not reach the server.'); });
}

/* Execute an approved proposal.
 *
 * Some action classes additionally require a signed admin approval (A2). Rather
 * than the caller deciding, this ATTEMPTS the plain execute first and only runs
 * the ceremony if the server says one is needed — the server is the authority on
 * which classes are gated, and duplicating that list here would create a second
 * source of truth that could disagree with it.
 */
function aapExecute(pid, needsApproval) {
  if (!needsApproval) {
    fetch('/api/ai/proposal/' + encodeURIComponent(pid) + '/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    }).then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) { aapFail('Execution failed.', j); return; }
        location.reload();
      })
      .catch(function () { alert('Could not reach the server.'); });
    return;
  }
  aapApproveAndExecute(pid);
}

/* The full A2 ceremony: request an approval, show the match code, collect a
   signature, execute. */
function aapApproveAndExecute(pid) {
  if (!aapGuardContext('approval')) return;

  var el = document.getElementById('aap-proposal-' + pid);
  var actionClass = el ? el.getAttribute('data-action-class') : '';
  var target = el ? el.getAttribute('data-row-id') : '';
  var proposed = el ? el.getAttribute('data-proposed') : '';
  var authId = el ? el.getAttribute('data-authenticator') : '';
  if (!authId) {
    alert('No security key is registered for approvals.\n\n' +
          'Register two in Settings before approving this action.');
    return;
  }

  /* action_params must be the EXACT bytes the server will rebuild and compare.
     Built to match core/admin_approval_local.local_action_params(): JSON with
     sorted keys and no whitespace. A mismatch here produces a signature that
     never verifies, so the shape is pinned rather than convenient. */
  var params = JSON.stringify({
    action_class: actionClass,
    proposal_id: Number(pid),
    proposed_action: proposed,
    row_id: String(target),
    v: 1
  });
  var paramsB64 = btoa(params);

  fetch('/api/admin-approval/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      capability: actionClass,
      target: String(target),
      action_params_b64: paramsB64,
      authenticator_id: authId
    })
  }).then(function (r) { return r.json(); })
    .then(function (j) {
      if (!j.ok) { aapFail('Could not start the approval.', j); return null; }
      /* The match code is compared BY EYE against what the device shows. It is
         the out-of-band check that the request being signed is the one that was
         actually made, so it is shown BEFORE the prompt, not after. */
      if (!confirm('Approval code: ' + j.match_code + '\n\n' +
                   'Check this matches what your device shows, then continue ' +
                   'to approve:\n\n' + actionClass + ' -> ' + target)) {
        return null;
      }
      return navigator.credentials.get({
        publicKey: {
          challenge: aapB64uToBuf(j.challenge_b64.replace(/\+/g, '-').replace(/\//g, '_')),
          allowCredentials: [{ type: 'public-key', id: aapB64uToBuf(authId) }],
          userVerification: 'preferred',
          timeout: 60000,
          rpId: location.hostname
        }
      }).then(function (assertion) {
        return fetch('/api/ai/proposal/' + encodeURIComponent(pid) + '/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            approval_request_id: j.request_id,
            authenticator_data_b64: aapBufToB64(assertion.response.authenticatorData),
            client_data_json_b64: aapBufToB64(assertion.response.clientDataJSON),
            signature_b64: aapBufToB64(assertion.response.signature)
          })
        }).then(function (r) { return r.json(); });
      });
    })
    .then(function (j) {
      if (!j) return;
      if (!j.ok) { aapFail('The action was not carried out.', j); return; }
      location.reload();
    })
    .catch(function (e) {
      if (e && e.name === 'NotAllowedError') return;
      alert('Approval failed.\n\n' + (e && e.message ? e.message : e));
    });
}
