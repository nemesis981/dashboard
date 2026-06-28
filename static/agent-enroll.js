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
