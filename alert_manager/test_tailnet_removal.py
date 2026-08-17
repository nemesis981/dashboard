"""Tests for tailscale_api's tailnet device removal.

Run:  python3 alert_manager/test_tailnet_removal.py

No network. `requests` and the token exchange are replaced with fakes, so this
exercises the real decision logic without touching a live tailnet -- deleting a
real node to test a delete path is not a test, it is an outage.

WHAT THIS IS ACTUALLY GUARDING. Revocation is now a claim about the NETWORK, not
about Nemesis's bookkeeping. The failure that matters is therefore not "removal
broke" -- that is loud. It is "removal did not happen and reported success
anyway", which would put a device the owner believes is off the VPN back in the
allowlist with nothing to show for it. So nearly every check below is about an
outcome that must NOT be `confirmed`, and `test_only_removed_is_confirmed` is
the backstop: it walks every state the module defines and asserts exactly one of
them counts.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tailscale_api as T  # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


class FakeResp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class FakeRequests:
    """Records calls and returns queued responses."""

    class RequestException(Exception):
        pass

    def __init__(self, get=None, delete=None):
        self._get = get
        self._delete = delete
        self.deleted_urls = []
        self.get_calls = 0

    def get(self, url, **kw):
        self.get_calls += 1
        if isinstance(self._get, Exception):
            raise self._get
        return self._get

    def delete(self, url, **kw):
        self.deleted_urls.append(url)
        if isinstance(self._delete, Exception):
            raise self._delete
        return self._delete

    def post(self, *a, **kw):
        raise AssertionError("no POST expected in these tests")


def node(nid, addrs, hostname="", name=""):
    return {"nodeId": nid, "addresses": addrs,
            "hostname": hostname, "name": name}


def install(get=None, delete=None, configured=True):
    """Swap in fakes. Returns the FakeRequests so callers can inspect it."""
    fr = FakeRequests(get=get, delete=delete)
    fr.RequestException = FakeRequests.RequestException
    T.requests = fr
    T._get_access_token = lambda: "fake-token"
    if configured:
        os.environ["TAILSCALE_OAUTH_CLIENT_ID"] = "fake-id"
        os.environ["TAILSCALE_OAUTH_CLIENT_SECRET"] = "fake-secret"
    else:
        os.environ.pop("TAILSCALE_OAUTH_CLIENT_ID", None)
        os.environ.pop("TAILSCALE_OAUTH_CLIENT_SECRET", None)
    return fr


DEVICES = {"devices": [
    node("n-aaa", ["100.64.0.10", "fd7a:115c:a1e0::a"], "laptop", "laptop.tail1.ts.net"),
    node("n-bbb", ["100.64.0.11"], "desktop", "desktop.tail1.ts.net"),
    node("n-ccc", ["100.64.0.12"], "shared", "shared.tail1.ts.net"),
    node("n-ddd", ["100.64.0.13"], "shared", "shared2.tail1.ts.net"),
]}


def test_happy_path():
    print("\n[confirmed removal]")
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    r = T.remove_device_by_address(address="100.64.0.10")
    check("state is REMOVED", r.state, T.Removal.REMOVED)
    check("confirmed is True", r.confirmed, True)
    check("deleted the matching node", "n-aaa" in fr.deleted_urls[0], True)
    check("exactly one delete issued", len(fr.deleted_urls), 1)

    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(204))
    check("204 also counts as removed",
          T.remove_device_by_address(address="100.64.0.11").state,
          T.Removal.REMOVED)


def test_not_found_is_not_success():
    print("\n[no match -> NOT confirmed]")
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    r = T.remove_device_by_address(address="100.64.0.99")
    check("state is NOT_FOUND", r.state, T.Removal.NOT_FOUND)
    check("confirmed is False", r.confirmed, False)
    check("nothing was deleted", fr.deleted_urls, [])
    check("detail says it could not be distinguished",
          "cannot be distinguished" in r.detail, True)


def test_address_match_is_exact():
    print("\n[address matching is exact, not substring]")
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    # "100.64.0.1" is a prefix of "100.64.0.10"/"...11"/"...12" -- a substring
    # match would delete the wrong node, which is unrecoverable by noticing later.
    r = T.remove_device_by_address(address="100.64.0.1")
    check("prefix does not match", r.state, T.Removal.NOT_FOUND)
    check("nothing deleted on a prefix", fr.deleted_urls, [])


def test_ambiguous_refuses():
    print("\n[ambiguous match -> refuse, do not guess]")
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    r = T.remove_device_by_address(hostname="shared")
    check("state is AMBIGUOUS", r.state, T.Removal.AMBIGUOUS)
    check("confirmed is False", r.confirmed, False)
    check("nothing was deleted", fr.deleted_urls, [])


def test_hostname_fallback():
    print("\n[hostname fallback]")
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    check("bare hostname matches",
          T.remove_device_by_address(hostname="laptop").state, T.Removal.REMOVED)
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    check("FQDN first label matches",
          T.remove_device_by_address(hostname="desktop.tail1.ts.net").state,
          T.Removal.REMOVED)
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    check("address wins over hostname when both given",
          T.remove_device_by_address(address="100.64.0.10",
                                     hostname="desktop").state,
          T.Removal.REMOVED)
    check("...and it deleted the ADDRESS's node", "n-aaa" in fr.deleted_urls[0], True)


def test_forbidden_is_its_own_state():
    print("\n[missing devices:core scope -> FORBIDDEN, not a generic failure]")
    fr = install(get=FakeResp(403), delete=FakeResp(200))
    r = T.remove_device_by_address(address="100.64.0.10")
    check("403 on list -> FORBIDDEN", r.state, T.Removal.FORBIDDEN)
    check("confirmed is False", r.confirmed, False)
    check("names the scope", "devices:core" in r.detail, True)

    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(403))
    r = T.remove_device_by_address(address="100.64.0.10")
    check("403 on delete -> FORBIDDEN", r.state, T.Removal.FORBIDDEN)
    check("warns the device is STILL on the VPN",
          "STILL ON THE VPN" in r.detail, True)


def test_delete_404_is_not_success():
    print("\n[404 on delete is NOT success here (unlike revoke_key)]")
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(404))
    r = T.remove_device_by_address(address="100.64.0.10")
    check("state is FAILED", r.state, T.Removal.FAILED)
    check("confirmed is False", r.confirmed, False)


def test_transport_and_http_failures():
    print("\n[transport / HTTP failures never read as success]")
    fr = install(get=FakeResp(200, DEVICES),
                 delete=FakeRequests.RequestException("connection reset"))
    r = T.remove_device_by_address(address="100.64.0.10")
    check("transport error -> FAILED", r.state, T.Removal.FAILED)
    check("confirmed is False", r.confirmed, False)

    fr = install(get=FakeResp(500), delete=FakeResp(200))
    r = T.remove_device_by_address(address="100.64.0.10")
    check("500 on list -> FAILED", r.state, T.Removal.FAILED)

    fr = install(get=FakeResp(200, {}), delete=FakeResp(200))
    r = T.remove_device_by_address(address="100.64.0.10")
    check("malformed list payload -> FAILED, not empty-tailnet",
          r.state, T.Removal.FAILED)


def test_not_configured():
    print("\n[no credentials -> explicit state, nothing attempted]")
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200), configured=False)
    r = T.remove_device_by_address(address="100.64.0.10")
    check("state is NOT_CONFIGURED", r.state, T.Removal.NOT_CONFIGURED)
    check("confirmed is False", r.confirmed, False)
    check("no API call attempted", fr.get_calls, 0)


def test_no_handle_at_all():
    print("\n[no address and no hostname]")
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    r = T.remove_device_by_address()
    check("state is NOT_FOUND", r.state, T.Removal.NOT_FOUND)
    check("confirmed is False", r.confirmed, False)
    check("no API call attempted", fr.get_calls, 0)


def test_node_id_is_url_quoted():
    print("\n[node id is percent-encoded into the URL path]")
    evil = {"devices": [node("../../tailnet/-/keys", ["100.64.0.20"])]}
    fr = install(get=FakeResp(200, evil), delete=FakeResp(200))
    T.remove_device_by_address(address="100.64.0.20")
    url = fr.deleted_urls[0]
    check("no raw path traversal in the URL", "../" in url, False)
    check("slashes were escaped", "%2F" in url, True)
    check("still targets the device endpoint",
          url.startswith("https://api.tailscale.com/api/v2/device/"), True)


def test_only_removed_is_confirmed():
    print("\n[backstop: exactly one state counts as confirmed]")
    states = [v for k, v in vars(T.Removal).items()
              if isinstance(v, str) and not k.startswith("_") and k.isupper()]
    confirmed = [s for s in states
                 if T.RemovalResult(s, "").confirmed]
    check("every state enumerated", len(states) >= 6, True)
    check("exactly one confirmed state", confirmed, [T.Removal.REMOVED])


def test_can_manage_devices_probe():
    print("\n[capability probe]")
    install(get=FakeResp(200, DEVICES))
    ok, why = T.can_manage_devices()
    check("probe passes with scope", ok, True)

    install(get=FakeResp(403))
    ok, why = T.can_manage_devices()
    check("probe fails without scope", ok, False)
    check("probe names the scope", "devices:core" in why, True)

    install(get=FakeResp(200, DEVICES), configured=False)
    ok, why = T.can_manage_devices()
    check("probe fails with no creds", ok, False)

    # The probe must never delete anything -- it is advertised as read-only.
    fr = install(get=FakeResp(200, DEVICES), delete=FakeResp(200))
    T.can_manage_devices()
    check("probe issued no DELETE", fr.deleted_urls, [])


if __name__ == "__main__":
    print("tailnet removal tests")
    _real_requests = T.requests
    _real_token = T._get_access_token
    _saved_env = {k: os.environ.get(k) for k in
                  ("TAILSCALE_OAUTH_CLIENT_ID", "TAILSCALE_OAUTH_CLIENT_SECRET")}
    try:
        test_happy_path()
        test_not_found_is_not_success()
        test_address_match_is_exact()
        test_ambiguous_refuses()
        test_hostname_fallback()
        test_forbidden_is_its_own_state()
        test_delete_404_is_not_success()
        test_transport_and_http_failures()
        test_not_configured()
        test_no_handle_at_all()
        test_node_id_is_url_quoted()
        test_only_removed_is_confirmed()
        test_can_manage_devices_probe()
    finally:
        T.requests = _real_requests
        T._get_access_token = _real_token
        for k, v in _saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
