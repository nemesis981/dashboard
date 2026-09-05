"""The key-pack checkout link: prefilled, or absent. Never broken.

WHY THIS EXISTS (D5 in the key-pack design). A free user has no reason to know
their installation ID, but the issuer cannot sign a pack purchase without one --
the intake service reads `meta.custom_data.install_id` and parks any order lacking
it as `needs_attention` for a human to reconcile by hand. So the dashboard has to
attach it to the checkout link itself.

THE FAILURE MODE THIS GUARDS IS NOT A BROKEN PAGE, IT IS A BAD PURCHASE. Every
degraded state here resolves to rendering NO button, because a checkout link that
is missing the install id still takes someone's money -- it just cannot deliver
what they bought without manual intervention. "No button" is recoverable; "money
in a reconciliation queue" is not, at least not cheaply. That asymmetry is why
every branch below fails toward absence rather than toward a best-effort link.

WHAT IS DELIBERATELY NOT ASSERTED: a pack SIZE. How much capacity a pack grants
lives in the backend's variant map, which this repo cannot read. Any number shown
on this page would be unverifiable here and contradictable by the storefront after
someone has paid, so the copy states none and there is nothing to test.
"""
import os
import sys
import tempfile

# Must precede `import dashboard`. `data_dir()` is the dirname of the DB path, and
# the Flask secret is resolved under it -- so without this redirect the import
# reads /var/lib/nemesis, fails on permissions, and calls sys.exit(). That is a
# SystemExit, which `except Exception` does not catch: the suite would die during
# import with no FATAL line and no traceback, looking like a crash rather than a
# harness problem. Same mechanism test_downgrade_guard.py uses.
os.environ["NEMESIS_DB_PATH"] = os.path.join(
    tempfile.mkdtemp(prefix="kpc-"), "alerts.db")

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Copied from core/test_downgrade_guard.py rather than invented: importing
# dashboard under a DIFFERENT path than the service uses would test a module graph
# that never runs in production, and the failure would look like a test-only quirk
# in either direction.
for _p in (_REPO,
           os.path.join(_REPO, "alert_manager"),
           os.path.join(_REPO, "core_module", "hw_monitor"),
           os.path.join(_REPO, "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_failures = []
_ran = []


def check(label, got, want):
    _ran.append(label)
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok   %s" % label)


def check_true(label, ok, detail=""):
    _ran.append(label)
    if ok:
        print("  ok   %s" % label)
    else:
        _failures.append("%s %s" % (label, detail))
        print("  FAIL %s %s" % (label, detail))


def die(msg):
    print("FATAL: %s" % msg)
    sys.exit(1)


try:
    import dashboard
except BaseException:  # BaseException: dashboard calls sys.exit() on config failure
    import traceback
    traceback.print_exc()
    die("could not import dashboard")

BUILD = dashboard._key_pack_checkout_url
GOOD = "https://store.example.com/checkout/buy/abc-123"
#: Obviously synthetic. A real install id is a hardware fingerprint of a real
#: machine, and this repo is public -- see Rule 8.
IID = "INSTALL-ID-FOR-TESTS-0001"


# ── A. The link is only built when everything needed is present ──────────────

def test_absent_configuration_yields_no_link():
    """No storefront configured -> no button. This is the DEFAULT state today.

    The variant is not minted yet, so KEY_PACK_CHECKOUT_URL ships empty. The
    button must therefore be absent on every install in the field right now --
    which makes this the branch that is actually exercised in production.
    """
    check("empty base -> no link", BUILD(IID, base=""), "")
    check("whitespace-only base -> no link", BUILD(IID, base="   "), "")


def test_missing_install_id_yields_no_link():
    """No install id -> no button, even with a perfectly good storefront.

    This is the whole point of the feature: a link without the id is exactly the
    purchase that cannot be signed. Rendering it would be worse than rendering
    nothing, so the check is not "is the id nice to have" but "is it present".
    """
    check("no install id -> no link", BUILD("", base=GOOD), "")
    check("None install id -> no link", BUILD(None, base=GOOD), "")
    check("whitespace install id -> no link", BUILD("   ", base=GOOD), "")


def test_the_happy_path_carries_the_id_under_the_contract_key():
    """The one shape that must work, asserted against the backend's real key.

    `checkout[custom][install_id]` is a cross-repo contract with intake/app.py,
    not a formatting preference -- so this asserts the encoded key explicitly
    rather than just "some id is in there somewhere".
    """
    url = BUILD(IID, base=GOOD)
    check_true("happy path builds a link", url != "", "(got empty)")
    check_true("keeps the configured base",
               url.startswith(GOOD + "?"), "(got %r)" % url)
    check_true("carries the id under the contract key",
               "checkout%5Bcustom%5D%5Binstall_id%5D=" + IID in url,
               "(got %r)" % url)


# ── B. Scheme handling: this value lands in an href ──────────────────────────

def test_only_https_is_accepted():
    """A non-https base is refused, and javascript: is the reason why.

    This string is interpolated into an href on the page that displays licence
    state. A javascript: URL there executes rather than navigates. Jinja escaping
    does not help -- the value is a syntactically valid attribute either way.
    """
    check("javascript: refused",
          BUILD(IID, base="javascript:alert(document.cookie)"), "")
    check("http refused", BUILD(IID, base="http://store.example.com/buy/x"), "")
    check("data: refused", BUILD(IID, base="data:text/html,<script>1</script>"), "")
    check("scheme-relative refused", BUILD(IID, base="//store.example.com/buy/x"), "")
    check("bare path refused", BUILD(IID, base="/checkout/buy/x"), "")
    check("https with no host refused", BUILD(IID, base="https:///buy/x"), "")


def test_unparseable_configuration_is_refused_not_raised():
    """Bad config must not 500 the licensing page.

    This runs on every render, not at startup, so an exception here takes down the
    page that tells someone what licence they have -- a strictly worse outcome
    than a missing button.
    """
    try:
        got = BUILD(IID, base="https://[oops")
        check("unparseable base -> no link", got, "")
    except Exception as e:
        check_true("unparseable base must not raise", False, "(raised %r)" % e)


# ── C. The id is placed as data, never as text ───────────────────────────────

def test_an_install_id_cannot_inject_extra_parameters():
    """A hostile-looking id becomes one parameter VALUE, not more parameters.

    install_id is machine-derived rather than user-typed, so this is defence
    against a shape rather than a known attacker. It is cheap, and the
    alternative -- trusting that the fingerprint format never changes -- is the
    kind of premise that stops being true without anyone revisiting the code
    that assumed it.
    """
    hostile = "abc&discount=100&x=y"
    url = BUILD(hostile, base=GOOD)
    check_true("hostile id does not introduce a discount parameter",
               "discount=100" not in url, "(got %r)" % url)
    check_true("hostile id is percent-encoded into one value",
               "abc%26discount%3D100%26x%3Dy" in url, "(got %r)" % url)
    check_true("exactly one parameter results",
               url.count("&") == 0, "(got %r)" % url)

    spaced = "id with spaces"
    check_true("spaces are encoded",
               "id+with+spaces" in BUILD(spaced, base=GOOD)
               or "id%20with%20spaces" in BUILD(spaced, base=GOOD),
               "(got %r)" % BUILD(spaced, base=GOOD))


def test_existing_query_parameters_survive():
    """An operator may configure a link that already carries parameters.

    Discount codes and campaign tags are configured on the URL itself, so
    replacing the whole query string would silently drop them -- a revenue bug
    that looks like nothing at all.
    """
    base = GOOD + "?discount=LAUNCH&aff=partner"
    url = BUILD(IID, base=base)
    check_true("existing discount survives", "discount=LAUNCH" in url,
               "(got %r)" % url)
    check_true("existing affiliate tag survives", "aff=partner" in url,
               "(got %r)" % url)
    check_true("and the id is still added",
               "checkout%5Bcustom%5D%5Binstall_id%5D=" + IID in url,
               "(got %r)" % url)


def test_a_stale_install_id_in_configuration_is_replaced_not_duplicated():
    """Two values for one key is resolved by the storefront, not by us.

    A configured URL copy-pasted from a previous machine's checkout would carry
    that machine's id. Appending ours would leave the storefront to pick, and it
    may well pick first-wins -- binding the purchase to someone else's install.
    """
    base = GOOD + "?checkout[custom][install_id]=SOMEONE-ELSES-MACHINE"
    url = BUILD(IID, base=base)
    check_true("the stale id is gone", "SOMEONE-ELSES-MACHINE" not in url,
               "(got %r)" % url)
    check_true("ours replaced it",
               "checkout%5Bcustom%5D%5Binstall_id%5D=" + IID in url,
               "(got %r)" % url)
    check("exactly one install_id parameter",
          url.count("install_id"), 1)


def test_a_fragment_is_preserved():
    """Faithful to what the operator configured, rather than quietly rewriting it."""
    url = BUILD(IID, base=GOOD + "#pricing")
    check_true("fragment kept", url.endswith("#pricing"), "(got %r)" % url)
    check_true("query still precedes the fragment",
               "install_id" in url.split("#")[0], "(got %r)" % url)


# ── D. Tier gating: the pack does nothing for a commercial install ───────────

def test_the_view_offers_the_pack_only_to_non_commercial_installs():
    """A commercial licence ignores remote_cap_bonus entirely.

    `remote_cap_for_license` returns on the commercial path before it ever reads
    the bonus, and the backend's variant map refuses the field on a commercial
    variant. So selling a pack to a commercial install takes money for a key that
    grants that install nothing -- which makes this gate a correctness check, not
    a presentational one.

    Exercised through the real `_license_view` rather than by re-implementing its
    rule here: a test that re-states the condition it is checking passes against
    a mutation of the code it is meant to guard.
    """
    saved_url = dashboard.KEY_PACK_CHECKOUT_URL
    saved_status = dashboard.__dict__.get("_license_view")
    from core import entitlements as ent
    real_status = ent.license_status
    real_budget = ent.remote_device_budget
    try:
        dashboard.KEY_PACK_CHECKOUT_URL = GOOD

        class _Census:
            reconciled = True
            reason = ""
            tailnet_only = []
            known_not_entitled = []
            count = 1

        ent.remote_device_budget = lambda *a, **k: (1, 5, _Census())

        ent.license_status = lambda *a, **k: ("free", "valid", "")
        free_view = dashboard._license_view()
        check_true("free tier is offered the pack",
                   free_view["checkout_url"] != "", "(got empty)")
        check_true("and the link carries this machine's id",
                   free_view["install_id"] != ""
                   and free_view["install_id"] in free_view["checkout_url"],
                   "(id %r, url %r)" % (free_view["install_id"],
                                        free_view["checkout_url"]))

        ent.license_status = lambda *a, **k: ("commercial", "valid", "")
        comm_view = dashboard._license_view()
        check("commercial tier is NOT offered the pack",
              comm_view["checkout_url"], "")
    finally:
        dashboard.KEY_PACK_CHECKOUT_URL = saved_url
        ent.license_status = real_status
        ent.remote_device_budget = real_budget
        if saved_status is not None:
            dashboard.__dict__["_license_view"] = saved_status


def test_the_view_never_raises_and_always_defines_the_key():
    """The template reads `checkout_url` unconditionally; it must always exist.

    An undefined key would render as empty under Jinja's default and look
    identical to "correctly absent" -- so the absence of this check would hide
    exactly the bug it is here to catch.
    """
    view = dashboard._license_view()
    check_true("checkout_url is always present", "checkout_url" in view,
               "(keys: %r)" % sorted(view))
    check_true("and is a string", isinstance(view.get("checkout_url"), str),
               "(got %r)" % type(view.get("checkout_url")))


def test_the_shipped_default_is_absent():
    """Ships with no storefront configured, so no install shows a dead button.

    Asserted on the real module attribute rather than on a copy, because the
    whole claim is about what this repo actually ships.
    """
    check("shipped default is empty", dashboard.KEY_PACK_CHECKOUT_URL, "")
    check("so the default build yields nothing",
          BUILD(IID, base=None) if dashboard.KEY_PACK_CHECKOUT_URL == "" else "",
          "")


EXPECTED_CHECKS = 34

if __name__ == "__main__":
    print("=" * 66)
    print("key-pack checkout: prefilled, or absent -- never broken")
    print("=" * 66)
    test_absent_configuration_yields_no_link()
    test_missing_install_id_yields_no_link()
    test_the_happy_path_carries_the_id_under_the_contract_key()
    test_only_https_is_accepted()
    test_unparseable_configuration_is_refused_not_raised()
    test_an_install_id_cannot_inject_extra_parameters()
    test_existing_query_parameters_survive()
    test_a_stale_install_id_in_configuration_is_replaced_not_duplicated()
    test_a_fragment_is_preserved()
    test_the_view_offers_the_pack_only_to_non_commercial_installs()
    test_the_view_never_raises_and_always_defines_the_key()
    test_the_shipped_default_is_absent()

    print("\n" + "=" * 66)
    print("checks run: %d" % len(_ran))
    if len(_ran) != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d, expected %d" % (len(_ran), EXPECTED_CHECKS))
        sys.exit(1)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
