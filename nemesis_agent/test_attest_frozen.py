#!/usr/bin/env python3
"""Frozen/PyInstaller builds are attestable (Tier 1 gap-scan item 5, 2026-08-23).

Before this, `evaluate()` returned ABSENT unconditionally on any frozen build, so
every Windows device was permanently unattested -- which mattered increasingly as
the Windows freeze pipeline became the real shipping path.

The agent ships in two shapes and they cannot be attested the same way, so the
manifest now declares which shape it describes. The property under test is not
just "frozen works" but that the two shapes cannot be CONFUSED: a source manifest
evaluated on a frozen install must not read as tampering, and a frozen manifest
must actually detect a modified executable.

Frozen-ness is simulated by monkeypatching `is_frozen()` and `executable_path()`
-- this process is not a PyInstaller bundle. That is a real limitation of the
harness and is why the digest is taken over a file the test controls: it proves
the comparison logic, not the PyInstaller integration. The integration itself was
exercised on a real frozen build during the 2026-08-22 freeze work.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attest

_pass = _fail = 0


def check(label, got, want=True):
    global _pass, _fail
    if got == want:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s   (got=%r want=%r)" % (label, got, want))


class FrozenAs:
    """Pretend to be a frozen build whose executable is `path`."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self._f, self._e = attest.is_frozen, attest.executable_path
        attest.is_frozen = lambda: True
        attest.executable_path = lambda: self.path
        return self

    def __exit__(self, *a):
        attest.is_frozen, attest.executable_path = self._f, self._e


def _exe(content=b"MZ fake frozen bundle v1"):
    d = tempfile.mkdtemp(prefix="frozen-")
    p = os.path.join(d, "nemesis-agent.exe")
    with open(p, "wb") as fh:
        fh.write(content)
    return p


# ═══════════════════════════════════════════════════════════════════════
print("\n== 1. a frozen build produces a frozen-shaped manifest ==")

exe = _exe()
with FrozenAs(exe):
    m = attest.build_manifest("1.0.2")
    check("kind is frozen", m["kind"], attest.KIND_FROZEN)
    check("exactly one entry (the executable)", len(m["files"]), 1)
    check("keyed by the executable basename", "nemesis-agent.exe" in m["files"])
    check("the digest is a sha256", len(list(m["files"].values())[0]), 64)

# CONTROL: a source build still produces the source shape, unchanged.
m_src = attest.build_manifest("1.0.2", root=os.path.dirname(attest.__file__))
check("CONTROL: a source build is still kind=source", m_src["kind"], attest.KIND_SOURCE)
check("CONTROL: ...and covers many files, not one", len(m_src["files"]) > 1)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 2. an intact frozen build ATTESTS ==")

exe = _exe()
root = tempfile.mkdtemp(prefix="froot-")
with FrozenAs(exe):
    attest.install_manifest(attest.build_manifest("1.0.2"), root=root)
    r = attest.evaluate(root=root, agent_version="1.0.2")
    check("state is attested", r["state"], attest.ATTESTED)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 3. a MODIFIED frozen executable FAILS -- the whole point ==")

exe = _exe()
root = tempfile.mkdtemp(prefix="froot2-")
with FrozenAs(exe):
    attest.install_manifest(attest.build_manifest("1.0.2"), root=root)
    # tamper AFTER the manifest was built
    with open(exe, "wb") as fh:
        fh.write(b"MZ fake frozen bundle v1 ... plus a backdoor")
    r = attest.evaluate(root=root, agent_version="1.0.2")
    check("state is FAILED, not absent and not attested", r["state"], attest.FAILED)
    # The operator-facing `detail` is a summary count; the STRUCTURED diff
    # carries the names. Both matter: a count with no names cannot be acted on,
    # and names with no count are hard to triage at fleet scale.
    check("the structured diff names the modified executable",
          r["diff"]["modified"], ["nemesis-agent.exe"])
    check("  ...and the detail summarises it as one modification",
          "modified=1" in r["detail"], True)

# CONTROL: restoring the original bytes attests again -- so the FAILED above was
# caused by the modification, not by anything incidental to the fixture.
with FrozenAs(exe):
    with open(exe, "wb") as fh:
        fh.write(b"MZ fake frozen bundle v1")
    r = attest.evaluate(root=root, agent_version="1.0.2")
    check("CONTROL: restoring the bytes attests again", r["state"], attest.ATTESTED)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 4. the two shapes cannot be confused ==")

# A SOURCE manifest on a FROZEN install: ABSENT, never FAILED. Reporting it as
# tampering is the false positive that gets the whole signal ignored.
root = tempfile.mkdtemp(prefix="froot3-")
src_manifest = attest.build_manifest("1.0.2", root=os.path.dirname(attest.__file__))
attest.install_manifest(src_manifest, root=root)
with FrozenAs(_exe()):
    r = attest.evaluate(root=root, agent_version="1.0.2")
    check("source manifest on a frozen agent -> ABSENT", r["state"], attest.ABSENT)
    check("  ...and the detail says which shape mismatched",
          "source" in r["detail"] and "frozen" in r["detail"], True)
    check("  ...and it is NOT reported as tampering", r["state"] != attest.FAILED, True)

# The reverse: a FROZEN manifest on a SOURCE install.
root = tempfile.mkdtemp(prefix="froot4-")
with FrozenAs(_exe()):
    frozen_manifest = attest.build_manifest("1.0.2")
attest.install_manifest(frozen_manifest, root=root)
r = attest.evaluate(root=root, agent_version="1.0.2")
check("frozen manifest on a source agent -> ABSENT", r["state"], attest.ABSENT)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 5. backwards compatibility: a manifest with no 'kind' ==")

check("absent kind reads as source", attest.manifest_kind({"files": {}}),
      attest.KIND_SOURCE)
check("explicit kind is honoured",
      attest.manifest_kind({"kind": "frozen", "files": {}}), attest.KIND_FROZEN)

# A pre-2026-08-23 manifest (no kind field) must still evaluate on a source
# install exactly as it did before -- this is the upgrade path for every
# already-deployed Linux agent.
root = tempfile.mkdtemp(prefix="froot5-")
legacy = dict(attest.build_manifest("1.0.2", root=os.path.dirname(attest.__file__)))
legacy.pop("kind")
attest.install_manifest(legacy, root=root)
r = attest.evaluate(root=root, agent_version="1.0.2")
check("a legacy manifest still evaluates (not ABSENT-by-shape)",
      r["state"] != attest.ABSENT or "shape" not in r.get("detail", ""), True)

# CONTROL: an empty-digest map must never attest -- a check that cannot fail.
try:
    attest.install_manifest({"kind": attest.KIND_FROZEN, "files": {}}, root=root)
    check("an empty frozen manifest is REFUSED at install", False, True)
except ValueError:
    check("an empty frozen manifest is REFUSED at install", True)

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
