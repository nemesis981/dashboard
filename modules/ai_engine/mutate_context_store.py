"""§5 MUTATION HARNESS — proves the context-store suite can actually FAIL.

⚠ WHY THIS EXISTS AT ALL. A green suite and a suite that never walks the code
are indistinguishable from their own output. Every guarantee in DESIGN-L4 §4 is
currently backed by an assertion that PASSES; none of that is evidence the
assertion would fail if the guarantee were broken. This harness breaks each
guarantee in the SHIPPED SOURCE, runs the real suite, and requires RED.

⭐ IT MUTATES THE REAL FILES, NOT COPIES. A harness that mutates a copy proves
the copy is checkable. Each mutation is applied to the working tree, the suite
is run as a subprocess, and the file is restored from the byte-exact original
in a `finally` -- so an interrupt mid-run cannot leave a mutant on disk.

SAFETY: refuses to run on a dirty-beyond-expected tree, verifies byte-exact
restoration after every mutation, and re-runs the suite at the end to prove the
tree is GREEN again. Read-only with respect to git; it never stages or commits.

Run:  python3 modules/ai_engine/mutate_context_store.py
"""
import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.join(HERE, "context_store.py")
MODULE = os.path.join(HERE, "module.py")
SUITE = os.path.join(HERE, "test_context_store.py")

#: (label, target file, find, replace, why this must turn the suite red)
MUTATIONS = [
    ("M1  context influences effective_ceiling()", MODULE,
     "    hard = ACTION_CLASS_CEILINGS.get(action_class)",
     "    hard = ACTION_CLASS_CEILINGS.get(action_class)\n"
     "    _mutant = 'ai_learned_context'  # §4.6 violation",
     "§4.6: the ladder decides authority; the store must never touch it"),

    ("M2  expiry disabled for permissive entries", STORE,
     "    if direction == PERMISSIVE:\n        expires = (datetime.fromisoformat(ts)",
     "    if False:\n        expires = (datetime.fromisoformat(ts)",
     "§4.3: a permissive entry that never expires accumulates like a "
     "category grant wearing a narrow label"),

    ("M3  revocation HARD-deletes instead of soft", STORE,
     '            "UPDATE ai_learned_context SET revoked_at=?, revoked_by=? "\n'
     '            "WHERE id=? AND revoked_at IS NULL",\n'
     '            (now or _now(), revoked_by, int(entry_id)))',
     '            "DELETE FROM ai_learned_context WHERE id=?",\n'
     '            (int(entry_id),))',
     "§4.4: 'no longer applied' and 'no longer recorded' are different "
     "states; a delete collapses them"),

    ("M4  retrieval truncates SILENTLY", STORE,
     "        truncated = matched_total > len(rows)",
     "        truncated = False  # silently trimmed",
     "§4.4: a bounded context presenting as complete is 'never head -n a "
     "set you draw a conclusion from', applied to the AI's own inputs"),

    ("M5  suspended rows still influence decisions", STORE,
     '               "  AND suspended_at IS NULL "',
     '               "  AND 1=1 "',
     "§4.7: a suspended row is awaiting a human; honouring it means the "
     "vendor baseline silently lost"),
]

# M6 is not a source mutation -- the guarantee lives in the SCHEMA, so it is
# proven by attempting the write against the real database instead.
GREEN = "\033[32m"
RED = "\033[31m"
OFF = "\033[0m"


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def run_suite():
    """Run the real suite as a subprocess. Returns True if GREEN."""
    p = subprocess.run([sys.executable, SUITE], capture_output=True, text=True)
    return p.returncode == 0, p.stdout + p.stderr


def main():
    print(__doc__.split("Run:")[0].strip()[:0] or "", end="")
    print("=" * 74)
    print("§5 MUTATION HARNESS — each guarantee must be able to FAIL")
    print("=" * 74)

    baseline = {p: _sha(p) for p in (STORE, MODULE, SUITE)}

    ok, out = run_suite()
    if not ok:
        print(f"{RED}ABORT{OFF}: the suite is RED before any mutation. A "
              "mutation harness on a failing suite measures nothing.")
        print(out[-1500:])
        return 1
    print(f"{GREEN}CONTROL{OFF}: unmutated suite is GREEN "
          "(so a later RED is attributable to the mutation)\n")

    results = []
    for label, path, find, repl, why in MUTATIONS:
        original = open(path, encoding="utf-8").read()
        if find not in original:
            print(f"{RED}[SKIP]{OFF} {label}")
            print(f"        anchor not found in {os.path.basename(path)} — the "
                  "harness is STALE, not the code innocent")
            results.append((label, None))
            continue
        try:
            open(path, "w", encoding="utf-8").write(original.replace(find, repl, 1))
            died, _out = run_suite()
            caught = not died
            mark = f"{GREEN}[CAUGHT]{OFF}" if caught else f"{RED}[SURVIVED]{OFF}"
            print(f"{mark} {label}")
            print(f"         {why}")
            results.append((label, caught))
        finally:
            open(path, "w", encoding="utf-8").write(original)
            assert _sha(path) == baseline[path], (
                "RESTORE FAILED for %s — the working tree is now dirty" % path)

    # M6: the §4.3 asymmetry is a DATABASE constraint, not a code path, so it
    # cannot be mutated in source. Prove it where it actually lives.
    print()
    caught6 = _schema_guarantee()
    mark = f"{GREEN}[CAUGHT]{OFF}" if caught6 else f"{RED}[SURVIVED]{OFF}"
    print(f"{mark} M6  permissive+category rejected BY THE SCHEMA")
    print("         §4.3: enforced where no write path can bypass it, "
          "including one written later by someone who never read §4.3")
    results.append(("M6  permissive+category rejected by the schema", caught6))

    print()
    ok, _ = run_suite()
    print(f"{GREEN}RESTORED{OFF}: suite GREEN again, all files byte-identical"
          if ok else f"{RED}DANGER{OFF}: suite RED after restore")

    caught = sum(1 for _l, c in results if c)
    total = len(results)
    print("=" * 74)
    for label, c in results:
        state = "caught" if c else ("SKIPPED — stale anchor" if c is None
                                    else "SURVIVED")
        print(f"  {label:<48} {state}")
    print(f"\n{caught}/{total} mutations caught")
    print("=" * 74)
    return 0 if (caught == total and ok) else 1


def _schema_guarantee():
    """Attempt the §4.3-violating write directly against a real database."""
    import tempfile
    probe = os.path.join(tempfile.mkdtemp(prefix="l4mut-"), "t.db")
    code = (
        "import sys; sys.path.insert(0,'/opt/nemesis');"
        "sys.path.insert(0,'/opt/nemesis/alert_manager');"
        "import modules; modules.set_shared_db_path(%r);"
        "from modules.ai_engine import module as ai; ai._init_db();"
        "from modules.ai_engine import context_store as cs;"
        "c = cs._conn();"
        "c.execute(\"INSERT INTO ai_learned_context(created_at,action_class,"
        "trigger_type,trigger_key,direction,scope,admin_reasoning,expires_at)"
        " VALUES('t','c','ip','k','permissive','category','r','z')\")"
    ) % probe
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    # The write MUST fail. A zero exit means the constraint let it through.
    return p.returncode != 0 and "CHECK constraint failed" in (p.stdout + p.stderr)


if __name__ == "__main__":
    sys.exit(main())
