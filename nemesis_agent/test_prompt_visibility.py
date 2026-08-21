#!/usr/bin/env python3
"""The dialog must be VISIBLE before anything blocks on it.

Run: python3 nemesis_agent/test_prompt_visibility.py

Regression cover for the bug Tier B found on 2026-08-03: the agent created its
prompt as a `transient` Toplevel parented to a WITHDRAWN root, which Windows
never maps. The window existed (class TkChild, visible=False), the agent blocked
in wait_window(), and nothing appeared on screen -- so a tier-4 device would
have hung at startup with no way for the user to answer or decline.

There is no tkinter on this build host, which is exactly why the original bug
survived 199 passing checks. These tests therefore cover the parts that CAN be
checked without a display: the viewability guard's logic, the console fallback
it enables, and the structural properties of each window shape.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import secret_prompt
from secret_prompt import DialogNotViewable, NoPromptAvailable

def _tk_really_importable():
    """Whether Tk can ACTUALLY be used on this machine, decided independently of
    the function under test.

    The checks below used to assert `_tk_available() is False` outright, because
    the build box had no python3-tk. That made the environment a silent premise:
    the moment Tk was installed (2026-08-20, to verify the agent settings window)
    both tests failed, reporting a defect in code that had not changed. A control
    whose answer depends on an unstated property of the machine is not a control.

    So the assertion becomes AGREEMENT: `_tk_available()` must match reality,
    whatever reality is here. That still catches the failure the original check
    cared about -- a `_tk_available()` stuck on one answer -- and it catches it on
    a machine WITH Tk too, which the original could not.
    """
    try:
        import tkinter                                        # noqa: PLC0415,F401
    except Exception:                                         # noqa: BLE001
        return False
    try:
        root = tkinter.Tk()
    except Exception:                                         # noqa: BLE001
        return False                    # importable but no usable display
    root.destroy()
    return True


_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def raises(fn):
    try:
        fn()
    except Exception as e:
        return type(e).__name__
    return "NO_EXCEPTION"


class FakeWin:
    """Minimal stand-in for a Tk window, so the guard is testable with no display."""

    def __init__(self, viewable=1, explode=False):
        self._viewable, self._explode = viewable, explode
        self.destroyed = False

    def update_idletasks(self):
        if self._explode:
            raise RuntimeError("tcl error")

    def update(self):
        if self._explode:
            raise RuntimeError("tcl error")

    def winfo_viewable(self):
        return self._viewable

    def destroy(self):
        self.destroyed = True


def main():
    print("the viewability guard")
    check("POSITIVE a mapped window passes",
          secret_prompt._require_viewable(FakeWin(viewable=1)), None)
    check("CONTROL an unmapped window raises DialogNotViewable",
          raises(lambda: secret_prompt._require_viewable(FakeWin(viewable=0))),
          "DialogNotViewable")
    check("CONTROL a window that errors on update() also raises, not passes",
          raises(lambda: secret_prompt._require_viewable(FakeWin(explode=True))),
          "DialogNotViewable")
    check("CONTROL winfo_viewable()==0 is not mistaken for 'unknown, assume fine'",
          raises(lambda: secret_prompt._require_viewable(FakeWin(viewable=0))),
          "DialogNotViewable")

    print("\nan invisible dialog falls back to the console, it does NOT block")
    real_tk, real_standalone = secret_prompt._tk_available, secret_prompt._prompt_secret_standalone
    calls = []
    try:
        secret_prompt._tk_available = lambda: True
        def boom(**kw):
            calls.append("standalone")
            raise DialogNotViewable("simulated invisible dialog")
        secret_prompt._prompt_secret_standalone = boom
        # No TTY here, so the console path raises NoPromptAvailable -- which is
        # itself the proof that the fallback was taken rather than blocking.
        got = raises(lambda: secret_prompt.prompt_secret_auto(
            kind=secret_prompt.SECRET_PASSWORD, mode=secret_prompt.UNLOCK))
        check("POSITIVE the GUI path was attempted first", calls, ["standalone"])
        check("CONTROL it then fell through to the console",
              got, "NoPromptAvailable")
    finally:
        secret_prompt._tk_available = real_tk
        secret_prompt._prompt_secret_standalone = real_standalone

    print("\nwindow-shape structure (the actual bug)")
    src = open(os.path.join(HERE, "secret_prompt.py")).read()
    standalone = src[src.index("def _prompt_secret_standalone"):src.index("def prompt_secret_auto")]
    parented = src[src.index("def prompt_secret(parent"):src.index("def _prompt_secret_standalone")]

    # Matched against the AST, not the text: both functions DESCRIBE the bug in
    # their docstrings, so a substring search finds the explanation and reports a
    # defect that is not there. (It did, first time round.)
    import ast

    def calls_in(func_name):
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == func_name)
        names = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Attribute):
                    names.add(f.attr)
                elif isinstance(f, ast.Name):
                    names.add(f.id)
        return names

    standalone_calls = calls_in("_prompt_secret_standalone")
    parented_calls = calls_in("prompt_secret")
    check("CONTROL the standalone path never CALLS withdraw()",
          "withdraw" in standalone_calls, False)
    check("CONTROL the standalone path never CALLS transient() or Toplevel()",
          bool({"transient", "Toplevel"} & standalone_calls), False)
    check("CONTROL the parented path really does call both",
          {"transient", "Toplevel"} <= parented_calls, True)
    check("the parented path keeps Toplevel + transient (correct with a real parent)",
          "Toplevel" in parented and "transient" in parented, True)
    check("the parented path checks viewability before grabbing",
          parented.index("_require_viewable") < parented.index("grab_set"), True)
    check("CONTROL ...and before blocking on wait_window",
          parented.index("_require_viewable") < parented.index("wait_window"), True)
    check("the standalone path checks viewability before mainloop",
          standalone.index("_require_viewable") < standalone.index("mainloop"), True)

    print("\nboth shapes share one form builder (same rules, same wording)")
    check("parented path uses _build_form", "_build_form" in parented, True)
    check("standalone path uses _build_form", "_build_form" in standalone, True)

    print("\nthe policy half is still importable either way")
    check("_tk_available agrees with whether Tk really works here",
          secret_prompt._tk_available(), _tk_really_importable())
    check("validate_secret still works headless",
          secret_prompt.validate_secret(secret_prompt.SECRET_PASSWORD, "abcdefghij")[0],
          True)

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
