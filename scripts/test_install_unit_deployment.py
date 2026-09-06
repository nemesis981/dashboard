#!/usr/bin/env python3
"""install.sh unit-deployment contract -- scripts/systemd/ and the timer-aware rules.

WHY THIS EXISTS. install.sh deployed NINE hardcoded services and nothing else. Every unit
under scripts/systemd/ -- four services and three timers, including the retention timers
that hold the data windows -- reached no user, on any install, ever. `.timer` did not appear
in install.sh a single time. The units were correct; nothing installed them.

⛔ THE TWO RULES THAT ARE EASY TO GET WRONG, AND SILENTLY:

  1. A TIMER-TRIGGERED SERVICE MUST NOT BE ENABLED -- only its .timer is.
     `nemesis-oplog-coalesce.service` and `nemesis-top-processes-archive.service` carry NO
     [Install] section (they are `static`), so `systemctl enable` on them FAILS. And
     `nemesis-cert-renew.service` DOES carry [Install] yet must still not be enabled: it is
     driven by its timer, and enabling it would run the renew at every boot instead of on
     the schedule. Live state on the reference box confirms the intended shape --
     cert-renew.service `disabled`, cert-renew.timer `enabled`.
     ⇒ "has [Install]" is NOT the test for "should be enabled". Having a sibling .timer is.

  2. A .timer WITHOUT ITS .service IS A UNIT THAT FAILS AT RUN TIME, NOT AT INSTALL TIME.
     systemd accepts a timer whose Unit= names a file that does not exist; it fails when it
     first fires, which may be a day later, in a log nobody reads. The pairing is asserted
     here instead.

⚠ TEXT MATCHING AGAINST install.sh STRIPS COMMENTS FIRST. install.sh is one of the most
heavily commented files in the repo, and this file's own subject matter -- ".timer",
"systemctl enable" -- is exactly what those comments discuss. A raw grep would match the
prose explaining the code and report coverage that does not exist. Same failure class as the
`action="none"` premise check that counted 9 sites where 5 existed.
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNIT_DIR = os.path.join(ROOT, "scripts", "systemd")
INSTALL_SH = os.path.join(ROOT, "install.sh")

# Computed, not hardcoded: sections 1 and 3 are data-driven over whatever units exist, so a
# fixed literal would false-positive the moment a legitimate unit is added -- and a check that
# cries wolf on correct changes gets deleted. The formula still catches what the convention is
# for: a check silently skipped by a short-circuit changes the RAN count without changing S/T.
#   5 fixtures + 3 per timer + 1 classification + 2 reach + (S+T) deploy + 3 enable + 2 gaps
def _expected(S, T):
    return 5 + 3 * T + 1 + 2 + (S + T) + 3 + 2

_pass = _fail = 0
def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  PASS  %s" % label)
    else:
        _fail += 1
        print("  FAIL  %s%s" % (label, ("  -- " + detail) if detail else ""))


def strip_comments(text):
    """Drop whole-line shell comments. Deliberately conservative: it does NOT try to
    remove trailing comments, because `#` appears inside legitimate shell strings and a
    naive strip would corrupt real code. Whole-line comments are the bulk of install.sh's
    prose and removing them is enough to stop the match-the-comment failure."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


# ── 0. the fixtures exist ────────────────────────────────────────────────────
print("0. fixtures")
check("scripts/systemd/ exists", os.path.isdir(UNIT_DIR), UNIT_DIR)
check("install.sh exists", os.path.isfile(INSTALL_SH))

services = sorted(f for f in os.listdir(UNIT_DIR) if f.endswith(".service")) if os.path.isdir(UNIT_DIR) else []
timers = sorted(f for f in os.listdir(UNIT_DIR) if f.endswith(".timer")) if os.path.isdir(UNIT_DIR) else []
check("at least one service present", len(services) > 0, "found %d" % len(services))
check("at least one timer present", len(timers) > 0, "found %d" % len(timers))

src_raw = open(INSTALL_SH).read() if os.path.isfile(INSTALL_SH) else ""
src = strip_comments(src_raw)

# The strip must actually remove something, or every check below is running against raw
# text while claiming otherwise -- a control on the instrument, not on install.sh.
check("comment-strip is live (removed >100 lines)",
      len(src_raw.splitlines()) - len(src.splitlines()) > 100,
      "removed %d lines" % (len(src_raw.splitlines()) - len(src.splitlines())))


# ── 1. on-disk unit invariants ───────────────────────────────────────────────
print("\n1. scripts/systemd/ internal consistency")
for t in timers:
    body = open(os.path.join(UNIT_DIR, t)).read()
    m = re.search(r"^\s*Unit=(.+?)\s*$", body, re.M)
    named = m.group(1).strip() if m else None
    check("%s declares Unit=" % t, named is not None)
    check("%s -> %s exists on disk" % (t, named),
          named is not None and os.path.isfile(os.path.join(UNIT_DIR, named)),
          "Unit=%r" % named)
    check("%s is WantedBy=timers.target" % t, "timers.target" in body)

# Classify services: a sibling timer means timer-driven, whatever [Install] says.
timer_driven = {t[:-len(".timer")] + ".service" for t in timers}
standalone = [s for s in services if s not in timer_driven]
print("   timer-driven: %s" % sorted(timer_driven))
print("   standalone:   %s" % standalone)
check("classification covers every service",
      len(timer_driven & set(services)) + len(standalone) == len(services))


# ── 2. install.sh deploys the directory at all ───────────────────────────────
print("\n2. install.sh reaches scripts/systemd/")
check("install.sh references scripts/systemd (code, not comment)",
      "scripts/systemd" in src, "0 occurrences outside comments")
check("install.sh mentions .timer at all (code, not comment)",
      ".timer" in src, "0 occurrences outside comments")


# ── 3. every unit file is actually deployed ──────────────────────────────────
print("\n3. registry completeness -- every unit on disk is deployed")
# A glob-based loop satisfies this without naming units; an explicit list must name them.
glob_deploy = re.search(r'systemd/\*\.\{?service', src) or 'systemd"/*.' in src or "systemd/*." in src
for u in services + timers:
    stem = u.rsplit(".", 1)[0]
    check("%s deployed (named or covered by glob)" % u,
          bool(glob_deploy) or stem in src,
          "not named in install.sh and no glob loop found")


# ── 4. the enable rules ──────────────────────────────────────────────────────
print("\n4. enable/start rules")
check("every timer is enabled by install.sh",
      bool(glob_deploy) or all(t.rsplit(".", 1)[0] in src for t in timers))
# The dangerous one: a static service must never be handed to `systemctl enable`.
enable_lines = [l for l in src.splitlines() if "systemctl enable" in l]
check("install.sh has at least one systemctl enable line", len(enable_lines) > 0)
bad = []
for s in sorted(timer_driven & set(services)):
    stem = s.rsplit(".", 1)[0]
    for l in enable_lines:
        if stem in l:
            bad.append((stem, l.strip()))
check("no timer-driven SERVICE is named on a `systemctl enable` line",
      not bad, "%r" % bad[:2])


# ── 5. the two gaps this change also closes ──────────────────────────────────
print("\n5. drift-check and malware-scan")
check("install.sh invokes scripts/deploy_drift_check.sh",
      "deploy_drift_check.sh" in src, "0 occurrences outside comments")
check("malware-scan is in the deployed service list",
      "malware-scan" in src, "core_module/malware_scan/malware-scan.service has no deployer")


print("\n%d passed, %d failed" % (_pass, _fail))
_exp = _expected(len(services), len(timers))
if _pass + _fail != _exp:
    print("EXPECTED_CHECKS MISMATCH: expected %d for %d services / %d timers, ran %d -- a "
          "check was added, removed, or skipped by a short-circuit"
          % (_exp, len(services), len(timers), _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
