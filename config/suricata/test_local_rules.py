#!/usr/bin/env python3
"""Offline verification for the Nemesis host-defence rules (config/suricata/local.rules).

Run: python3 config/suricata/test_local_rules.py

WHY THIS EXISTS
---------------
Rule 1000002 fired 161 times in a week against a trusted LAN laptop whose traffic
went to ONE port -- :53, this host's own DNS service. The rule was a pure SYN-rate
counter with no port-diversity test, so "sweep" described something it never
measured. The fix excludes this host's advertised service ports from the sweep
counters.

A fix like that is exactly the kind that can silently over-correct: suppressing
the false positive is trivial (exclude everything), and the resulting rule set
would look fixed while detecting nothing. So every "should NOT alert" case here is
paired with a control proving the same traffic DOES alert under the OLD rules, and
every "should alert" case is run against the NEW rules. A run that only proved the
false positive was gone would be worthless.

Requires: suricata binary. Builds its own pcaps in pure Python -- no scapy, no new
dependency. Touches nothing live: reads the system suricata.yaml for HOME_NET,
writes only into a temp directory, and never talks to the running service.

Addresses are RFC1918 lab values (192.168.56.x, the documented vboxnet0 range).
They must be inside HOME_NET for the rules to match at all, which rules out the
RFC 5737 documentation blocks used elsewhere in this repo.
"""

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NEW_RULES = os.path.join(HERE, "local.rules")
SYS_YAML = "/etc/suricata/suricata.yaml"

SRC = "192.168.56.99"        # synthetic "client"/"attacker"
DST = "192.168.56.10"        # synthetic Nemesis host (must be inside HOME_NET)
NEMESIS_HOST = DST           # substituted for @NEMESIS_HOST@ in the rules
OTHER_LAN = "192.168.56.77"  # a third LAN device, for the self-scan cases

EXPECTED_CHECKS = 24

passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    mark = "PASS" if cond else "FAIL"
    suffix = f"  ({detail})" if detail else ""
    print(f"  [{mark}] {name}{suffix}")
    if cond:
        passed += 1
    else:
        failed += 1
    return cond


# ── pcap construction (pure stdlib) ──────────────────────────────────────────

def _ipv4(addr):
    return bytes(int(x) for x in addr.split("."))


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def syn_packet(src, dst, sport, dport):
    """One bare TCP SYN, Ethernet-framed, with valid IP and TCP checksums.

    Checksums are computed rather than zero-filled even though the harness also
    passes `-k none`: a packet Suricata might reject as malformed would produce
    "no alert", which is indistinguishable from "the rule correctly did not
    match" -- the precise failure this suite exists to avoid.
    """
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (5 << 4), 0x02, 8192, 0, 0)
    pseudo = _ipv4(src) + _ipv4(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]

    total_len = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, 6, 0) + _ipv4(src) + _ipv4(dst)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]

    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + tcp


def write_pcap(path, packets):
    with open(path, "wb") as fh:
        fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            # All inside one second: the rules threshold on `seconds 60`, so the
            # whole burst must land in a single window or the test would measure
            # the clock rather than the rule.
            fh.write(struct.pack("!IIII", 1000000000, i, len(pkt), len(pkt)))
            fh.write(pkt)


# ── running suricata offline ─────────────────────────────────────────────────

class RuleLoadError(RuntimeError):
    """A rule failed to PARSE. Fatal here, deliberately.

    THE reason this class exists (found the hard way, 2026-08-06): the first
    attempt at the fix used `portvar`, which is Snort syntax Suricata does not
    accept. Both sweep rules failed to load — and a rule that never loads simply
    produces no alerts, which is indistinguishable from a rule that correctly
    declined to match. The false-positive case "passed" beautifully while sweep
    detection was entirely OFF. Never let a parse failure be read as a result.
    """


def run_suricata(rules_path, pcap_path, workdir, expect_sids=(1000001, 1000002, 1000003)):
    out = os.path.join(workdir, "out")
    os.makedirs(out, exist_ok=True)
    proc = subprocess.run(
        ["suricata", "-c", SYS_YAML, "-S", rules_path, "-r", pcap_path,
         "-l", out, "-k", "none"],
        capture_output=True, text=True, timeout=180)

    # Fail closed on any signature that did not parse.
    blob = (proc.stderr or "") + (proc.stdout or "")
    logf = os.path.join(out, "suricata.log")
    if os.path.exists(logf):
        with open(logf, errors="replace") as fh:
            blob += fh.read()
    for marker in ("error parsing signature", "is not defined in configuration file",
                   "no rule options"):
        if marker in blob:
            raise RuleLoadError(
                f"suricata refused to load a rule from {rules_path}: {marker!r}. "
                f"Any 'no alert' result below would be meaningless.")

    # Positive control on loading: the engine must report having loaded rules.
    m = re.search(r"(\d+) signatures processed", blob)
    if m and int(m.group(1)) == 0:
        raise RuleLoadError(f"suricata loaded 0 signatures from {rules_path}")

    fast = os.path.join(out, "fast.log")
    sids = []
    if os.path.exists(fast):
        with open(fast) as fh:
            for line in fh:
                m = re.search(r"\[1:(\d+):\d+\]", line)
                if m:
                    sids.append(int(m.group(1)))
    return sids, proc


PLACEHOLDER = "@NEMESIS_HOST@"


def substituted(workdir, name="new.rules"):
    """The repo rules with @NEMESIS_HOST@ resolved, as the deploy script does.

    The committed file is a TEMPLATE and deliberately does not parse on its own —
    the host address differs per install and must never be committed (Rule 8).
    Tests therefore substitute exactly the way scripts/deploy-suricata-rules.sh
    does, so what is verified here is what gets deployed.
    """
    with open(NEW_RULES) as fh:
        text = fh.read()
    if PLACEHOLDER not in text:
        raise RuleLoadError(
            f"{PLACEHOLDER} missing from local.rules — either the template was "
            f"broken, or a REAL address was committed in its place (Rule 8).")
    path = os.path.join(workdir, name)
    with open(path, "w") as fh:
        fh.write(text.replace(PLACEHOLDER, f"[{NEMESIS_HOST}]"))
    return path


def old_rules_file(workdir):
    """The pre-fix rules: same file with the service-port exclusion removed.

    Derived FROM the new file rather than kept as a second copy, so the control
    cannot drift away from what it is a control for.
    """
    with open(NEW_RULES) as fh:
        text = fh.read()
    text = text.replace(PLACEHOLDER, f"[{NEMESIS_HOST}]")
    old = text.replace("$HOME_NET ![22,53,80,443,5000,5001]", "$HOME_NET any")
    old = old.replace(f"alert tcp ![{NEMESIS_HOST}] any", "alert tcp any any")
    if old == text:
        # The exclusion is what this whole suite verifies. If the pattern no
        # longer appears, the control silently becomes a copy of the new rules
        # and every comparison below agrees for the wrong reason.
        raise RuleLoadError(
            "could not build the old-rules control: the service-port exclusion "
            "pattern was not found in local.rules. Did the rule text change?")
    path = os.path.join(workdir, "old.rules")
    with open(path, "w") as fh:
        fh.write(old)
    return path


def main():
    if not shutil.which("suricata"):
        print("suricata binary not found — cannot verify. NOT reporting a pass.",
              file=sys.stderr)
        sys.exit(2)
    if not os.path.exists(SYS_YAML):
        print(f"{SYS_YAML} not readable — cannot resolve HOME_NET.", file=sys.stderr)
        sys.exit(2)

    work = tempfile.mkdtemp(prefix="nem-rules-test-")
    old = old_rules_file(work)
    new = substituted(work)

    # CONTROL ON THE HARNESS ITSELF: prove the old file really differs from the
    # new one. If the substitution silently failed, every "old rules" control
    # below would just re-run the new rules and agree with them for the wrong
    # reason.
    with open(NEW_RULES) as a, open(old) as b:
        differs = a.read() != b.read()
    check("HARNESS CONTROL: the old-rules control file differs from the new one",
          differs)

    # DRIFT GUARD: the exclusion list is written out in full in both sweep rules
    # (Suricata has no rules-file variable syntax — see local.rules). Two copies
    # can drift, so pin that they are identical and that there are exactly two.
    with open(NEW_RULES) as fh:
        rule_text = fh.read()
    excls = re.findall(r"\$HOME_NET (!\[[0-9,]+\])", rule_text)
    check("both sweep rules carry an exclusion list", len(excls) == 2, f"found {len(excls)}")
    check("the two exclusion lists are IDENTICAL (no drift)",
          len(set(excls)) == 1, f"{set(excls)}")

    # RULE 8 GUARD: the committed template must never carry a real HOST address.
    # Allowed: the generic RFC1918 NETWORK bases quoted in the header comment to
    # illustrate the stock HOME_NET, and the documented 192.168.56.x lab range.
    # Anything else is a leaked address — this is how a real LAN address was
    # caught on its way into the public repo earlier the same day.
    ALLOWED = {"192.168.0.0", "10.0.0.0", "172.16.0.0", "100.64.0.0", "0.0.0.0"}

    def leaked(text):
        return [ip for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
                if ip not in ALLOWED and not ip.startswith("192.168.56.")]

    check("the committed rules carry NO real host address", not leaked(rule_text),
          f"found {leaked(rule_text)}")
    # CONTROL: prove the guard can actually fail. A leak-check that cannot detect
    # a planted address is the same non-measurement this suite exists to reject.
    check("CONTROL the leak guard DOES catch a planted address",
          leaked("# staging note: box at 10.99.99.99") == ["10.99.99.99"])
    check("the committed rules use the @NEMESIS_HOST@ placeholder",
          PLACEHOLDER in rule_text)
    # All three self-noise rules must carry the source exclusion.
    check("rules 1-3 all exclude this host as a source",
          rule_text.count(f"alert tcp !{PLACEHOLDER} any") == 3,
          f"found {rule_text.count(f'alert tcp !{PLACEHOLDER} any')}")

    # ── Case 1: the false positive — 150 SYNs to :53 only ────────────────────
    print("\n[Case 1] the real false positive: 150 SYNs to :53 (this host's own DNS)")
    fp = os.path.join(work, "fp.pcap")
    write_pcap(fp, [syn_packet(SRC, DST, 40000 + i, 53) for i in range(150)])

    sids_old, _ = run_suricata(old, fp, os.path.join(work, "c1old"))
    check("CONTROL under OLD rules it DOES fire (so the pcap reaches the rule)",
          1000002 in sids_old, f"sids={sorted(set(sids_old))}")
    check("CONTROL old rules also trip the moderate sweep rule",
          1000001 in sids_old, f"sids={sorted(set(sids_old))}")

    sids_new, _ = run_suricata(new, fp, os.path.join(work, "c1new"))
    check("FIXED: aggressive sweep (1000002) no longer fires on DNS traffic",
          1000002 not in sids_new, f"sids={sorted(set(sids_new))}")
    check("FIXED: moderate sweep (1000001) no longer fires either",
          1000001 not in sids_new, f"sids={sorted(set(sids_new))}")

    # ── Case 2: a REAL port scan must still be caught ────────────────────────
    print("\n[Case 2] a real horizontal scan: 150 SYNs across 150 distinct ports")
    scan = os.path.join(work, "scan.pcap")
    ports = [p for p in range(10000, 10400) if p not in (22, 53, 80, 443, 5000, 5001)][:150]
    write_pcap(scan, [syn_packet(SRC, DST, 40000 + i, p) for i, p in enumerate(ports)])

    sids_new, _ = run_suricata(new, scan, os.path.join(work, "c2new"))
    check("aggressive sweep (1000002) STILL fires on a real scan",
          1000002 in sids_new, f"sids={sorted(set(sids_new))}")
    check("moderate sweep (1000001) STILL fires on a real scan",
          1000001 in sids_new, f"sids={sorted(set(sids_new))}")

    # ── Case 3: a scan that INCLUDES the excluded service ports ──────────────
    # The exclusion must not become a blind spot an attacker can hide inside by
    # mixing service ports into the sweep.
    print("\n[Case 3] a scan mixing service ports with 120 others")
    mixed = os.path.join(work, "mixed.pcap")
    mports = [22, 53, 80, 443, 5000, 5001] * 5 + list(range(20000, 20120))
    write_pcap(mixed, [syn_packet(SRC, DST, 40000 + i, p) for i, p in enumerate(mports)])

    sids_new, _ = run_suricata(new, mixed, os.path.join(work, "c3new"))
    check("a mixed scan is still caught (aggressive)", 1000002 in sids_new,
          f"sids={sorted(set(sids_new))}")
    check("a mixed scan is still caught (moderate)", 1000001 in sids_new,
          f"sids={sorted(set(sids_new))}")

    # ── Case 4: rule 3 (service-port concentration) is unaffected ────────────
    print("\n[Case 4] rule 1000003 still covers concentration on service ports")
    svc = os.path.join(work, "svc.pcap")
    write_pcap(svc, [syn_packet(SRC, DST, 40000 + i, 80) for i in range(40)])

    sids_new, _ = run_suricata(new, svc, os.path.join(work, "c4new"))
    check("1000003 fires on repeated probes to :80", 1000003 in sids_new,
          f"sids={sorted(set(sids_new))}")
    check("  and the sweep rules correctly stay silent on it",
          1000001 not in sids_new and 1000002 not in sids_new,
          f"sids={sorted(set(sids_new))}")

    # ── Case 5: below-threshold traffic must not alert (both rule sets) ──────
    print("\n[Case 5] below-threshold traffic stays quiet")
    quiet = os.path.join(work, "quiet.pcap")
    write_pcap(quiet, [syn_packet(SRC, DST, 40000 + i, 20000 + i) for i in range(5)])
    sids_new, _ = run_suricata(new, quiet, os.path.join(work, "c5new"))
    check("5 SYNs across 5 ports trips nothing", not sids_new,
          f"sids={sorted(set(sids_new))}")

    # ── Case 6: the stealth-scan rules are untouched by this change ──────────
    print("\n[Case 6] stealth-scan rules (NULL/FIN/XMAS) unaffected")
    null = os.path.join(work, "null.pcap")
    pkts = []
    for i in range(20):
        p = bytearray(syn_packet(SRC, DST, 40000 + i, 20000 + i))
        p[47] = 0x00      # TCP flags byte -> NULL scan
        pkts.append(bytes(p))
    write_pcap(null, pkts)
    sids_new, _ = run_suricata(new, null, os.path.join(work, "c6new"))
    check("NULL-flag scan (1000004) still fires", 1000004 in sids_new,
          f"sids={sorted(set(sids_new))}")

    # ── Case 7: THE SELF-SCAN false positive (926 + 1,160 real hits) ─────────
    # Nemesis's own device-scanner sweeping the LAN tripped its own rules. The
    # traffic is genuinely sweep-shaped, so the ONLY thing distinguishing it is
    # the source — which is why this needed a different fix from the port one.
    print("\n[Case 7] this host scanning the LAN must not trip its own rules")
    selfscan = os.path.join(work, "selfscan.pcap")
    sports = [p for p in range(11000, 11400)
              if p not in (22, 53, 80, 443, 5000, 5001)][:150]
    write_pcap(selfscan, [syn_packet(NEMESIS_HOST, OTHER_LAN, 40000 + i, p)
                          for i, p in enumerate(sports)])
    sids_new, _ = run_suricata(new, selfscan, os.path.join(work, "c7new"))
    check("FIXED: the host's own LAN sweep no longer fires", not sids_new,
          f"sids={sorted(set(sids_new))}")

    # CONTROL: byte-identical traffic from ANY OTHER source MUST still fire.
    # Without this, "no alert" above would equally describe a rule set that
    # stopped detecting sweeps altogether.
    other = os.path.join(work, "otherscan.pcap")
    write_pcap(other, [syn_packet(SRC, OTHER_LAN, 40000 + i, p)
                       for i, p in enumerate(sports)])
    sids_new, _ = run_suricata(new, other, os.path.join(work, "c7ctl"))
    check("CONTROL the SAME scan from another host still fires",
          1000002 in sids_new and 1000001 in sids_new,
          f"sids={sorted(set(sids_new))}")

    # CONTROL: and it DID fire under the old rules — proving the pcap is
    # sweep-shaped and that this case reproduces the real false positive.
    sids_old, _ = run_suricata(old, selfscan, os.path.join(work, "c7old"))
    check("CONTROL the self-scan DID fire under the old rules",
          1000001 in sids_old, f"sids={sorted(set(sids_old))}")

    # ── Case 8: rule 1000003's self-noise (all 1,160 hits) ───────────────────
    print("\n[Case 8] this host's own outbound :80/:443 must not trip rule 3")
    selfsvc = os.path.join(work, "selfsvc.pcap")
    write_pcap(selfsvc, [syn_packet(NEMESIS_HOST, OTHER_LAN, 40000 + i, 80)
                         for i in range(40)])
    sids_new, _ = run_suricata(new, selfsvc, os.path.join(work, "c8new"))
    check("FIXED: the host's own outbound :80 no longer fires 1000003",
          1000003 not in sids_new, f"sids={sorted(set(sids_new))}")
    sids_old, _ = run_suricata(old, selfsvc, os.path.join(work, "c8old"))
    check("CONTROL it DID fire under the old rules", 1000003 in sids_old,
          f"sids={sorted(set(sids_old))}")

    shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 60)
    total = passed + failed
    print(f"Total: {passed} passed, {failed} failed ({total} checks)")
    if total != EXPECTED_CHECKS:
        print(f"GUARD FAILED: expected {EXPECTED_CHECKS} checks, ran {total}.")
        sys.exit(1)
    print("RESULT: all checks passed" if not failed else "RESULT: FAILED")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
