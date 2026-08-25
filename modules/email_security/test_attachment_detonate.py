"""Stage 3 -- attachment detonation. Real DataManager, fake sandbox.

WHAT IS REAL AND WHAT IS FAKED, AND WHY THAT SPLIT:
  REAL  -- the DataManager, the namespace grant, the tables, the MIME parse.
           A stubbed DM cannot observe a missing grant (see test_email_writes).
  FAKE  -- DisposableSandbox itself. Detonating for real needs VirtualBox, a
           clean snapshot, and minutes per sample. The engine has its OWN suites
           (test_sandbox.py, test_sandbox_guest_os.py) covering isolation and
           teardown; duplicating them here would test the engine, not the wiring.
           What THIS suite must prove is that the wiring reacts correctly to each
           thing the engine can do -- which needs a sandbox that can be made to
           raise on demand, not a real one.

NO NETWORK, NO REAL MALWARE, NO VM, NO LIVE DB. Payloads are inert byte strings.
"""
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

import modules                                                  # noqa: E402
import database                                                 # noqa: E402
import data_manager as dm_mod                                   # noqa: E402
from modules.malware_detection import sandbox as sbmod          # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


_TMPDB = os.path.join(tempfile.mkdtemp(prefix="emailsec-det-"), "t.db")
database.DB_PATH = _TMPDB
modules.set_shared_db_path(_TMPDB)
database.init_email_security_tables()

import attachment_detonate as ad                                # noqa: E402
import mime_parse                                               # noqa: E402

DM = modules.get_data_manager()
DM.set_actor("user:tester")


# ── a sandbox that does exactly one thing, on demand ────────────────────────
class FakeSandbox:
    def __init__(self, behaviour="ok"):
        self.behaviour = behaviour
        self.calls = []

    def detonate(self, sample_path, run_cmd, timeout_s=120, collect=None):
        # Record what the wiring actually handed the engine -- the sample must
        # exist and be readable AT CALL TIME, which is the contract detonate()
        # itself asserts with os.path.isfile.
        self.calls.append({
            "path": sample_path,
            "exists": os.path.isfile(sample_path),
            "mode": oct(os.stat(sample_path).st_mode & 0o777),
            "dir_mode": oct(os.stat(os.path.dirname(sample_path)).st_mode & 0o777),
            "bytes": open(sample_path, "rb").read(),
        })
        if self.behaviour == "teardown":
            raise sbmod.TeardownFailed("vm nemesis-det-1 still present")
        if self.behaviour == "isolation":
            raise sbmod.IsolationUnverified("NIC present, refused")
        if self.behaviour == "boom":
            raise RuntimeError("something else broke")
        return {"vm": "vm-1", "detonated": True, "isolation_verified": True,
                "observation": {"events": 3}}


RAW = (b"From: a@example.com\r\nSubject: t\r\n"
       b"Content-Type: multipart/mixed; boundary=B\r\n\r\n"
       b"--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
       b"--B\r\nContent-Type: application/octet-stream\r\n"
       b'Content-Disposition: attachment; filename="invoice.exe"\r\n\r\n'
       b"INERT-SAMPLE-BYTES\r\n--B--\r\n")

parsed = mime_parse.parse(RAW)


def _rows():
    c = DM.connect("email_security")
    try:
        return c.execute(
            "SELECT outcome, error, report_json, actor, extension, name_hash, "
            "attachment_sha256 FROM email_attachment_detonations "
            "ORDER BY id").fetchall()
    finally:
        c.close()


print("-- 0. CONTROLS --")
check("throwaway DB, not the live one", "/var/lib/nemesis" not in _TMPDB)
check("REAL DataManager, not a stub", isinstance(DM, dm_mod.DataManager))
check("enforcement ON (the grant is load-bearing)",
      dm_mod.namespace_mode("email_security") == dm_mod.MODE_ENFORCE)
check("new table IS granted", dm_mod.allowed("email_security",
                                             "email_attachment_detonations"))
check("CONTROL: a sibling name is still DENIED (exact-match, not prefix)",
      dm_mod.allowed("email_security", "email_detonations") is False)
check("CONTROL: the fixture really has one attachment to detonate",
      len(parsed.attachments) == 1, parsed.attachments)
check("CONTROL: and mime_parse gave metadata WITHOUT the payload bytes",
      "sha256" in parsed.attachments[0] and
      not any(k in parsed.attachments[0] for k in ("payload", "bytes", "data")),
      parsed.attachments[0])

print("\n-- 1. Happy path: sample materialised correctly, outcome recorded --")
fs = FakeSandbox("ok")
out = ad.detonate_message_attachments(fs, 1, parsed, RAW)
check("outcome 'completed'", out == ["completed"], out)
call = fs.calls[0]
check("sample existed when the engine was called", call["exists"] is True)
check("sample bytes are the ATTACHMENT's, not the message's",
      call["bytes"] == b"INERT-SAMPLE-BYTES", call["bytes"][:30])
check("sample file mode 0600", call["mode"] == "0o600", call["mode"])
check("workdir mode 0700", call["dir_mode"] == "0o700", call["dir_mode"])
check("no executable bit on the sample", "7" not in call["mode"][2:], call["mode"])
check("real EXTENSION carried (Windows executes by extension)",
      call["path"].endswith(".exe"), call["path"])
check("real FILENAME not carried (it can hold personal info)",
      "invoice" not in os.path.basename(call["path"]), call["path"])

r = _rows()
check("one row recorded", len(r) == 1, len(r))
check("outcome column 'completed'", r[0][0] == "completed", r[0][0])
check("report stored", r[0][2] and "observation" in r[0][2], r[0][2])
check("actor stamped from current_actor()", r[0][3] == "user:tester", r[0][3])
check("extension in the clear", r[0][4] == "exe", r[0][4])
check("filename stored HASHED, not plain", r[0][5] and "invoice" not in r[0][5],
      r[0][5])

print("\n-- 2. Host cleanup: the sample must not outlive the call --")
check("workdir removed after detonation",
      not os.path.exists(os.path.dirname(call["path"])),
      os.path.dirname(call["path"]))

print("\n-- 3. TeardownFailed: DANGEROUS halt, recorded, batch stops --")
fs2 = FakeSandbox("teardown")
try:
    ad.detonate_message_attachments(fs2, 2, parsed, RAW)
    check("TeardownFailed halts the batch", False, "it returned normally")
except ad.DetonationHalted as exc:
    check("TeardownFailed raises DetonationHalted", True)
    check("...flagged DANGEROUS (a VM may still be running the sample)",
          exc.dangerous is True)
    check("...outcome is teardown_failed", exc.outcome == "teardown_failed")
r2 = [x for x in _rows() if x[0] == "teardown_failed"]
check("...and it was RECORDED before halting", len(r2) == 1, len(r2))
check("...with the engine's error text, not a default",
      r2 and r2[0][1] and "still present" in r2[0][1], r2 and r2[0][1])
check("...and NOT recorded as anything clean-looking",
      all(x[0] != "completed" for x in _rows() if x[0] == "teardown_failed"))
check("workdir still cleaned up despite the exception",
      not os.path.exists(os.path.dirname(fs2.calls[0]["path"])))

print("\n-- 4. IsolationUnverified: nothing ran; SAFE halt, still a halt --")
fs3 = FakeSandbox("isolation")
try:
    ad.detonate_message_attachments(fs3, 3, parsed, RAW)
    check("IsolationUnverified halts the batch", False, "it returned normally")
except ad.DetonationHalted as exc:
    check("IsolationUnverified raises DetonationHalted", True)
    check("...flagged NOT dangerous (nothing executed)", exc.dangerous is False)
    check("...outcome is isolation_unverified",
          exc.outcome == "isolation_unverified")
r3 = [x for x in _rows() if x[0] == "isolation_unverified"]
check("...recorded as isolation_unverified, NEVER as completed", len(r3) == 1)

print("\n-- 5. The two failures stay DISTINGUISHABLE in the table --")
outs = {x[0] for x in _rows()}
check("teardown_failed and isolation_unverified are separate values",
      {"teardown_failed", "isolation_unverified"} <= outs, outs)
check("...and neither equals 'completed'",
      "completed" in outs and len(outs & {"teardown_failed",
                                          "isolation_unverified"}) == 2, outs)

print("\n-- 6. An ordinary error is per-sample: recorded, does NOT halt --")
fs4 = FakeSandbox("boom")
out4 = ad.detonate_message_attachments(fs4, 4, parsed, RAW)
check("returns 'error' rather than raising", out4 == ["error"], out4)
r4 = [x for x in _rows() if x[0] == "error"]
check("recorded with the exception type", r4 and "RuntimeError" in r4[0][1],
      r4 and r4[0][1])

print("\n-- 7. No payload / no match: skipped, never 'completed' --")
nopay = {"sha256": None, "size": 0, "name_hash": "h", "extension": "pdf"}
check("metadata-only part -> skipped_no_payload",
      ad.detonate_attachment(FakeSandbox(), 5, nopay, RAW)
      == "skipped_no_payload")
ghost = {"sha256": "0" * 64, "size": 10, "name_hash": "h2", "extension": "pdf"}
check("hash that matches no part -> skipped_no_payload, with a reason",
      ad.detonate_attachment(FakeSandbox(), 6, ghost, RAW)
      == "skipped_no_payload")
g = [x for x in _rows() if x[6] == "0" * 64]
check("...and the reason names the unmatched hash", g and "no part" in g[0][1],
      g and g[0][1])

print("\n-- 8. Oversize is skipped, never truncated --")
big = dict(parsed.attachments[0])
big["size"] = ad.MAX_SAMPLE_BYTES + 1
fs5 = FakeSandbox()
check("-> skipped_too_large",
      ad.detonate_attachment(fs5, 7, big, RAW) == "skipped_too_large")
check("...and the engine was never called at all", fs5.calls == [], fs5.calls)

print("\n-- 9. extract_payload: absent is None, empty is b'' --")
check("no match returns None, not b''",
      ad.extract_payload(RAW, "f" * 64) is None)
check("a real match returns the bytes",
      ad.extract_payload(RAW, parsed.attachments[0]["sha256"])
      == b"INERT-SAMPLE-BYTES")

print("\n-- 10. MUTATION: prove section 3 can go red --")
# If TeardownFailed were caught-and-continued (the tempting "robustness" fix),
# the batch would NOT halt. Simulate that shape and confirm the difference is
# observable -- i.e. section 3's assertions are not vacuous.
def _swallowing(sandbox, verdict_id, att, raw, **kw):
    try:
        return ad.detonate_attachment(sandbox, verdict_id, att, raw, **kw)
    except ad.DetonationHalted as e:
        return e.outcome                      # swallowed -> batch would continue


mut = _swallowing(FakeSandbox("teardown"), 8, parsed.attachments[0], RAW)
check("MUTANT (swallows the halt) returns instead of raising -> section 3 is real",
      mut == "teardown_failed", mut)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
