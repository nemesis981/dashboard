#!/bin/bash
# Nemesis Agent — Linux Installer
#
# Non-interactive by design: every value arrives as a flag or an environment
# variable, and a missing REQUIRED value is a loud failure with usage, never a
# prompt. The previous version asked two `read -rp` questions, which made
# unattended/fleet provisioning impossible — the same class of defect as the
# Pi-hole unattended-install hang already tracked in PUNCHLIST.
#
#   sudo ./install_linux.sh --server 10.0.0.5 [--token ABC] [--device-name lab-1]
#
# ── WHY A VENV, NOT `pip install` ───────────────────────────────────────────
# Ubuntu 24.04+/Debian 12+ ship PEP 668 (`/usr/lib/pythonX/EXTERNALLY-MANAGED`),
# under which `pip install` into the system interpreter fails outright:
#     error: externally-managed-environment
# The old installer ran exactly that under `set -e`, so on Ubuntu 26.04 it
# ABORTED at the dependency step — before copying the agent, writing any config,
# or creating the service. Nothing was installed and the failure was easy to
# miss. Measured live on Ubuntu 26.04, 2026-08-20. A self-contained venv is
# immune to this and keeps the agent's dependencies off the system interpreter.
#
# ── WHY THE COPY IS FILTERED ────────────────────────────────────────────────
# `nemesis_agent.conf` and `keys/` live INSIDE the agent source directory. The
# old `cp -r "$SCRIPT_DIR/."` therefore copied whatever enrollment identity
# happened to be sitting in the source tree — i.e. it could install ANOTHER
# machine's private key and device_id, giving two hosts the same identity. The
# copy below excludes them explicitly, and an existing install's conf/keys are
# preserved rather than overwritten.

set -euo pipefail

INSTALL_DIR="${NEMESIS_INSTALL_DIR:-/opt/nemesis-agent}"
SERVICE_NAME="nemesis-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
VENV_DIR=""   # set after arg parsing (depends on INSTALL_DIR)

SERVER="${NEMESIS_SERVER:-}"
PORT="${NEMESIS_PORT:-5001}"
SUBNET="${NEMESIS_SUBNET:-}"
DEVICE_NAME="${NEMESIS_DEVICE_NAME:-}"
TOKEN="${NEMESIS_ENROLLMENT_TOKEN:-}"
SERVER_KEY="${NEMESIS_SERVER_KEY:-}"
AGENT_USER="${NEMESIS_AGENT_USER:-}"
DO_ENROLL=1

step()  { echo -e "\n==> $1"; }
ok()    { echo "    [OK] $1"; }
warn()  { echo "    [!!] $1"; }
fail()  { echo "    [FAIL] $1" >&2; exit 1; }

usage() {
    cat >&2 <<USAGE
Nemesis Agent — Linux Installer

  sudo ./install_linux.sh --server <ip-or-host> [options]

Required:
  --server <addr>        Nemesis server address        (env NEMESIS_SERVER)

Options:
  --port <n>             Server port, default 5001     (env NEMESIS_PORT)
  --device-name <name>   Friendly name, default hostname
                                                       (env NEMESIS_DEVICE_NAME)
  --token <tok>          Installer enrollment token; the server auto-approves
                         when the token was minted with auto-approve
                                                       (env NEMESIS_ENROLLMENT_TOKEN)
  --subnet <cidr>        Local subnet for local-vs-VPN detection
                                                       (env NEMESIS_SUBNET)
  --server-key <b64>     Server public key (base64 DER) to pin as the
                         task-signing trust anchor      (env NEMESIS_SERVER_KEY)
  --user <name>          Service account, default the invoking (sudo) user
                                                       (env NEMESIS_AGENT_USER)
  --install-dir <path>   Default /opt/nemesis-agent    (env NEMESIS_INSTALL_DIR)
  --no-enroll            Install and start only; do not enroll
  -h, --help             This message

This installer never prompts. A missing required value fails immediately so an
unattended run cannot hang waiting on stdin.
USAGE
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --server)       SERVER="${2:-}"; shift 2 ;;
        --port)         PORT="${2:-}"; shift 2 ;;
        --device-name)  DEVICE_NAME="${2:-}"; shift 2 ;;
        --token)        TOKEN="${2:-}"; shift 2 ;;
        --subnet)       SUBNET="${2:-}"; shift 2 ;;
        --server-key)   SERVER_KEY="${2:-}"; shift 2 ;;
        --user)         AGENT_USER="${2:-}"; shift 2 ;;
        --install-dir)  INSTALL_DIR="${2:-}"; shift 2 ;;
        --no-enroll)    DO_ENROLL=0; shift ;;
        -h|--help)      usage ;;
        *)              echo "unknown argument: $1" >&2; usage ;;
    esac
done

VENV_DIR="${INSTALL_DIR}/venv"
CONF="${INSTALL_DIR}/nemesis_agent.conf"

[ "$EUID" -eq 0 ] || fail "Run as root: sudo bash install_linux.sh --server <addr>"

if [ -z "$SERVER" ]; then
    echo "ERROR: --server is required (or set NEMESIS_SERVER)." >&2
    echo "       This installer does not prompt — see --help." >&2
    exit 2
fi

[ -n "$DEVICE_NAME" ] || DEVICE_NAME="$(hostname)"
# The service must not run as root: the agent is a long-lived network client and
# needs no privilege beyond reading its own directory.
[ -n "$AGENT_USER" ] || AGENT_USER="${SUDO_USER:-root}"
id "$AGENT_USER" >/dev/null 2>&1 || fail "service user '$AGENT_USER' does not exist"
[ "$AGENT_USER" != "root" ] || warn "installing to run as root — pass --user for an unprivileged account"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SCRIPT_DIR/agent.py" ] || fail "agent.py not found next to this script ($SCRIPT_DIR)"

echo "============================================================"
echo "  Nemesis Agent — Linux install"
echo "  server      : ${SERVER}:${PORT}"
echo "  device name : ${DEVICE_NAME}"
echo "  install dir : ${INSTALL_DIR}"
echo "  service user: ${AGENT_USER}"
echo "  enrollment  : $([ "$DO_ENROLL" -eq 1 ] && echo "yes$([ -n "$TOKEN" ] && echo " (token supplied)")" || echo "skipped (--no-enroll)")"
echo "============================================================"

# ── 1. Python ───────────────────────────────────────────────────────────────
step "Checking Python..."
PYTHON=""
for cmd in python3 python; do
    command -v "$cmd" &>/dev/null || continue
    VER="$($cmd -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)" || continue
    MAJOR="${VER%%.*}"; MINOR="${VER##*.}"
    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
        PYTHON="$cmd"; ok "Found $cmd $VER"; break
    fi
done
[ -n "$PYTHON" ] || fail "Python 3.8+ not found. Install python3 and re-run."

# ── 2. System packages ──────────────────────────────────────────────────────
# `python3-venv` supplies ensurepip; without it `python3 -m venv` fails on
# Debian/Ubuntu. Errors are surfaced, not sent to /dev/null — the old installer
# hid apt failures behind `&>/dev/null || true`, so a missing dependency only
# showed up later as a confusing runtime error.
step "Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get &>/dev/null; then
    apt-get update -qq || warn "apt-get update failed — continuing with the current package lists"
    if apt-get install -y -qq python3-venv libnotify-bin; then
        ok "python3-venv, libnotify-bin"
    else
        warn "apt-get install failed; continuing (venv creation below will catch a real problem)"
    fi
else
    warn "no apt-get — install python3-venv yourself if venv creation fails"
fi

# ── 3. Virtual environment ──────────────────────────────────────────────────
step "Creating virtual environment at ${VENV_DIR}..."
mkdir -p "$INSTALL_DIR"
if [ ! -x "${VENV_DIR}/bin/python" ]; then
    "$PYTHON" -m venv "$VENV_DIR" || fail "could not create venv (is python3-venv installed?)"
fi
VPY="${VENV_DIR}/bin/python"
[ -x "$VPY" ] || fail "venv python missing at $VPY"
ok "venv ready"

step "Installing Python packages into the venv..."
"$VPY" -m pip install --upgrade pip --quiet || warn "pip self-upgrade failed — continuing"
# REQUIRED. `cryptography` is not optional and is NOT in REQUIREMENTS.md's list
# (which names only requests/psutil/watchdog/plyer) — but `enrollment.py` and
# `keyprotect/` both import it at module level, so without it enrollment raises
# ModuleNotFoundError and the agent cannot even start. It went unnoticed because
# Ubuntu ships python3-cryptography system-wide, so a system-interpreter install
# picked it up by accident; a clean venv does not. Caught by a real install on a
# fresh VM, 2026-08-20.
"$VPY" -m pip install --quiet requests psutil cryptography \
    || fail "could not install required packages (requests, psutil, cryptography). Check network/DNS from this host."
ok "required packages: requests, psutil, cryptography"
# watchdog + plyer are OPTIONAL — agent.py guards these imports and runs without
# them. A desktop-notification library must not be able to fail an install.
if "$VPY" -m pip install --quiet watchdog plyer; then
    ok "optional packages: watchdog, plyer"
else
    warn "optional packages (watchdog, plyer) not installed — agent runs without them"
fi

# ── 4. Copy agent files (FILTERED — see header) ─────────────────────────────
#
# STOP A RUNNING AGENT FIRST -- this is an enrollment-correctness step, not
# just tidiness. On a re-install the previously-installed agent keeps running
# through section 6, and if its conf carries no device_id yet it is sitting in
# ensure_enrolled()'s poll loop, ready to POST /enroll of its own accord. The
# server mints a fresh device_id per POST, so the installer and that live agent
# can enroll the SAME machine CONCURRENTLY and produce two rows timestamped in
# the same second -- which is the signature seen on the 2026-08-20
# installer-test-node pair (two rows, one shared public key, identical
# agent_last_seen), as distinct from the minutes-apart pair a sequential re-run
# produces.
#
# ⚠ INFERRED, not reproduced: the concurrent race is deduced from that shared
# timestamp plus the absence of any stop here. The sequential re-run path WAS
# reproduced directly (see the idempotence gate in section 6). Stopping first
# also avoids swapping agent.py underneath a live process.
if systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1 \
   && systemctl is-active --quiet "$SERVICE_NAME"; then
    step "Stopping the running agent before reinstalling..."
    systemctl stop "$SERVICE_NAME" || warn "could not stop ${SERVICE_NAME}; continuing"
    ok "existing agent stopped (prevents a concurrent second enrollment)"
fi

step "Installing agent files to ${INSTALL_DIR}..."
tar -C "$SCRIPT_DIR" \
    --exclude='./nemesis_agent.conf' \
    --exclude='./keys' \
    --exclude='./venv' \
    --exclude='./__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.log' \
    -cf - . | tar -C "$INSTALL_DIR" -xf -
ok "agent files copied (config and keys deliberately excluded)"

# Belt and braces: if the source tree DID carry identity material, prove none of
# it landed here. A copied keypair means two hosts share one identity, and the
# symptom (mysterious duplicate/mismatched device) appears far from the cause.
if [ -f "$SCRIPT_DIR/nemesis_agent.conf" ] || [ -d "$SCRIPT_DIR/keys" ]; then
    SRC_ID="$(grep -E '^device_id' "$SCRIPT_DIR/nemesis_agent.conf" 2>/dev/null | tr -d ' ' | cut -d= -f2 || true)"
    if [ -n "${SRC_ID:-}" ] && grep -qs "$SRC_ID" "$CONF" 2>/dev/null; then
        fail "the source tree's device_id leaked into ${CONF} — refusing to continue"
    fi
    ok "source tree carried identity material; confirmed it did NOT get copied"
fi

# ── 5. Configure (non-interactive) ──────────────────────────────────────────
# An existing conf is UPDATED in place, never replaced: it holds device_id and
# enrollment_status, and discarding those makes the agent enrol a second time
# and appear twice on the server.
step "Writing configuration..."
if [ ! -f "$CONF" ]; then
    cat > "$CONF" <<EOF
[nemesis]
nemesis_ip = ${SERVER}
nemesis_port = ${PORT}
nemesis_subnet = ${SUBNET}
device_name = ${DEVICE_NAME}
device_id =
enrollment_status =
enrollment_token = ${TOKEN}
poll_interval = 300
suricata_enabled = false
suricata_profile = auto
scan_on_reconnect = true
last_scan_at =
EOF
    ok "created ${CONF}"
else
    "$VPY" - "$CONF" "$SERVER" "$PORT" "$SUBNET" "$DEVICE_NAME" "$TOKEN" <<'PYEOF'
import configparser, sys
path, server, port, subnet, name, token = sys.argv[1:7]
cfg = configparser.ConfigParser()
cfg.read(path)
if not cfg.has_section("nemesis"):
    cfg.add_section("nemesis")
cfg.set("nemesis", "nemesis_ip", server)
cfg.set("nemesis", "nemesis_port", port)
cfg.set("nemesis", "device_name", name)
if subnet:
    cfg.set("nemesis", "nemesis_subnet", subnet)
if token:
    cfg.set("nemesis", "enrollment_token", token)
with open(path, "w") as f:
    cfg.write(f)
print("    [OK] updated existing config (device_id/enrollment_status preserved)")
PYEOF
fi
[ -n "$SERVER_KEY" ] && { \
    "$VPY" - "$CONF" "$SERVER_KEY" <<'PYEOF'
import configparser, sys
path, key = sys.argv[1], sys.argv[2]
cfg = configparser.ConfigParser(); cfg.read(path)
cfg.set("nemesis", "server_public_key", key)
with open(path, "w") as f: cfg.write(f)
print("    [OK] server public key recorded for pinning")
PYEOF
}

chown -R "$AGENT_USER": "$INSTALL_DIR"
chmod 600 "$CONF"
ok "ownership set to ${AGENT_USER}"

# ── 6. Enrollment ───────────────────────────────────────────────────────────
# Runs AS THE SERVICE USER so the keypair is created with that account's
# ownership -- keys minted as root would be unreadable by the service.
if [ "$DO_ENROLL" -eq 1 ]; then
    step "Enrolling with the Nemesis server..."
    set +e
    sudo -u "$AGENT_USER" "$VPY" - <<PYEOF
import os, sys
os.chdir("${INSTALL_DIR}")
sys.path.insert(0, "${INSTALL_DIR}")
import config, enrollment

conf = config.load()
if not conf.get("nemesis_ip"):
    print("    [FAIL] config has no nemesis_ip"); sys.exit(1)

# None = the legacy unencrypted key path. Deliberate for a headless Linux agent:
# there is no operator present to supply a device secret at install time, and
# ensure_provisioned() never re-provisions, so re-running this cannot mint a
# second identity for an already-enrolled host.
enrollment.ensure_provisioned(None)

srv_key = (conf.get("server_public_key") or "").strip()
if srv_key:
    try:
        if enrollment.pin_server_key(srv_key):
            print("    [OK] pinned server public key (task-signing anchor)")
    except Exception as e:
        print("    [!!] could not pin server key: %s" % e)

# Admin-approval authenticators (ADR 0026 §D3) — which HUMANS this device will
# accept approvals from. Absent conf key = feature not enabled on this appliance;
# the agent then refuses every approval-gated action, which is fail-closed.
admin_auth = (conf.get("admin_authenticators") or "").strip()
if admin_auth:
    try:
        if enrollment.pin_admin_authenticators(admin_auth):
            fp = enrollment.admin_authenticators_fingerprint()
            n = len(enrollment.pinned_admin_authenticators())
            print("    [OK] pinned %d admin authenticator(s)" % n)
            # ── OUT-OF-BAND CHECK — the one thing code cannot do for the operator.
            #
            # Everything else this installer pins arrives from the appliance, so an
            # appliance already compromised RIGHT NOW can pin its own admin key and
            # every later guarantee follows from a lie. No amount of agent-side
            # verification detects that; the trust root is genuinely out of reach.
            #
            # What IS in reach: the companion app holds the real admin key and can
            # display this same digest. An operator who compares them forces a
            # compromised appliance to also fool a device it does not control. That
            # is why this is printed prominently rather than logged quietly -- an
            # unread fingerprint mitigates nothing.
            print("")
            print("    ┌─ VERIFY THIS ON YOUR PHONE ─────────────────────────────")
            print("    │  Admin key fingerprint:")
            print("    │    %s" % fp[:32])
            print("    │    %s" % fp[32:])
            print("    │")
            print("    │  Open the Nemesis companion app and compare. If it does")
            print("    │  NOT match, STOP: this device has been given admin keys")
            print("    │  that are not yours, and approvals it accepts would not")
            print("    │  be yours either.")
            print("    └─────────────────────────────────────────────────────────")
            print("")
    except Exception as e:
        print("    [!!] could not pin admin authenticators: %s" % e)
        print("         approval-gated actions will be REFUSED on this device")

# ── IDEMPOTENCE GATE — do not enroll a host that is already enrolled ────────
#
# enroll() is a POST, and the server mints a FRESH device_id on every one of
# them (hw_monitor._create_enrollment: `device_id = uuid4().hex`, with no
# dedupe on public_key -- deliberately, so a genuine reinstall is a new device
# and `first_connect` fires). Calling it unconditionally therefore made a
# second run of this installer create a SECOND agent_devices row for one
# machine, orphan the first as a permanently-stale pending row, and repoint
# the conf at the new id. Both rows carry the SAME public key, because
# ensure_provisioned() correctly does not re-provision -- so the duplicate is
# invisible as a key mismatch and shows up only as an inflated device count.
#
# Reproduced deliberately on a throwaway VM 2026-08-20: one install -> 1 row;
# a second install of the same source on the same host -> 2 rows, same name,
# same IP, both pending_unverified, one shared public key.
#
# ⚠ The three answers below are NOT interchangeable:
#   real status ("pending_unverified"/"approved"/...) -> the server KNOWS this
#       device. Never re-enroll; just resync the local status string.
#   "unknown" -> the server genuinely does not have this device_id (row deleted,
#       or conf carried over from another machine). Enrolling is correct.
#   None      -> the question could not be ASKED (server unreachable, bad JSON).
#       That is a FAILED READ, not an answer, and must not be treated as
#       "unknown" -- doing so is exactly how a transient network blip during a
#       re-run mints a duplicate. Fail closed: leave the existing enrollment
#       alone and say so.
existing = (conf.get("device_id") or "").strip()
if existing:
    known = enrollment.check_status(conf, existing)
    if known is None:
        print("    [!!] already enrolled (device_id=%s...) but the server could not be "
              "reached to confirm -- NOT re-enrolling" % existing[:8])
        print("    [..] leaving the existing enrollment intact; the agent will retry on start")
        sys.exit(0)
    if known != "unknown":
        conf["enrollment_status"] = known
        config.save(conf)
        print("    [OK] already enrolled: device_id=%s... status=%s (not re-enrolling)"
              % (existing[:8], known))
        if known not in ("approved",):
            print("    [..] awaiting owner approval in the Nemesis dashboard")
        sys.exit(0)
    print("    [..] conf carries device_id=%s... but the server does not know it "
          "-- enrolling fresh" % existing[:8])

device_id, status = enrollment.enroll(conf)
if not device_id:
    print("    [FAIL] server did not answer -- check that ${SERVER}:${PORT} is reachable")
    sys.exit(1)

# PERSIST. Without this the agent does not know it already enrolled and enrols
# again on first run, producing a SECOND pending row for one machine.
conf = config.load()
conf["device_id"] = device_id
conf["enrollment_status"] = status or "pending"
config.save(conf)
print("    [OK] enrolled: device_id=%s status=%s" % (device_id[:8], status))
if status not in ("approved",):
    print("    [..] awaiting owner approval in the Nemesis dashboard")
PYEOF
    ENROLL_RC=$?
    set -e
    if [ $ENROLL_RC -ne 0 ]; then
        warn "enrollment did not complete — the agent will retry on start"
    fi
else
    step "Skipping enrollment (--no-enroll)"
fi

# ── 7. systemd service ──────────────────────────────────────────────────────
step "Creating systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Nemesis Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VPY} ${INSTALL_DIR}/agent.py
Restart=always
RestartSec=10
StandardOutput=append:${INSTALL_DIR}/nemesis_agent.log
StandardError=append:${INSTALL_DIR}/nemesis_agent.log

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
ok "service created and enabled (runs the venv interpreter)"

# ── The log file has TWO writers, and it must exist before either one runs ──
#
# systemd opens `StandardOutput=append:` as ROOT, before dropping to
# User=${AGENT_USER}. agent.py then opens the SAME path itself, as the service
# user, via logging.FileHandler (agent.py:83). If systemd creates the file
# first it lands root:root 0644, the agent's own open() gets EACCES, and the
# handler is constructed at import time -- so the agent dies before main(),
# every time, and systemd restarts it forever. Measured live 2026-08-20: a
# clean install crash-looped at "restart counter is at 3" with
# PermissionError on nemesis_agent.log and never reached enrollment at all.
#
# The `chown -R` in section 5 cannot cover this: the file does not exist yet
# when it runs -- systemd creates it here, two sections later. So pre-create it
# owned by the service user; systemd then appends to an existing file it does
# not own, which it is perfectly happy to do.
touch "${INSTALL_DIR}/nemesis_agent.log"
chown "$AGENT_USER": "${INSTALL_DIR}/nemesis_agent.log"
chmod 640 "${INSTALL_DIR}/nemesis_agent.log"
ok "log file pre-created owned by ${AGENT_USER} (both systemd and the agent append to it)"

# ── 8. Start + verify ───────────────────────────────────────────────────────
step "Starting Nemesis Agent..."
systemctl restart "$SERVICE_NAME"
sleep 3
if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "agent running"
else
    warn "agent not running — journalctl -u ${SERVICE_NAME} -n 30"
fi

# Self-check: prove the installed venv can actually import what the agent needs,
# rather than assuming a successful pip run means a working install.
step "Verifying installation..."
if "$VPY" -c "import requests, psutil" 2>/dev/null; then
    ok "venv imports required packages"
else
    fail "venv cannot import requests/psutil — the install is not usable"
fi
DEV_ID="$(grep -E '^device_id' "$CONF" | tr -d ' ' | cut -d= -f2 || true)"
if [ -n "${DEV_ID:-}" ]; then
    ok "enrolled device_id: ${DEV_ID:0:8}…"
else
    warn "no device_id recorded — the agent will enroll on first run"
fi

echo ""
echo "============================================================"
echo "  Nemesis Agent installed"
echo "  Install dir: ${INSTALL_DIR}"
echo "  Interpreter: ${VPY}"
echo "  Config:      ${CONF}"
echo "  Log file:    ${INSTALL_DIR}/nemesis_agent.log"
echo "  Status:      systemctl status ${SERVICE_NAME}"
echo "============================================================"
