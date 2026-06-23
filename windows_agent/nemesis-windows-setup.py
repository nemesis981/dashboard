#!/usr/bin/env python3
"""
Nemesis Firewall Windows Setup
Installs VirtualBox (if needed), imports the Nemesis VM, installs
LibreHardwareMonitor, and sets up the Nemesis Windows Agent.

Usage:
    python nemesis-windows-setup.py

Build as EXE:
    pip install pyinstaller
    pyinstaller --onefile nemesis-windows-setup.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Optional imports — will be None on non-Windows or if not installed
# ---------------------------------------------------------------------------
try:
    import ctypes
    _CTYPES = True
except ImportError:
    _CTYPES = False

try:
    import winreg
    _WINREG = True
except ImportError:
    _WINREG = False

try:
    import requests
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

try:
    from tqdm import tqdm as _tqdm
    _TQDM = True
except ImportError:
    _TQDM = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VBOX_VERSION      = "7.0.18"
VBOX_BUILD        = "162988"
VBOX_INSTALLER_URL = (
    f"https://download.virtualbox.org/virtualbox/{VBOX_VERSION}/"
    f"VirtualBox-{VBOX_VERSION}-{VBOX_BUILD}-Win.exe"
)
VBOX_INSTALLER_FILENAME = f"VirtualBox-{VBOX_VERSION}-{VBOX_BUILD}-Win.exe"

LHM_URL = (
    "https://github.com/LibreHardwareMonitor/LibreHardwareMonitor"
    "/releases/latest/download/LibreHardwareMonitor.zip"
)
LHM_INSTALL_DIR = r"C:\Program Files\LibreHardwareMonitor"

NEMESIS_OVA_URL = (
    "https://github.com/nemesis981/dashboard/releases/latest/download/"
    "nemesis-firewall.ova"
)
NEMESIS_VM_NAME  = "Nemesis-Firewall"
AGENT_INSTALL_DIR = r"C:\nemesis-agent"

VBOX_DEFAULT_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
VMRUN_DEFAULT_PATH = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# ---------------------------------------------------------------------------
# Pretty printing helpers
# ---------------------------------------------------------------------------

def _hr(char="─", width=60):
    print(char * width)

def _step(n, text):
    print()
    _hr()
    print(f"  Step {n}: {text}")
    _hr()

def _ok(msg):
    print(f"  [OK]   {msg}")

def _info(msg):
    print(f"  [..]   {msg}")

def _warn(msg):
    print(f"  [!!]   {msg}")

def _err(msg):
    print(f"  [ERR]  {msg}", file=sys.stderr)

def _pause(prompt="  Press Enter to continue..."):
    input(prompt)

# ---------------------------------------------------------------------------
# Step 1 — Welcome screen
# ---------------------------------------------------------------------------

def welcome():
    _hr("═")
    print("""
  ███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
  ████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
  ██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
  ██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
  ██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
  Firewall — Windows Setup
""")
    _hr("═")
    print("""
  This installer will set up the Nemesis Firewall on your Windows PC.

  What will be installed:
    • VirtualBox (if not already installed) — runs the Nemesis VM
    • Nemesis Firewall VM (~2-4 GB download)
    • LibreHardwareMonitor — reads your hardware sensors
    • Nemesis Windows Agent — sends sensor data to the VM

  Estimated time: 20-30 minutes (depending on internet speed)

  Requirements:
    • Windows 10 or Windows 11 (64-bit)
    • Administrator privileges
    • ~10 GB free disk space
    • Stable internet connection
""")
    _hr("═")
    answer = input("  Ready to begin? (yes/no): ").strip().lower()
    if answer not in ("yes", "y"):
        print("\n  Setup cancelled. Run this script again when you're ready.")
        sys.exit(0)

# ---------------------------------------------------------------------------
# Step 2 — Prerequisites
# ---------------------------------------------------------------------------

def check_python_version():
    if sys.version_info < (3, 8):
        _err(f"Python 3.8 or newer is required (you have {sys.version}).")
        _err("Download the latest Python from: https://www.python.org/downloads/")
        sys.exit(1)
    _ok(f"Python {sys.version_info.major}.{sys.version_info.minor} — OK")


def check_admin():
    if not _CTYPES:
        _warn("Cannot verify administrator privileges (ctypes not available).")
        return
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False
    if not is_admin:
        _err("This installer must be run as Administrator.")
        _err("")
        _err("To restart with Administrator privileges:")
        _err("  1. Right-click the installer icon (or this terminal window)")
        _err("  2. Choose 'Run as administrator'")
        _err("  3. Run the installer again")
        sys.exit(1)
    _ok("Running as Administrator — OK")


def check_internet():
    if not _REQUESTS:
        _warn("requests library not available — skipping internet check.")
        return
    _info("Checking internet connectivity...")
    try:
        requests.get("https://github.com", timeout=10)
        _ok("Internet connectivity — OK")
    except Exception:
        _err("No internet connection detected.")
        _err("Please connect to the internet and try again.")
        sys.exit(1)


def ensure_requests():
    """Install requests + tqdm if missing (they're needed for downloads)."""
    global _REQUESTS, _TQDM, requests, _tqdm  # noqa: PLW0603
    if not _REQUESTS:
        _info("Installing required Python packages (requests, tqdm)...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "requests", "tqdm"],
            check=True,
        )
        import requests as _req
        requests = _req
        _REQUESTS = True
    if not _TQDM:
        try:
            from tqdm import tqdm as _t
            _tqdm = _t
            _TQDM = True
        except ImportError:
            pass  # fall back to simple progress


def check_prerequisites():
    _step(2, "Checking prerequisites")
    check_python_version()
    check_admin()
    ensure_requests()
    check_internet()


# ---------------------------------------------------------------------------
# Download helper with progress bar
# ---------------------------------------------------------------------------

def download_file(url, dest_path, label=None):
    """Download url → dest_path, showing progress."""
    label = label or os.path.basename(dest_path)
    _info(f"Downloading {label}...")
    _info(f"  URL : {url}")
    _info(f"  To  : {dest_path}")

    response = requests.get(url, stream=True, timeout=60)
    response.raise_for_status()

    total = int(response.headers.get("content-length", 0))

    with open(dest_path, "wb") as fh:
        if _TQDM and total:
            bar = _tqdm(
                total=total,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                desc=f"  {label[:30]}",
            )
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)
                    bar.update(len(chunk))
            bar.close()
        else:
            downloaded = 0
            last_pct = -1
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = int(downloaded * 100 / total)
                        if pct != last_pct and pct % 5 == 0:
                            mb = downloaded / 1_048_576
                            total_mb = total / 1_048_576
                            print(f"    {pct:3d}%  {mb:.1f} / {total_mb:.1f} MB")
                            last_pct = pct
            if not total:
                print(f"    Done. ({downloaded / 1_048_576:.1f} MB)")
    _ok(f"Downloaded {label}")


# ---------------------------------------------------------------------------
# Step 3 — Virtualization software
# ---------------------------------------------------------------------------

def _reg_key_exists(hive, subkey):
    if not _WINREG:
        return False
    try:
        k = winreg.OpenKey(hive, subkey)
        winreg.CloseKey(k)
        return True
    except OSError:
        return False


def _find_exe_in_program_files(*path_parts):
    for base in (
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramW6432", r"C:\Program Files"),
    ):
        if base:
            candidate = os.path.join(base, *path_parts)
            if os.path.isfile(candidate):
                return candidate
    return None


def detect_vmware():
    if _reg_key_exists(winreg.HKEY_LOCAL_MACHINE if _WINREG else None,
                       r"SOFTWARE\VMware, Inc.\VMware Workstation"):
        return True
    if _find_exe_in_program_files("VMware", "VMware Workstation", "vmware.exe"):
        return True
    return False


def detect_virtualbox():
    if _reg_key_exists(winreg.HKEY_LOCAL_MACHINE if _WINREG else None,
                       r"SOFTWARE\Oracle\VirtualBox"):
        return True
    if os.path.isfile(VBOX_DEFAULT_PATH):
        return True
    if _find_exe_in_program_files("Oracle", "VirtualBox", "VBoxManage.exe"):
        return True
    return False


def find_vboxmanage():
    if os.path.isfile(VBOX_DEFAULT_PATH):
        return VBOX_DEFAULT_PATH
    found = _find_exe_in_program_files("Oracle", "VirtualBox", "VBoxManage.exe")
    if found:
        return found
    return None


def install_virtualbox():
    tmp_dir = tempfile.gettempdir()
    installer_path = os.path.join(tmp_dir, VBOX_INSTALLER_FILENAME)

    try:
        download_file(VBOX_INSTALLER_URL, installer_path, label="VirtualBox installer")
    except Exception as exc:
        _err(f"Failed to download VirtualBox: {exc}")
        sys.exit(1)

    _info("Running VirtualBox installer silently (this may take a few minutes)...")
    try:
        result = subprocess.run(
            [installer_path, "--silent", "--ignore-reboot"],
            check=True,
        )
        _ = result  # used
    except subprocess.CalledProcessError as exc:
        _err(f"VirtualBox installer failed (exit code {exc.returncode}).")
        _err("Try running the installer manually from:")
        _err(f"  {installer_path}")
        sys.exit(1)

    _info("Waiting for installation to complete...")
    time.sleep(10)

    if not find_vboxmanage():
        _err("VirtualBox was installed but VBoxManage.exe was not found.")
        _err("Please ensure VirtualBox installed correctly and try again.")
        sys.exit(1)
    _ok("VirtualBox installed successfully")


def check_virtualization():
    _step(3, "Checking for virtualization software")

    if detect_vmware():
        _ok("VMware Workstation detected")
        _warn("VMware support: VM import will use VirtualBox workflow for now.")
        _warn("Full VMware support is planned for a future release.")
        _info("Falling back to VirtualBox installation.")

    if detect_virtualbox():
        _ok("VirtualBox detected")
        vboxmanage = find_vboxmanage()
        if vboxmanage:
            _ok(f"VBoxManage found: {vboxmanage}")
            return "virtualbox", vboxmanage

    _info("No virtualization software found.")
    _info("Nemesis will install VirtualBox (free, open source).")
    print()
    answer = input("  Install VirtualBox now? (yes/no): ").strip().lower()
    if answer not in ("yes", "y"):
        _err("VirtualBox is required. Please install it manually from:")
        _err("  https://www.virtualbox.org/wiki/Downloads")
        sys.exit(1)

    install_virtualbox()
    vboxmanage = find_vboxmanage()
    return "virtualbox", vboxmanage


# ---------------------------------------------------------------------------
# Step 4 — Download Nemesis VM image
# ---------------------------------------------------------------------------

def download_ova():
    _step(4, "Downloading Nemesis VM image")
    _warn("Downloading the Nemesis Firewall VM (~2-4 GB). Please be patient.")

    tmp_dir = tempfile.gettempdir()
    ova_path = os.path.join(tmp_dir, "nemesis-firewall.ova")

    if os.path.isfile(ova_path):
        size_mb = os.path.getsize(ova_path) / 1_048_576
        _info(f"Found existing download at {ova_path} ({size_mb:.0f} MB).")
        answer = input("  Use existing file? (yes/no): ").strip().lower()
        if answer in ("yes", "y"):
            _ok("Using existing OVA file")
            return ova_path

    try:
        download_file(NEMESIS_OVA_URL, ova_path, label="nemesis-firewall.ova")
    except Exception as exc:
        _err(f"Failed to download Nemesis VM: {exc}")
        _err("Check your internet connection and try again.")
        sys.exit(1)

    return ova_path


# ---------------------------------------------------------------------------
# Step 5 — Import VM
# ---------------------------------------------------------------------------

def _detect_active_adapter():
    """Return the name of the active ethernet/wifi adapter from ipconfig."""
    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = result.stdout.splitlines()
        adapter_name = None
        for line in lines:
            # Lines like: "Ethernet adapter Local Area Connection:"
            # or "Wireless LAN adapter Wi-Fi:"
            stripped = line.strip()
            if stripped.endswith(":") and ("adapter" in stripped.lower()):
                # Extract name: everything after "adapter " and before ":"
                low = stripped.lower()
                for keyword in ("ethernet adapter ", "wireless lan adapter ", "wi-fi adapter "):
                    if keyword in low:
                        name_start = low.index(keyword) + len(keyword)
                        adapter_name = stripped[name_start:].rstrip(":")
                        break
            # Check if this adapter has an IPv4 address (i.e. it's active)
            if adapter_name and "IPv4 Address" in line:
                return adapter_name
        # Fall back to first adapter found
        return adapter_name
    except Exception:
        return None


def import_vm_virtualbox(vboxmanage, ova_path):
    _info("Importing Nemesis VM into VirtualBox...")
    _info("(This may take 5-10 minutes)")

    try:
        subprocess.run(
            [
                vboxmanage, "import", ova_path,
                "--vsys", "0",
                "--memory", "4096",
                "--cpus", "4",
            ],
            check=True,
        )
        _ok("VM imported successfully")
    except subprocess.CalledProcessError as exc:
        _err(f"Failed to import VM (exit code {exc.returncode}).")
        _err("Check that VirtualBox is installed correctly and the OVA file is not corrupted.")
        sys.exit(1)

    # Configure bridged networking
    adapter_name = _detect_active_adapter()
    if not adapter_name:
        _warn("Could not auto-detect active network adapter.")
        adapter_name = input(
            "  Enter your network adapter name (e.g. 'Ethernet' or 'Wi-Fi'): "
        ).strip()

    if adapter_name:
        _info(f"Configuring bridged networking on adapter: {adapter_name}")
        try:
            subprocess.run(
                [
                    vboxmanage, "modifyvm", NEMESIS_VM_NAME,
                    "--nic1", "bridged",
                    "--bridgeadapter1", adapter_name,
                ],
                check=True,
            )
            _ok(f"Bridged networking configured ({adapter_name})")
        except subprocess.CalledProcessError as exc:
            _warn(f"Could not configure bridged networking (exit code {exc.returncode}).")
            _warn("You may need to configure this manually in VirtualBox settings.")

    # Start VM headless
    _info("Starting Nemesis VM in headless mode...")
    try:
        subprocess.run(
            [vboxmanage, "startvm", NEMESIS_VM_NAME, "--type", "headless"],
            check=True,
        )
        _ok("Nemesis VM started")
    except subprocess.CalledProcessError as exc:
        _err(f"Failed to start VM (exit code {exc.returncode}).")
        _err("Try starting it manually from the VirtualBox Manager.")
        sys.exit(1)


def import_vm(virt_type, vboxmanage, ova_path):
    _step(5, "Importing Nemesis VM")

    if virt_type == "virtualbox":
        import_vm_virtualbox(vboxmanage, ova_path)
    else:
        _err(f"Unsupported virtualization type: {virt_type}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Step 6 — Install LibreHardwareMonitor
# ---------------------------------------------------------------------------

def install_lhm():
    _step(6, "Installing LibreHardwareMonitor")

    tmp_dir = tempfile.gettempdir()
    zip_path = os.path.join(tmp_dir, "LibreHardwareMonitor.zip")

    try:
        download_file(LHM_URL, zip_path, label="LibreHardwareMonitor.zip")
    except Exception as exc:
        _err(f"Failed to download LibreHardwareMonitor: {exc}")
        sys.exit(1)

    _info(f"Extracting to {LHM_INSTALL_DIR}...")
    os.makedirs(LHM_INSTALL_DIR, exist_ok=True)

    import zipfile
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(LHM_INSTALL_DIR)
        _ok(f"LibreHardwareMonitor extracted to {LHM_INSTALL_DIR}")
    except Exception as exc:
        _err(f"Failed to extract LibreHardwareMonitor: {exc}")
        sys.exit(1)

    lhm_exe = os.path.join(LHM_INSTALL_DIR, "LibreHardwareMonitor.exe")
    print()
    print("  " + "─" * 58)
    print("  ACTION REQUIRED: Set up LibreHardwareMonitor")
    print("  " + "─" * 58)
    print(f"""
  LibreHardwareMonitor has been installed to:
    {LHM_INSTALL_DIR}

  You need to set it up manually:

    1. Open:  {lhm_exe}
    2. Right-click the file → 'Run as administrator'
    3. In the menu: Options → Web Server
    4. Check the box: 'Run Web Server'
    5. Leave LibreHardwareMonitor running in the system tray
       (minimize it — do NOT close it)

  The setup wizard needs it running before it can continue.
""")
    print("  " + "─" * 58)

    while True:
        answer = input(
            "  Have you started LibreHardwareMonitor with the web server? (yes/no): "
        ).strip().lower()
        if answer in ("yes", "y"):
            break
        print("  Please complete the steps above, then answer 'yes'.")


# ---------------------------------------------------------------------------
# Step 7 — Install Windows Agent
# ---------------------------------------------------------------------------

def install_agent():
    _step(7, "Installing Nemesis Windows Agent")

    # Install runtime dependencies
    _info("Installing Python dependencies...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "requests", "psutil"],
            check=True,
        )
        _ok("Python dependencies installed")
    except subprocess.CalledProcessError as exc:
        _err(f"pip install failed (exit code {exc.returncode}).")
        sys.exit(1)

    # Copy agent files
    os.makedirs(AGENT_INSTALL_DIR, exist_ok=True)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    agent_files = ["agent.py", "discover.py"]
    for fname in agent_files:
        src = os.path.join(script_dir, fname)
        dst = os.path.join(AGENT_INSTALL_DIR, fname)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
            _ok(f"Copied {fname} → {dst}")
        else:
            _warn(f"Agent file not found: {src}")
            _warn("Make sure agent.py and discover.py are in the same folder as this installer.")

    # Run discovery (interactive)
    discover_script = os.path.join(AGENT_INSTALL_DIR, "discover.py")
    if os.path.isfile(discover_script):
        print()
        print("  " + "─" * 58)
        print("  Sensor Discovery")
        print("  " + "─" * 58)
        print("""
  The sensor discovery wizard will now run.
  It will ask you to map your hardware sensors (CPU temp, fans, etc.)
  to the roles Nemesis uses on the dashboard.

  Have the Nemesis VM's IP address ready.
  (Check your router's connected devices list, or wait for the VM
  to finish booting — it usually takes 5-10 minutes on first start.)
""")
        _pause("  Press Enter to start sensor discovery...")
        try:
            subprocess.run(
                [sys.executable, discover_script],
                check=True,
            )
            _ok("Sensor discovery complete")
        except subprocess.CalledProcessError as exc:
            _warn(f"Sensor discovery exited with code {exc.returncode}.")
            _warn("You can re-run it later with: python C:\\nemesis-agent\\discover.py")
    else:
        _warn("discover.py not found — skipping sensor discovery.")
        _warn("Run it manually later: python C:\\nemesis-agent\\discover.py")


# ---------------------------------------------------------------------------
# Step 8 — Set up Windows Agent at startup
# ---------------------------------------------------------------------------

def setup_startup():
    _step(8, "Configuring Windows Agent to start automatically")

    agent_script = os.path.join(AGENT_INSTALL_DIR, "agent.py")
    username = os.environ.get("USERNAME", os.environ.get("USER", ""))
    task_name = "NemesisAgent"

    _info(f"Creating Task Scheduler task '{task_name}'...")
    try:
        subprocess.run(
            [
                "schtasks", "/create",
                "/tn", task_name,
                "/tr", f'"{sys.executable}" "{agent_script}"',
                "/sc", "onlogon",
                "/ru", username,
                "/f",
            ],
            check=True,
        )
        _ok(f"Startup task '{task_name}' created (runs at logon for {username})")
    except subprocess.CalledProcessError as exc:
        _warn(f"Failed to create startup task (exit code {exc.returncode}).")
        _warn("The agent will not start automatically on reboot.")
        _warn(f"You can start it manually: python {agent_script}")

    # Start the agent now
    _info("Starting the Nemesis Windows Agent now...")
    try:
        subprocess.Popen(
            [sys.executable, agent_script],
            creationflags=subprocess.DETACHED_PROCESS
            if hasattr(subprocess, "DETACHED_PROCESS")
            else 0,
        )
        _ok("Nemesis Windows Agent started in background")
    except Exception as exc:
        _warn(f"Could not start agent automatically: {exc}")
        _warn(f"Start it manually: python {agent_script}")


# ---------------------------------------------------------------------------
# Step 9 — Completion
# ---------------------------------------------------------------------------

def print_completion(virt_type):
    print()
    _hr("═")
    print("""
  Setup Complete!
""")
    _hr()
    label = "VirtualBox" if virt_type == "virtualbox" else "VMware"
    print(f"  {label:<30}  installed  ✓")
    print(f"  {'Nemesis Firewall VM':<30}  imported and starting  ✓")
    print(f"  {'LibreHardwareMonitor':<30}  installed  ✓")
    print(f"  {'Nemesis Windows Agent':<30}  installed and running  ✓")
    _hr()
    print("""
  The Nemesis VM is now starting up and running its setup wizard.
  This may take 5-10 minutes on the first boot — please be patient.

  Once the VM has started:
    • Open your browser and go to: http://<vm-ip>
    • The VM's IP address can be found by:
        - Opening VirtualBox Manager
        - Selecting the 'Nemesis-Firewall' VM
        - Clicking Details → Network
        - Or checking your router's 'Connected Devices' list

  Your Windows hardware sensor data is being sent to the VM
  automatically via the Nemesis Windows Agent.

  The agent will restart automatically when you log in to Windows.
""")
    _hr("═")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Step 1: Welcome
    welcome()

    # Step 2: Prerequisites
    check_prerequisites()

    # Step 3: Virtualization
    virt_type, vboxmanage = check_virtualization()

    # Step 4: Download OVA
    ova_path = download_ova()

    # Step 5: Import VM
    import_vm(virt_type, vboxmanage, ova_path)

    # Step 6: LibreHardwareMonitor
    install_lhm()

    # Step 7: Windows Agent
    install_agent()

    # Step 8: Startup task
    setup_startup()

    # Step 9: Done
    print_completion(virt_type)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Setup interrupted by user.")
        sys.exit(1)
