import time
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db import init_db, save_event
from datetime import datetime

# ── Log files to monitor ─────────────────────────────────────
LOG_FILES = {
    "auth":   "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "dpkg":   "/var/log/dpkg.log",
}

positions = {
    "auth":   0,
    "syslog": 0,
    "dpkg":   0,
}

# ── Lines to ignore completely (noise) ───────────────────────
IGNORE_PATTERNS = [
    # Snap noise
    "snapd", "snap.", "systemd[1249]",
    "Started Service for sn", "Stopped Service for sn",
    # Graphics/display — not security
    "libEGL", "MESA", "ZINK", "vkEnumerate",
    "libGL", "dri2", "pdev", "EDID",
    # Desktop noise
    "gsd-color", "gsd-media", "gnome-shell",
    "xdg-permission", "xdg-document",
    "pulseaudio", "gdm-launch", "firefox",
    "glib-gobject", "g_object_unref",
    "GetManagedObjects", "GLib-GObject",
    "keybinding", "accelerator",
    "libreoffice", "soffice", "Xorg", "xf86",
    # AppArmor ALLOWED = explicitly permitted, not a threat
    'apparmor="ALLOWED"', 'apparmor="allow"',
    # Kernel audit = normal system call logging, not threats
    "audit: type=1400", "audit(", "apparmor",
    # OOM routine = normal memory management
    "Userspace Out-Of-Memory",
    "Starting Userspace Out-Of-Memory",
    "oom_reaper",
    # Systemd routine start/stop noise
    "systemd[1]: Started", "systemd[1]: Stopped",
    "systemd[1]: Starting", "systemd[1]: Stopping",
    # Hardware/network daemons noise
    "bluetoothd", "NetworkManager", "avahi-daemon",
    "thermald", "acpid", "ModemManager",
    "dbus-daemon", "packagekit", "whoopsie", "kerneloops",
]

def should_ignore(line):
    for pattern in IGNORE_PATTERNS:
        if pattern.lower() in line.lower():
            return True
    return False

def parse_line(source, line):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Always skip noise first
    if should_ignore(line):
        return None

    # ────────────────────────────────────────────────────────
    # AUTH.LOG — login attempts, sudo, user changes
    # ────────────────────────────────────────────────────────
    if source == "auth":

        # CRITICAL — real attack indicators
        if "Failed password" in line:
            return (timestamp, "auth.log", "CRITICAL", line.strip())
        if "Invalid user" in line:
            return (timestamp, "auth.log", "CRITICAL", line.strip())
        if "authentication failure" in line:
            return (timestamp, "auth.log", "CRITICAL", line.strip())
        if "BREAK-IN ATTEMPT" in line:
            return (timestamp, "auth.log", "CRITICAL", line.strip())
        if "maximum authentication attempts exceeded" in line:
            return (timestamp, "auth.log", "CRITICAL", line.strip())
        if "Connection closed by invalid user" in line:
            return (timestamp, "auth.log", "CRITICAL", line.strip())

        # WARNING — suspicious but not necessarily an attack
        if "sudo" in line and "COMMAND" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())
        if "new user" in line or "useradd" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())
        if "user deleted" in line or "userdel" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())
        if "usermod" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())

        # INFO — normal activity worth logging
        if "Accepted password" in line or "Accepted publickey" in line:
            return (timestamp, "auth.log", "INFO", line.strip())
        if "session opened" in line:
            return (timestamp, "auth.log", "INFO", line.strip())
        if "session closed" in line:
            return (timestamp, "auth.log", "INFO", line.strip())

    # ────────────────────────────────────────────────────────
    # SYSLOG — kernel security + UFW firewall
    # UFW writes to syslog not ufw.log on this system
    # ────────────────────────────────────────────────────────
    if source == "syslog":

        # UFW firewall — only flag attacks on dangerous ports
        # Normal internet traffic on random ports = ignore
        if "[UFW BLOCK]" in line:
            dangerous_ports = [
                "DPT=22 ",    # SSH brute force
                "DPT=23 ",    # Telnet
                "DPT=3389 ",  # RDP
                "DPT=445 ",   # SMB
                "DPT=1433 ",  # MSSQL
                "DPT=3306 ",  # MySQL
            ]
            if any(p in line for p in dangerous_ports):
                return (timestamp, "ufw.log", "CRITICAL", line.strip())
            # All other UFW blocks = normal internet noise, skip
            return None

        # Real kernel security events
        if 'apparmor="DENIED"' in line:
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "Out of memory: Killed process" in line:
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "segfault" in line.lower() and "kernel" in line.lower():
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "No space left on device" in line:
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "I/O error" in line and "kernel" in line.lower():
            return (timestamp, "syslog", "WARNING", line.strip())

    # ────────────────────────────────────────────────────────
    # DPKG.LOG — software installs and removals
    # ────────────────────────────────────────────────────────
    if source == "dpkg":
        if " install " in line and "status" not in line and "startup" not in line:
            return (timestamp, "dpkg.log", "WARNING", line.strip())
        if " remove " in line and "status" not in line and "startup" not in line:
            return (timestamp, "dpkg.log", "WARNING", line.strip())
        if " upgrade " in line and "status" not in line:
            return (timestamp, "dpkg.log", "INFO", line.strip())

    return None


def watch_logs():
    print("🔍 Collector started — watching log files...")
    print("📁 auth.log | syslog (UFW included) | dpkg.log")
    print("⏱  Checking every 5 seconds\n")
    init_db()

    while True:
        for source, path in LOG_FILES.items():
            try:
                with open(path, "r", errors="ignore") as f:
                    f.seek(positions[source])
                    for line in f:
                        result = parse_line(source, line)
                        if result:
                            save_event(*result)
                            icon = {"CRITICAL":"🔴","WARNING":"🟡","INFO":"🟢"}.get(result[2],"⚪")
                            print(f"{icon} [{result[2]}] {result[1]} → {result[3][:80]}")
                    positions[source] = f.tell()
            except FileNotFoundError:
                pass
            except PermissionError:
                print(f"🔒 Permission denied: {path} — run with sudo")
        time.sleep(5)


if __name__ == "__main__":
    watch_logs()
