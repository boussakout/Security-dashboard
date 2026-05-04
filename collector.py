import time
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from db import init_db, save_event
from datetime import datetime

# Log file paths
LOG_FILES = {
    "auth":   "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "dpkg":   "/var/log/dpkg.log",
    "ufw":    "/var/log/ufw.log",
}

# Remember where we stopped reading each file
positions = {
    "auth":   0,
    "syslog": 0,
    "dpkg":   0,
    "ufw":    0,
}
# Noisy patterns to ignore
IGNORE_PATTERNS = [
    "snapd",
    "snap.",
    "systemd[1249]",
    "Started Service for sn",
    "Stopped Service for sn",
]

def should_ignore(line):
    for pattern in IGNORE_PATTERNS:
        if pattern in line:
            return True
    return False

def parse_line(source, line):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Skip noisy lines first
    if should_ignore(line):
        return None

    # --- AUTH.LOG rules ---
    if source == "auth":
        if "Failed password" in line:
            return (timestamp, "auth.log", "CRITICAL", line.strip())
        if "Accepted password" in line or "Accepted publickey" in line:
            return (timestamp, "auth.log", "INFO", line.strip())
        if "sudo" in line and "COMMAND" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())
        if "new user" in line or "new group" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())
        if "session opened" in line:
            return (timestamp, "auth.log", "INFO", line.strip())
        if "session closed" in line:
            return (timestamp, "auth.log", "INFO", line.strip())
        if "authentication failure" in line:
            return (timestamp, "auth.log", "CRITICAL", line.strip())

    # --- SYSLOG rules ---
    if source == "syslog":
        if "error" in line.lower() or "failed" in line.lower():
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "warning" in line.lower():
            return (timestamp, "syslog", "WARNING", line.strip())
        if "kernel" in line.lower() and "denied" in line.lower():
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "out of memory" in line.lower():
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "segfault" in line.lower():
            return (timestamp, "syslog", "CRITICAL", line.strip())

    # --- DPKG rules ---
    if source == "dpkg":
        if "install" in line and "status" not in line:
            return (timestamp, "dpkg.log", "WARNING", line.strip())
        if "remove" in line and "status" not in line:
            return (timestamp, "dpkg.log", "WARNING", line.strip())
        if "upgrade" in line:
            return (timestamp, "dpkg.log", "INFO", line.strip())

    # --- UFW rules ---
    if source == "ufw":
        if "BLOCK" in line:
            return (timestamp, "ufw.log", "CRITICAL", line.strip())
        if "ALLOW" in line:
            return (timestamp, "ufw.log", "INFO", line.strip())
        if "AUDIT" in line:
            return (timestamp, "ufw.log", "WARNING", line.strip())

    return None  # ignore line if no rule matched

def watch_logs():
    print("🔍 Collector started — watching log files...")
    print("📁 Monitoring: auth.log | syslog | dpkg.log")
    print("⏱  Checking every 5 seconds — press CTRL+C to stop\n")

    init_db()

    while True:
        for source, path in LOG_FILES.items():
            try:
                with open(path, "r", errors="ignore") as f:
                    f.seek(positions[source])   # go to where we stopped

                    for line in f:
                        result = parse_line(source, line)
                        if result:
                            save_event(*result)
                            level_icon = {
                                "CRITICAL": "🔴",
                                "WARNING":  "🟡",
                                "INFO":     "🟢"
                            }.get(result[2], "⚪")
                            print(f"{level_icon} [{result[2]}] {result[1]} → {result[3][:70]}")

                    positions[source] = f.tell()  # save new position

            except FileNotFoundError:
                print(f"⚠️  File not found: {path}")
            except PermissionError:
                print(f"🔒 Permission denied: {path} — run with sudo")

        time.sleep(5)  # wait 5 seconds then check again

if __name__ == "__main__":
    watch_logs()
