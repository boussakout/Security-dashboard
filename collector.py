import time
import os
import sys
import urllib.request
import urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db import init_db, save_event
from datetime import datetime

# ── Telegram config ──────────────────────────────────────────
TELEGRAM_TOKEN   = ""
TELEGRAM_CHAT_ID = ""

# ── Rate limiting ────────────────────────────────────────────
last_alert_time = {}
ALERT_COOLDOWN_SECONDS = 60

def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=5)
        print("📨 Telegram alert sent!")
    except Exception as e:
        print(f"⚠️  Telegram failed: {e}")

def should_alert(event_key):
    now = time.time()
    last = last_alert_time.get(event_key, 0)
    if now - last >= ALERT_COOLDOWN_SECONDS:
        last_alert_time[event_key] = now
        return True
    return False

def get_event_key(source, message):
    ssh_triggers = [
        "Failed password", "Invalid user",
        "authentication failure", "BREAK-IN ATTEMPT",
        "maximum authentication", "Connection closed by invalid user", "PAM",
    ]
    if source == "auth.log" and any(t in message for t in ssh_triggers):
        return "auth_ssh_attack"
    if "UFW BLOCK" in message:
        for port in ["DPT=22","DPT=23","DPT=3389","DPT=445","DPT=1433","DPT=3306"]:
            if port in message:
                return f"ufw_{port}"
        return "ufw_block_other"
    if 'apparmor="DENIED"' in message: return f"{source}_apparmor"
    if "Out of memory" in message:     return f"{source}_oom"
    if "segfault" in message:          return f"{source}_segfault"
    if "No space left" in message:     return f"{source}_disk_full"
    if "*ERROR*" in message:           return f"{source}_kernel_error"
    return f"{source}_critical_other"

def format_telegram_message(timestamp, source, message):
    icons = {
        "auth.log": "🔐",
        "ufw.log":  "🛡️",
        "syslog":   "⚙️",
        "dpkg.log": "📦",
    }
    icon = icons.get(source, "⚠️")
    short = message
    if ": " in message:
        parts = message.split(": ", 3)
        if len(parts) >= 3:
            short = parts[-1]
    return (
        f"🚨 <b>SECURITY ALERT</b>\n\n"
        f"{icon} <b>Source:</b> {source}\n"
        f"🕐 <b>Time:</b> {timestamp}\n"
        f"📋 <b>Event:</b> {short[:300]}"
    )

# ── Log files to monitor ─────────────────────────────────────
LOG_FILES = {
    "auth":   "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "dpkg":   "/var/log/dpkg.log",
    "ufw":    "/var/log/ufw.log",
}

positions = {
    "auth":   0,
    "syslog": 0,
    "dpkg":   0,
    "ufw":    0,
}

# ── Noise to ignore ──────────────────────────────────────────
IGNORE_PATTERNS = [
    # Snap noise
    "snapd", "snap.", "systemd[1249]",
    "Started Service for sn", "Stopped Service for sn",
    # Graphics
    "libEGL", "MESA", "ZINK", "vkEnumerate",
    "libGL", "dri2", "pdev", "EDID",
    # Desktop
    "gsd-color", "gsd-media", "gnome-shell",
    "xdg-permission", "xdg-document",
    "pulseaudio", "gdm-launch", "firefox",
    "glib-gobject", "g_object_unref",
    "GetManagedObjects", "GLib-GObject",
    "keybinding", "accelerator",
    "libreoffice", "soffice", "Xorg", "xf86",
    # AppArmor allowed = not a threat
    'apparmor="ALLOWED"', 'apparmor="allow"',
    # Audit = normal system logging
    "audit: type=1400", "audit(", "apparmor",
    # OOM routine
    "Userspace Out-Of-Memory",
    "Starting Userspace Out-Of-Memory",
    "oom_reaper",
    # Systemd routine
    "systemd[1]: Started", "systemd[1]: Stopped",
    "systemd[1]: Starting", "systemd[1]: Stopping",
    # Hardware daemons
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

    if should_ignore(line):
        return None

    # ────────────────────────────────────────────────────────
    # AUTH.LOG
    # Tracks logins, sudo usage, user management
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

        # WARNING — suspicious but not necessarily attack
        if "sudo" in line and "COMMAND" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())
        if "new user" in line or "useradd" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())
        if "user deleted" in line or "userdel" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())
        if "usermod" in line:
            return (timestamp, "auth.log", "WARNING", line.strip())

        # INFO — normal activity
        if "Accepted password" in line or "Accepted publickey" in line:
            return (timestamp, "auth.log", "INFO", line.strip())
        if "session opened" in line:
            return (timestamp, "auth.log", "INFO", line.strip())
        if "session closed" in line:
            return (timestamp, "auth.log", "INFO", line.strip())

    # ────────────────────────────────────────────────────────
    # UFW.LOG
    # Only care about BLOCK on dangerous ports
    # Ignore ALLOW, AUDIT, and non-dangerous port blocks
    # ────────────────────────────────────────────────────────
    if source == "ufw":
        dangerous_ports = [
            "DPT=22 ", "DPT=23 ", "DPT=3389 ",
            "DPT=445 ", "DPT=1433 ", "DPT=3306 ",
        ]
        if "[UFW BLOCK]" in line:
            if any(p in line for p in dangerous_ports):
                return (timestamp, "ufw.log", "CRITICAL", line.strip())
        # Everything else (ALLOW, AUDIT, non-dangerous) = ignore
        return None

    # ────────────────────────────────────────────────────────
    # SYSLOG
    # Only real kernel security events
    # Skip all UFW lines here — handled by ufw.log above
    # ────────────────────────────────────────────────────────
    if source == "syslog":
        # Skip all UFW lines — already handled by ufw.log
        if "[UFW" in line:
            return None
        # CRITICAL kernel security events
        if 'apparmor="DENIED"' in line:
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "Out of memory: Killed process" in line:
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "segfault" in line.lower() and "kernel" in line.lower():
            return (timestamp, "syslog", "CRITICAL", line.strip())
        if "No space left on device" in line:
            return (timestamp, "syslog", "CRITICAL", line.strip())
        # WARNING kernel events
        if "*ERROR*" in line and "kernel" in line.lower():
            return (timestamp, "syslog", "WARNING", line.strip())
        if "I/O error" in line and "kernel" in line.lower():
            return (timestamp, "syslog", "WARNING", line.strip())

    # ────────────────────────────────────────────────────────
    # DPKG.LOG
    # Software installs and removals
    # ────────────────────────────────────────────────────────
    if source == "dpkg":
        if " install " in line and "status" not in line and "startup" not in line:
            return (timestamp, "dpkg.log", "WARNING", line.strip())
        if " remove " in line and "status" not in line and "startup" not in line:
            return (timestamp, "dpkg.log", "WARNING", line.strip())
        if " upgrade " in line and "status" not in line:
            return (timestamp, "dpkg.log", "INFO", line.strip())

    return None


def init_positions():
    """Jump to end of all files — no alerts for old data"""
    print("⏩ Jumping to end of log files — only NEW lines processed\n")
    for source, path in LOG_FILES.items():
        try:
            with open(path, "r", errors="ignore") as f:
                f.seek(0, 2)
                positions[source] = f.tell()
            print(f"   ✅ {path} — ready")
        except FileNotFoundError:
            print(f"   ⚠️  {path} not found — skipping")
        except PermissionError:
            print(f"   🔒 {path} — run with sudo")


def watch_logs():
    print("╔══════════════════════════════════════════════════╗")
    print("║       🛡️  Security Dashboard Collector           ║")
    print("╠══════════════════════════════════════════════════╣")
    print("║  📁 auth.log  → logins, sudo, users             ║")
    print("║  📁 ufw.log   → firewall blocks                 ║")
    print("║  📁 syslog    → kernel security events          ║")
    print("║  📁 dpkg.log  → software changes                ║")
    print("║  📨 Telegram  → CRITICAL only, 60s cooldown     ║")
    print("╚══════════════════════════════════════════════════╝\n")

    init_db()
    init_positions()
    print("\n👀 Watching for NEW events...\n")

    while True:
        for source, path in LOG_FILES.items():
            try:
                with open(path, "r", errors="ignore") as f:
                    f.seek(positions[source])
                    for line in f:
                        result = parse_line(source, line)
                        if result:
                            timestamp, src, level, msg = result
                            save_event(timestamp, src, level, msg)
                            icon = {
                                "CRITICAL": "🔴",
                                "WARNING":  "🟡",
                                "INFO":     "🟢"
                            }.get(level, "⚪")
                            print(f"{icon} [{level}] {src} → {msg[:80]}")

                            # Telegram only for CRITICAL with cooldown
                            if level == "CRITICAL":
                                key = get_event_key(src, msg)
                                if should_alert(key):
                                    alert = format_telegram_message(
                                        timestamp, src, msg
                                    )
                                    send_telegram(alert)
                                else:
                                    print(f"   ⏳ Suppressed (cooldown: {key})")

                    positions[source] = f.tell()

            except FileNotFoundError:
                pass
            except PermissionError:
                print(f"🔒 Permission denied: {path} — run with sudo")

        time.sleep(5)


if __name__ == "__main__":
    watch_logs()
