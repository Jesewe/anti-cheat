import psutil
import hashlib
import os
import re
import time
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Dict, Optional

# Anti-Cheat Configuration
TARGET_PROCESS = "cs2.exe"
SCAN_INTERVAL = 5  # Seconds
LOG_FILE = "anti_cheat.log"
CHEAT_SIGNATURES = {
    "aimbot.dll": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "wallhack.dll": "b94d27b9934d3e08a52e52d7da7dabfa5a0c8c7cdbddf243c8b9f64f5a3a3db2",
}
EMAIL_ALERTS = {
    "enabled": True,
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "sender_email": "alert@example.com",
    "receiver_email": "admin@example.com",
    "email_password": "yourpassword",
}
WHITELISTED_PROCESSES = ["explorer.exe"]

# Configure Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_event(level: str, message: str):
    """Logs an event with a specific level."""
    log_func = getattr(logging, level.lower(), logging.info)
    log_func(message)
    if level.upper() == "WARNING" and EMAIL_ALERTS["enabled"]:
        send_email_alert(message)

def send_email_alert(message: str):
    """Send an email alert with the provided message."""
    try:
        msg = MIMEText(message)
        msg["Subject"] = "Anti-Cheat Alert"
        msg["From"] = EMAIL_ALERTS["sender_email"]
        msg["To"] = EMAIL_ALERTS["receiver_email"]

        with smtplib.SMTP(EMAIL_ALERTS["smtp_server"], EMAIL_ALERTS["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_ALERTS["sender_email"], EMAIL_ALERTS["email_password"])
            server.sendmail(EMAIL_ALERTS["sender_email"], EMAIL_ALERTS["receiver_email"], msg.as_string())
        log_event("INFO", "Email alert sent successfully.")
    except Exception as e:
        log_event("ERROR", f"Failed to send email alert: {e}")

def hash_file(file_path: str, algorithm: str = "sha256") -> Optional[str]:
    """Generate a secure hash (SHA-256) of a file."""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        log_event("ERROR", f"Error hashing file {file_path}: {e}")
        return None

def load_cheat_signatures() -> Dict[str, str]:
    """Load cheat signatures from a predefined dictionary or external source."""
    return CHEAT_SIGNATURES

def scan_processes(target_process: str, cheat_signatures: Dict[str, str]):
    """Scan running processes for unauthorized interactions."""
    log_event("INFO", "Scanning processes...")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name'].lower()
            if process_name in [p.lower() for p in WHITELISTED_PROCESSES]:
                log_event("INFO", f"Skipping whitelisted process: {process_name}")
                continue

            if process_name == target_process.lower():
                log_event("INFO", f"Target process found: {proc.info['name']} (PID: {proc.info['pid']})")
                scan_modules(proc.info['pid'], cheat_signatures)
                check_memory_integrity(proc.info['pid'])
        except psutil.NoSuchProcess:
            continue
        except Exception as e:
            log_event("ERROR", f"Error scanning processes: {e}")

def scan_modules(pid: int, cheat_signatures: Dict[str, str]):
    """Scan loaded modules of a process for known cheats."""
    try:
        process = psutil.Process(pid)
        for module in process.memory_maps():
            file_path = module.path
            if file_path and os.path.exists(file_path):
                file_hash = hash_file(file_path)
                if file_hash and file_hash in cheat_signatures.values():
                    log_event("WARNING", f"Detected cheat module: {file_path}")
    except psutil.AccessDenied:
        log_event("WARNING", f"Access denied to process PID: {pid}")
    except Exception as e:
        log_event("ERROR", f"Error scanning modules for PID {pid}: {e}")

def check_memory_integrity(pid: int):
    """Check memory regions for unauthorized modifications."""
    try:
        process = psutil.Process(pid)
        memory_info = process.memory_info()
        log_event("INFO", f"Memory check for PID {pid}: RSS={memory_info.rss}, VMS={memory_info.vms}")

        # Perform deeper memory scans
        for region in process.memory_maps():
            if region.path == "":  # Only scan anonymous memory regions
                try:
                    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem_file:
                        mem_file.seek(region.addr)
                        data = mem_file.read(region.size)

                        # Example: Search for a specific pattern
                        if re.search(b"cheat_code_pattern", data):
                            log_event("WARNING", f"Detected unauthorized pattern in memory region: {region.addr}")
                except Exception as e:
                    log_event("ERROR", f"Error reading memory region {region.addr} for PID {pid}: {e}")

    except psutil.AccessDenied:
        log_event("WARNING", f"Access denied to memory of PID: {pid}")
    except Exception as e:
        log_event("ERROR", f"Error during memory integrity check for PID {pid}: {e}")

def monitor():
    """Continuously monitor the system."""
    log_event("INFO", "Anti-Cheat program started.")
    cheat_signatures = load_cheat_signatures()
    try:
        while True:
            scan_processes(TARGET_PROCESS, cheat_signatures)
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        log_event("INFO", "Anti-Cheat program terminated by user.")
    except Exception as e:
        log_event("ERROR", f"Unexpected error during monitoring: {e}")
    finally:
        log_event("INFO", "Anti-Cheat monitoring stopped.")

if __name__ == "__main__":
    try:
        monitor()
    except Exception as e:
        log_event("ERROR", f"Critical error: {e}")