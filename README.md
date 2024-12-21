# **Anti-Cheat Program**

This anti-cheat program is designed to detect unauthorized interactions with the `cs2.exe` process (Counter-Strike 2) by scanning running processes, loaded modules, and memory regions for known cheat signatures.

## **Features**
- **Process Monitoring**: Continuously scans for the `cs2.exe` process.
- **Module Scanning**: Detects unauthorized DLLs or modules loaded into the target process.
- **Memory Integrity Checks**: Monitors memory usage for anomalies or suspicious modifications.
- **Deeper Memory Scans**: Searches for specific patterns or unauthorized code injections in memory regions.
- **Logging**: Logs all events, including detections, warnings, and errors, to a file (`anti_cheat.log`).
- **Signature-Based Detection**: Uses SHA-256 hashes to identify known cheat files.
- **Email Alerts**: Sends real-time email notifications when a cheat module is detected.
- **Process Whitelisting**: Allows certain processes to be excluded from scans to avoid false positives.

---

## **Requirements**
This program is written in Python and requires the following dependencies:
- **Python 3.8+**
- **Required Libraries**:
  - `psutil`: For process and memory management.
  - `hashlib`: For secure hashing.
  - `logging`: For logging events to a file.
  - `smtplib`: For sending email alerts.
  - `re`: For pattern matching in memory scans.

Install the required libraries using pip:
```bash
pip install psutil
```

---

## **How It Works**
1. **Target Process**: Monitors the `cs2.exe` process.
2. **Cheat Signature Matching**:
   - Predefined cheat signatures are stored as SHA-256 hashes.
   - Scans loaded modules and matches their hashes against known cheat signatures.
3. **Memory Monitoring**:
   - Logs memory usage and checks for unauthorized modifications.
   - Performs deeper memory scans for specific patterns or unauthorized injections.
4. **Logging**:
   - Logs all activity (INFO, WARNING, ERROR) to `anti_cheat.log`.
5. **Email Alerts**:
   - Sends notifications to a predefined email address when cheats are detected.
6. **Whitelisting**:
   - Skips scanning for processes listed in the whitelist.

---

## **Configuration**
You can configure the program by modifying the following constants in the `anti_cheat.py` file:

- `TARGET_PROCESS`: Name of the process to monitor (default: `"cs2.exe"`).
- `SCAN_INTERVAL`: Interval (in seconds) between scans (default: `5` seconds).
- `LOG_FILE`: Name of the log file (default: `"anti_cheat.log"`).
- `CHEAT_SIGNATURES`: Dictionary of known cheat file names and their SHA-256 hashes.
- `EMAIL_ALERTS`: Email settings for sending notifications (enabled by default).
- `WHITELISTED_PROCESSES`: List of process names to exclude from scanning.

Example configuration:
```python
TARGET_PROCESS = "cs2.exe"
SCAN_INTERVAL = 5
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
    "email_password": "yourpassword"
}
WHITELISTED_PROCESSES = ["explorer.exe"]
```

---

## **Usage**
1. Clone or download this repository.
2. Ensure all dependencies are installed.
3. Run the program:
   ```bash
   python anti_cheat.py
   ```
4. The program will continuously monitor for cheats and log activity to `anti_cheat.log`.

---

## **Logging**
All activity is logged to `anti_cheat.log` with timestamps and severity levels:
- **INFO**: General information, such as process scans and memory checks.
- **WARNING**: Suspicious activity, such as detected cheats or access denial.
- **ERROR**: Critical issues, such as file read errors or unexpected exceptions.

---

## **Adding Cheat Signatures**
To add new cheat signatures:
1. Compute the SHA-256 hash of the cheat file:
   ```bash
   sha256sum <cheat_file>
   ```
2. Add the filename and hash to the `CHEAT_SIGNATURES` dictionary in `anti_cheat.py`.

Example:
```python
CHEAT_SIGNATURES = {
    "new_cheat.dll": "abc123...xyz456",
    ...
}
```

---

## **Limitations**
- **Signature-Based Detection**: Only detects cheats listed in the `CHEAT_SIGNATURES` dictionary.
- **Access Permissions**: May require elevated permissions to access certain processes or memory regions.
- **Performance Impact**: Scanning processes and memory can be resource-intensive on low-end systems.

---

## **Disclaimer**
This program is for educational purposes only. Ensure compliance with all legal and ethical standards when using this program. Unauthorized use may violate privacy or terms of service agreements.

---

## **License**
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.