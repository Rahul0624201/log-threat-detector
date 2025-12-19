# log-threat-detector
🔐 Log Analyzer & Threat Detector (Python)

A defensive cybersecurity tool that parses Linux authentication logs and detects common attack patterns such as brute-force attempts, password spraying, suspicious successful logins, and off-hours access.

This project simulates real SOC (Security Operations Center) workflows by turning raw logs into actionable security alerts.

🚀 Features

✅ Parse Linux auth.log / SSH logs
✅ Detect brute-force attacks from a single IP
✅ Detect password spraying across multiple users
✅ Detect successful login after multiple failures
✅ Flag off-hours successful logins
✅ Generate alerts in JSON and CSV reports
✅ Simple CLI interface with tunable thresholds

🛠️ Tech Stack

- Python 3.10+

- Python Standard Library only (no external dependencies)

- Regex-based log parsing

- CLI using argparse

📁 Project Structure

log-threat-detector/
├── src/
│ ├── init.py
│ ├── detector.py # CLI entry point
│ ├── parsers.py # Log parsing logic
│ ├── rules.py # Detection rules
│ └── report.py # Report generation
├── sample_logs/
│ └── auth.log.sample
├── output/ # Generated alerts (ignored by git)
├── README.md
├── requirements.txt
└── .gitignore

⚙️ Setup
1️⃣ Clone the repo

git clone https://github.com/Rahul0624201/log-threat-detector.git

cd log-threat-detector

2️⃣ (Optional) Create virtual environment

python -m venv .venv
..venv\Scripts\activate (Windows)
source .venv/bin/activate (Mac/Linux)

3️⃣ Install dependencies

pip install -r requirements.txt

Note: This project uses only Python’s standard library, so no extra packages are required.

▶️ How to Run

python -m src.detector --log sample_logs/auth.log.sample --year 2025

📌 Example Output

Parsed events: 10
Alerts: 3
BRUTE_FORCE_IP: 1
SUCCESS_AFTER_FAILURES: 1
OFF_HOURS_LOGIN: 1
Saved: output/alerts.json
Saved: output/alerts.csv

Reports will be generated in:
output/alerts.json
output/alerts.csv

🧪 Detection Rules

BRUTE_FORCE_IP – Many failed logins from one IP in short time (HIGH)
PASSWORD_SPRAY – One IP failing across many usernames (HIGH)
SUCCESS_AFTER_FAILURES – Login success after multiple failures (MEDIUM)
OFF_HOURS_LOGIN – Successful login outside business hours (LOW)

All thresholds are configurable via CLI arguments.

🔧 CLI Options

python -m src.detector --help

Key options include:
--bf-window → brute-force time window (minutes)
--bf-threshold → failed attempts before alert
--spray-users → distinct users for spray detection
--work-start / --work-end → business hours

🛡️ Why This Matters

- This project demonstrates:

- Log analysis and parsing

- Threat detection logic

- Blue-team defensive thinking

- SOC-style alert generation

- Python automation for security monitoring

- It mirrors real-world workflows used by SOC analysts and security engineers.

📈 Future Improvements

- Windows Event Log (4624/4625) support

- GeoIP / ASN enrichment for IPs

- Whitelist / allowlist handling

- MITRE ATT&CK mapping for alerts

- Simple web dashboard

- Unit tests with pytest

🧾 Sample Resume Bullet

Built a Python-based log analyzer and threat detection tool to identify brute-force attacks, password spraying, and anomalous authentication behavior from Linux auth logs, generating structured SOC-style alerts in JSON and CSV format.

⚠️ Disclaimer

This tool is for educational and defensive purposes only.
Do not use against systems you do not own or have permission to test.

👤 Author

Rahul Rajkumar
Computer Science Graduate | Cybersecurity Enthusiast
GitHub: https://github.com/Rahul0624201

⭐ If you find this project useful, feel free to star the repo!
