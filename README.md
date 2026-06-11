# Mini-SIEM-v1

A lightweight Security Information and Event Management (SIEM) system built in Python that ingests authentication logs, detects suspicious activity, enriches indicators with threat intelligence, correlates multiple attack signals, and generates actionable security alerts.

🚀 Features
- **Log ingestion and parsing of Linux authentication logs**
- **Detection of brute-force login attacks**
- **Suspicious IP activity and frequency-based anomaly detection**
- **Threat intelligence enrichment using AbuseIPDB**
- **Event correlation to identify high-confidence threats**
- **Automated threat scoring and severity classification**
- **JSON alert export for machine-readable analysis**
- **Human-readable incident reports for investigations**
- **Configurable detection thresholds and severity levels**

# 🛠️ Technologies Used
- **Python**
- **Regular Expressions (re)**
- **Log Analysis**
- **Security Event Crrelation**
- **email module (for .eml parsing)**
- **REST APIs (VirusTotal)**

⚙️ How It Works
- **Accepts Linux authentication logs as input**
- **Parses security events including failed logins, successful logins, and invalid user attempts**
- **Detects brute-force attacks based on repeated authentication failures**
- **Identifies suspicious IP activity using frequency and spike analysis**
- **Correlates multiple detection signals to increase alert confidence**
- **Queries AbuseIPDB for threat intelligence enrichment**
- **Calculates threat scores and assigns severity levels**
- **Generates structured security alerts and investigation reports**

🔑 Configuration
- Add your VirusTotal API key in: **config.py**
- Place authentication logs inside: logs/sample.log

▶️ How to Run

🔹 Basic run against sample log

```bash
python main.py --file logs/sample.log
```
🔹Skip enrichment (offline mode)
```bash
python main.py --file logs/sample.log --no-enrich
```
🔹Custom output paths
```bash
python main.py --file logs/auth.log --output-json /tmp/alerts.json --output-report /tmp/report.txt
```

 Generated outputs can be found in:
- **output/alerts.json**
- **output/report.txt**

📊 Example Output



<img width="461" height="305" alt="image" src="https://github.com/user-attachments/assets/189260cf-f97b-49af-af46-30bef2dd739c" />
<img width="1054" height="613" alt="image" src="https://github.com/user-attachments/assets/14901f4c-2bca-4b1f-bc8f-f04270b45a03" />
<img width="496" height="302" alt="image" src="https://github.com/user-attachments/assets/494af6c4-4cc7-491f-9aa5-3f6e59bcd144" />


