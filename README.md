# 🛡️ SOC Analyst Investigation & Threat Triage Toolkit

![SOC Toolkit CI Pipeline](https://github.com/Wasita-cell/Soc-Threat-Triage/actions/workflows/ci.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.10-blue.svg)
![Docker Ready](https://img.shields.io/badge/docker-containerized-2496ED.svg?logo=docker&logoColor=white)
![Test Suite](https://img.shields.io/badge/tests-pytest-green.svg)

An automated, modular Tier-1 SOC triage, incident response, and threat enrichment pipeline built in Python and Streamlit. Designed to accelerate security operations, mitigate alert fatigue, and correlate multi-vector indicators across Network, Web, Phishing, Malware, and Smishing/Vishing artifacts.

---

## 📌 Executive Summary

Security Operations Centers (SOCs) face overwhelming alert volumes daily. Manual pivoting between threat intelligence feeds, email headers, raw authentication logs, file sandboxes, and telecom databases is repetitive, error-prone, and time-consuming.

This toolkit automates the end-to-end investigation and initial containment workflow for Tier-1 analysts:
1. **Network & System Logs:** Sanitizes internal RFC 1918 traffic, detects SSH brute-force attempts from Linux `auth.log`, queries cached threat intelligence, and maps attacks to the **MITRE ATT&CK** matrix.
2. **Suspicious URLs:** Evaluates structural heuristics (ports, direct IP hosting, subdomain depth), suppresses VirusTotal false positives, and neutralizes indicators via automated **IOC Defanging**.
3. **Phishing Artifacts (.eml):** Extracts technical authentication tags (**SPF/DKIM/DMARC**), flags sender mismatches, detects **Freemail brand impersonation** (e.g., banks mimicked via `@gmail.com`), and harvests embedded lures.
4. **File Hash & Malware Inspection:** Employs **Privacy-First triage** by calculating cryptographic hashes (MD5, SHA-1, SHA-256) locally and querying threat feeds without uploading proprietary file contents, while flagging deceptive naming conventions (double extensions, macro-enabled scripts).
5. **Phone & Smishing/Vishing Intelligence:** Validates international telephone numbers via E.164, detects high-risk anonymous VoIP virtual lines, and verifies **NZ Enterprise SMS Short Codes** against official Telecommunications Forum (TCF) registry records.
6. **Mini-SOAR Containment:** Generates ready-to-execute boundary firewall rules (Linux UFW, iptables), DNS sinkholes, Microsoft 365 Exchange tenant purges, EDR block policies, and PBX/SMS gateway drop rules.
7. **Incident Handover Ticketing:** Standardizes findings into structured Markdown incident tickets for rapid Tier-2 / Incident Response escalation.

---

## 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               MULTI-VECTOR INGESTION (DATA INPUT LAYER)                                 │
└───────┬───────────────────┬───────────────────────┬──────────────────────┬──────────────────────┬───────┘
        │                   │                       │                      │                      │
        ▼                   ▼                       ▼                      ▼                      ▼
 [ 1. Network Logs ] [ 2. Suspicious URL ]   [ 3. Raw Email (.eml) ] [ 4. File / Hash ]    [ 5. Phone / SMS ]
        │                   │                       │                      │                      │
        ▼                   ▼                       ▼                      ▼                      ▼
  Regex Log Parser   URL Heuristics          Email Parser (RFC 5322) Hash Calculation      TCF / E.164 Triage
(Brute Force >= 2)   (Port, IP Host, Depth)  ├── SPF/DKIM/DMARC      (MD5/SHA1/SHA256)     ├── NZ Short Codes
        │                   │                ├── Sender Spoofing           │               ├── VoIP Detection
        ▼                   │                ├── Brand Impersonation       ▼               └── Carrier Lookup
RFC 1918 Sanitizer          │                └── URL Harvesting     Heuristic Engine              │
(Internal Filter)           │                       │               (Double Ext, Macros)          │
        │                   ▼                       │                      │                      │
        ▼          Subdomain Deception              │                      │                      │
SQLite Cache (24h)          │                       │                      │                      │
 ├── Hit  -> DB             │                       │                      │                      │
 └── Miss -> APIs           ▼                       ▼                      ▼                      │
      (AbuseIPDB)     VirusTotal v3 API     VirusTotal Pipeline    VirusTotal File API            │
        │             (FP Suppression)      (Extracted Links)      (Privacy-First Hash)           │
        │                   │                       │                      │                      │
        ▼                   ▼                       ▼                      ▼                      ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                  UNIFIED TRIAGE & ENRICHMENT ENGINE                                    │
 ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ • Multi-Factor Severity Scoring (LOW / MEDIUM / CRITICAL)                                              │
 │ • MITRE ATT&CK Auto-Mapping (T1110, T1595, T1566, T1566.002, T1566.005, T1204, T1059, T1036)           │
 │ • Automated IOC Defanging (e.g., hxxps://evil[.]com)                                                   │
 │ • Optional LLM Context Enrichment (Gemini API)                                                         │
 └──────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                    │
        ┌───────────────────────────────────────────┼───────────────────────────────────────────┐
        ▼                                           ▼                                           ▼
[ Real-Time Alert ]                     [ Mini-SOAR Containment ]                     [ Analyst Workspace ]
  Discord Webhook                      Automated CLI Block Scripts                  Streamlit Dynamic UI
(CRITICAL Triggers)                ├── Firewall (UFW / iptables)                  ├── Sidebar Vector Nav
                                   ├── DNS Sinkhole (/etc/hosts)                  ├── Live Telemetry Metrics
                                   ├── M365 Email Purge (PowerShell)              └── Tier-2 Handover Tickets
                                   ├── EDR Hash Rules (WDAC / Defender)               (Markdown / File Export)
                                   └── PBX / SMS Drop Rules (Asterisk/SMPP)

⚡ Core Modules & Capabilities

       Module              Filename             Operational Focus                           Key Technical Features

    IP Intelligence         app.py               Network Log Triage                         Regex auth parser ( > 2 threshold),
                                                                                           RFC 1918 internal filtering, SQLite persistent caching (24h TTL),
                                                                                           AbuseIPDB API integration, Discord webhook dispatcher.

    URL Scanner             url_scanner.py       Web Reputation & Heuristics                VirusTotal v3 URL engine (base64url identifiers),  
                                                                                           False-Positive suppression ratio,
                                                                                           non-standard port & IP host detection, automated IOC defanging.

   Phishing Analyzer        email_parser.py      Email Header & Artifact Forensics         RFC 5322 BytesParser, SPF/DKIM/DMARC status evaluation,
                                                                                           Freemail brand impersonation detection, Subdomain deception analysis, embedded URL harvesting.

   File & Hash Inspector    file_inspector.py    Artifact & Malware Analysis               Local MD5/SHA-1/SHA-256 calculation,
                                                                                           Privacy-First VirusTotal hash lookup,
                                                                                           double extension detection (.pdf.exe), risky script/macro identification.

   Phone & Smishing         phone_scanner.py     Telecom & SMS Short Code Triage           Offline E.164 parsing via phonenumbers, VoIP virtual line detection, 
                                                                                           NZ TCF-registered banking/courier short code verification, PBX/SMS gateway containment.

   Containment Engine       containment.py       Automated Threat Response (SOAR)          Generates Linux UFW/iptables rules,
                                                                                           Windows Firewall commands,
                                                                                           DNS blackholes, M365 PowerShell tenant purge commands, and EDR hash block rules.
   
    Report Generator       report_generator.py   Documentation & Escalation                 Standardizes incident artifacts, confidence scores,  
                                                                                           technical reasoning, and containment checklists into uniform Markdown tickets for Tier-2 handover.

    Unified UI              dashboard.py         Security Operations Interface             Decluttered sidebar-driven Streamlit dashboard, reactive metric cards,
                                                                                           dynamic dataframe inspection, and instant ticket download buttons.
                                                                                           
### ⚡ Key Modules & Operational Logic

#### 1. 🌐 IP Threat Intelligence & Log Parser (`app.py`)
- **Regex Ingestion:** Ingests raw `/var/log/auth.log` files and extracts external IPs exceeding brute-force thresholds (`> 2` failed attempts).
- **RFC 1918 Sanitization:** Automatically classifies internal subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) as `BENIGN / INTERNAL` to prevent unnecessary external API calls.
- **Persistent SQLite Caching (`triage_cache.db`):** Caches API telemetry with a 24-hour Time-to-Live (TTL) to respect vendor rate limits and achieve near-zero latency on repeated lookups.
- **Incident Escalation:** Formats and dispatches critical alert payloads to Discord/Slack webhooks in real time.

#### 2. 🔗 URL Reputation & Heuristics Scanner (`url_scanner.py`)
- **VirusTotal API v3:** Encodes target URLs using Base64URL identifiers without padding.
- **False-Positive Suppression:** Evaluates vendor distribution ratios (e.g., a single unverified flag alongside `> 10` harmless confirmations is suppressed to `BENIGN`).
- **Structural Heuristics:** Detects raw IP hosts, non-standard web ports, and excessive subdomain nesting.
- **IOC Defanging:** Converts dangerous links into inert strings (e.g., `https://` ➔ `hxxps://`, `.` ➔ `[.]`).

#### 3. 📧 Phishing Email Artifact Parser (`email_parser.py`)
- **Authentication Triad:** Extracts and evaluates SPF, DKIM, and DMARC statuses from RFC 5322 headers.
- **Freemail Brand Impersonation:** Flags attacks utilizing free webmail domains (`@gmail.com`, `@yahoo.com`) that attempt to impersonate financial institutions or corporate support desks—identifying threats even when technical SPF/DKIM records pass.
- **Subdomain Deception Analysis:** Inspects embedded links to detect fraudulent apex domains mimicking reputable brands in their subdomains.
- **Automated Link Harvesting:** Extracts all links from plain text and HTML payloads for automated pipelining into reputation scanners.

#### 4. 📁 File Hash & Malware Inspector (`file_inspector.py`)
- **Privacy-First Hash Lookup:** Computes `MD5`, `SHA-1`, and `SHA-256` locally from raw file bytes and queries VirusTotal File API by hash only, preventing sensitive or proprietary enterprise data leakage.
- **Deceptive Pattern Heuristics:** Flags deceptive evasion techniques such as double extensions (e.g., `invoice.pdf.exe`), excessive whitespace padding, and macro-enabled Office payloads (`.docm`, `.xlsm`).
- **Zero-Day Heuristic Escalation:** Automatically elevates unindexed artifacts to `MEDIUM` severity if high-risk script or executable extensions are identified.

#### 5. 📱 Phone & Smishing/Vishing Triage (`phone_scanner.py`)
- **NZ Enterprise Short Code Verification:** Cross-references 3-to-5 digit short codes against registered New Zealand Telecommunications Forum (TCF) records (e.g., ANZ `4444`/`244`, ASB `2255`, NZ Post `898`, IRD `308`).
- **Line Type Classification:** Detects anonymized virtual numbers (VoIP), distinguishing high-risk vishing lines from standard cellular or landline connections.
- **Telecom Containment:** Formats dialplan block rules for PBX systems (Asterisk, Cisco CUCM) and SMPP SMS gateway blacklists.

#### 6. 🛑 Automated Containment Engine (`containment.py`)
- **Boundary Firewall Rules:** Generates drop rules for Linux `UFW`, `iptables`, Windows Defender Firewall, and Cisco ACLs.
- **DNS Sinkholing:** Produces host blackhole entries (`/etc/hosts`) and Pi-hole block commands to sever command-and-control (C2) callback attempts.
- **M365 Tenant Remediation:** Generates Microsoft 365 Exchange Online PowerShell scripts to block sender domains and execute compliance purges (Hard Delete) across all mailboxes.
- **EDR Policy Enforcement:** Outputs Windows Defender Application Control (WDAC) and Attack Surface Reduction rules for verified malicious file hashes.

#### 7. 📋 Incident Ticket & Handover Generator (`report_generator.py`)
- **Standardized Escalation:** Formats triage findings into structured tickets with automated tracking IDs (`INC-YYYYMMDD-XXXX`).
- **SOC Context Compilation:** Auto-compiles IOC evidence, analyst reasoning, confidence scores, MITRE ATT&CK tags, and containment commands into clean Markdown ready for immediate handover to Tier-2 / Incident Response teams.

## 🎯 MITRE ATT&CK Mapping

| Technique ID | Technique Name | Triage Trigger / Operational Condition |
| :--- | :--- | :--- |
| **T1110** | Brute Force | `> 2` failed authentication attempts in Linux `auth.log` |
| **T1595** | Active Scanning | Known external scanner IP with elevated AbuseIPDB report confidence |
| **T1566** | Phishing | Email artifact with failed SPF/DMARC or mismatched sender domains |
| **T1566.002** | Spearphishing Link | Subdomain deception lures or confirmed malicious URLs |
| **T1566.005** | Voice Phishing (Vishing / Smishing) | Inbound VoIP caller ID, unverified SMS short code, or malicious sender ID |
| **T1204.002** | Malicious File | Known malicious file hash or high-risk executable payload (`.exe`, `.bat`, `.scr`) |
| **T1059.005** | Visual Basic | Macro-enabled Office file extensions (`.docm`, `.xlsm`) identified in attachments |
| **T1036.007** | Double File Extension | Masqueraded filenames hiding executable formats (e.g., `invoice.pdf.exe`) |

📁 Repository Structure
        Soc-Threat-Triage/
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions automated test & lint pipeline
├── samples/                   # Benign demonstration artifacts for live triage
│   ├── auth.log               # Simulated Linux SSH brute-force log
│   ├── phishing_alert.eml     # Sample brand impersonation phishing artifact
│   └── test_iocs.json         # Reference IOC collection for testing
├── tests/
│   └── test_triage.py         # Offline pytest suite (RFC 1918, defanging, heuristics)
├── app.py                     # Core IP triage engine, log parser, caching & webhooks
├── dashboard.py               # Streamlit sidebar-driven unified analyst workspace
├── email_parser.py            # Phishing artifact analysis & impersonation heuristics
├── url_scanner.py             # VirusTotal reputation scanner & heuristic defanging
├── file_inspector.py          # Cryptographic hashing & privacy-first file inspection
├── phone_scanner.py           # Telecom parsing, NZ SMS short codes & VoIP detection
├── containment.py             # Automated CLI containment command generator
├── report_generator.py        # Standardized SOC incident ticket formatter (Markdown)
├── Dockerfile                 # Multi-stage lightweight production container spec
├── .dockerignore              # Cache and credential exclusions for Docker build
├── pytest.ini                 # Pytest test discovery & execution configuration
├── requirements.txt           # Python package dependencies
├── .gitignore                 # Exclusion list for credentials, databases, and logs
└── README.md                  # Technical architecture and analyst documentation

## 🚀 Installation & Deployment

### Method 1: Containerized Deployment via Docker (Recommended)

Run the entire application in an isolated container environment without configuring local Python runtimes:

```bash
# 1. Build the lightweight container image
docker build -t soc-toolkit .

# 2. Run container with environment credentials mapped
docker run -d -p 8501:8501 --name soc-dashboard --env-file .env soc-toolkit

Access the dashboard at http://localhost:8501.

Method 2: Local Python Virtual Environment

    Bash
       # 1. Clone repository and initialize virtual environment
git clone https://github.com/Wasita-cell/Soc-Threat-Triage.git
cd Soc-Threat-Triage
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Configure environment variables (.env)
cp .env.example .env  # or create .env directly

Fill in your credentials inside .env:
    Ini, TOML

       ABUSEIPDB_API_KEY=your_abuseipdb_key
       VIRUSTOTAL_API_KEY=your_virustotal_key
       GEMINI_API_KEY=your_gemini_key
       DISCORD_WEBHOOK_URL=your_discord_webhook_url

    Bash
       # 4. Run automated test suite (offline verification)
        pytest -v

       # 5. Launch dashboard
        streamlit run dashboard.py


Access the interactive dashboard in your browser at http://localhost:8501 (or http://localhost:8503).

🔒 Security & Privacy Notice
       - Data Privacy Assurance: File investigations calculate cryptographic hashes locally and query threat databases via hash only. No proprietary files or sensitive corporate data are transmitted to third-party APIs.      
       - Environment Isolation: All API credentials, local database files (triage_cache.db), and raw logs are excluded from version control via .gitignore.

```markdown
### Steps to Save and Push to GitHub

1. Paste the updated content into `README.md` in VS Code and press `Cmd + S` to save.
2. Open the **Terminal** tab and execute the following commands:

```bash
git add README.md
git commit -m "docs: finalize professional 5-vector SOC triage toolkit documentation"
git push origin main