# 🛡️ SOC Analyst Investigation & Threat Triage Toolkit

An automated, modular Tier-1 SOC triage and threat enrichment pipeline built in Python and Streamlit. Designed to accelerate security operations, mitigate alert fatigue, and correlate multi-vector indicators across Network, Web, and Phishing artifacts.

---

## 📌 Executive Summary

Security Operations Centers (SOCs) face overwhelming alert volumes daily. Manual pivoting between threat intelligence feeds, email headers, and raw authentication logs is repetitive and time-consuming. 

This toolkit automates the investigation workflow for Tier-1 analysts:
1. **Network & System Logs:** Sanitizes internal RFC 1918 traffic, detects SSH brute-force attempts from Linux `auth.log`, checks local cache, and maps threat indicators to the **MITRE ATT&CK** framework.
2. **Suspicious URLs:** Evaluates structural heuristics, suppresses VirusTotal false positives, and neutralizes indicators via automated **IOC Defanging**.
3. **Phishing Artifacts (.eml):** Extracts technical authentication tags (**SPF/DKIM/DMARC**), flags sender mismatches, detects **Freemail brand impersonation** (e.g., banks mimicked via `@gmail.com`), and identifies **Subdomain Deception**.

---

## 🏗️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│               MULTI-VECTOR INGESTION (DATA INPUT LAYER)                 │
└──────┬─────────────────────────┬───────────────────────────────┬───────┘
       │                         │                               │
       ▼                         ▼                               ▼
[ 1. Network & Linux Log ]  [ 2. Suspicious URL ]      [ 3. Raw Email (.eml) ]
       │                         │                               │
       ▼                         ▼                               ▼
Regex Log Parser            URL Structural Heuristics   Email Header & Body Parser
(Failed Brute Force >= 2)   (Port, Direct IP, Depth)    (RFC 5322 BytesParser)
       │                         │                               │
       ▼                         │                               ├──> Auth Check (SPF/DKIM/DMARC)
RFC 1918 Private IP Filter       │                               ├──> Sender Discrepancy Check
(Sanitize Internal Traffic)      │                               ├──> Freemail Impersonation Detection
       │                         │                               └──> Embedded URL Extraction
       ▼                         ▼                                       │
SQLite Caching (24h TTL)    Subdomain Deception Check                    │
 ├── Hit  ──> Instant DB         │                                       │
 └── Miss ──> Threat APIs        │                                       │
      (AbuseIPDB / VT)           │                                       │
       │                         ▼                                       ▼
       │                    VirusTotal v3 API            Pass Extracted Links to URL Pipeline
       │                    (FP Suppression Logic)                       │
       │                         │                                       │
       ▼                         ▼                                       ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                   UNIFIED TRIAGE & ENRICHMENT ENGINE                    │
 ├─────────────────────────────────────────────────────────────────────────┤
 │ • Multi-Factor Severity Scoring (LOW / MEDIUM / CRITICAL)               │
 │ • MITRE ATT&CK Mapping (T1110 Brute Force, T1595 Recon, T1566 Phishing) │
 │ • Automated IOC Defanging (e.g., hxxp://evil[.]com)                     │
 │ • Optional LLM Context Enrichment (Gemini API)                         │
 └───────────────────────────────────┬─────────────────────────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
    [ Real-Time Alert Escalation ]         [ Analyst Presentation Layer ]
         Discord Webhook                     Streamlit Interactive UI
     (Triggered on CRITICAL)             (3-Tab Workspace & CSV/JSON Export)

⚡ Key Modules & Operational Logic
1. 🌐 IP Threat Intelligence & Log Parser (app.py)
       - Regex Ingestion: Ingests raw /var/log/auth.log files and extracts external IPs exceeding brute-force thresholds ( > 2 failed attempts).
       - RFC 1918 Sanitization: Automatically classifies internal subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1) as BENIGN / INTERNAL to prevent unnecessary external API calls.
       - Persistent SQLite Caching (triage_cache.db): Caches API telemetry with a 24-hour Time-to-Live (TTL) to respect vendor rate limits and achieve near-zero latency on repeated lookups.
       - Incident Escalation: Formats and dispatches critical alert payloads to Discord/Slack webhooks in real time.
2. 🔗 URL Reputation & Heuristics Scanner (url_scanner.py)
       - VirusTotal API v3: Encodes target URLs using Base64URL identifiers without padding.
       - False-Positive Suppression: Evaluates vendor distribution ratios (e.g., a single unverified flag alongside > 10 harmless confirmations is suppressed to BENIGN).
       - Structural Heuristics: Detects raw IP hosts, non-standard web ports, and excessive subdomain nesting.
       - IOC Defanging: Converts dangerous links into inert strings (e.g., https:// -> hxxps://, . -> [.]).
3. 📧 Phishing Email Artifact Parser (email_parser.py)
       - Authentication Triad: Extracts and evaluates SPF, DKIM, and DMARC statuses from RFC 5322 headers.
       - Freemail Brand Impersonation: Flags attacks utilizing free webmail domains (@gmail.com, @yahoo.com) that attempt to impersonate financial institutions or corporate support desks—identifying threats even when technical SPF/DKIM records pass.
       - Subdomain Deception Analysis: Inspects embedded links to detect fraudulent apex domains mimicking reputable brands in their subdomains.
       - Automated Link Harvesting: Extracts all links from plain text and HTML payloads for automated pipelining into reputation scanners.

🎯 MITRE ATT&CK Mapping
       Technique ID	       Technique Name	       Triage Trigger / Condition
       
           T1110             Brute Force           > 2 failed authentication attempts in Linux auth logs
           T1595            Active Scanning        Known external scanner IP with elevated AbuseIPDB report confidence
           T1566               Phishing            Email artifact with failed SPF/DMARC or mismatched sender domains
           T1566.002       Spearphishing Link      Subdomain deception lures or confirmed malicious URLs

📁 Repository Structure
         ├── app.py                  # Core IP triage engine, log parser, caching & webhooks
         ├── dashboard.py            # Streamlit multi-tab unified SOC analyst interface
         ├── email_parser.py         # Phishing artifact analysis & impersonation heuristics
         ├── url_scanner.py          # VirusTotal reputation scanner & heuristic defanging
         ├── requirements.txt        # Python package dependencies
         ├── .gitignore              # Exclusion list for credentials, databases, and logs
         └── README.md               # Documentation and technical architecture

