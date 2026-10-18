# 🛡️ Automated IP Threat Triage & Incident Monitoring Dashboard

An automated security operations triage tool built with Python and Streamlit. It accelerates Level-1 SOC workflows by aggregating real-time threat intelligence, mitigating API rate limits with local caching, parsing server authentication logs, and mapping detected threats to the MITRE ATT&CK framework.

---

## 🚀 Key Features

* **Multi-Source Threat Intelligence:** Correlates real-time threat scores and passive DNS data from AbuseIPDB and VirusTotal with Gemini AI contextual enrichment.
* **Resilient Rate Limiting & Caching:** Uses a local SQLite cache (`triage_cache.db`) with a 24-hour TTL to bypass strict API quotas (VirusTotal free tier 4 req/min) and eliminate redundant network queries.
* **Automated Log Parsing:** Built-in Regex parser extracts failed authentication attempts from Linux `auth.log` files and filters brute-force sources based on customizable threshold limits.
* **MITRE ATT&CK Mapping:** Automatically maps detected authentication anomalies directly to standard tactics and techniques, specifically **T1110 (Brute Force)**.
* **Alert Deduplication & Webhooks:** Sends real-time incident cards to Discord via Webhooks exclusively for newly discovered `CRITICAL` threats, preventing alert fatigue.
* **Deliverable Exports:** Generates one-click incident reports in both CSV (for spreadsheet review) and raw JSON formats.

---

## 🏗️ Architecture & Triage Workflow

```text
[Raw Input / auth.log] 
          │
          ▼
   Regex Log Parser ──> [Threshold Filtering (>= 2 Attempts)]
          │
          ▼
   Internal / Private IP Sanitization (RFC 1918)
          │
          ▼
   SQLite Local Cache Check (24-Hour Expiry)
     ├── Hit  ──> Instant Result (⚡ Cached)
     └── Miss ──> Live APIs (AbuseIPDB + VirusTotal Backoff) ──> Store in Cache
          │
          ▼
   Triage Engine (Scoring & Severity Classification)
          │
          ├── Critical Severity ──> Trigger Discord Webhook Alert
          └── MITRE Mapping     ──> Inject T1110 / T1595 Tags
          │
          ▼
Streamlit Interactive Dashboard (Metrics, Dataframe, CSV/JSON Export)