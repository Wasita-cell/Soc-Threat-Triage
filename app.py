#!/usr/bin/env python3
"""
Automated IP Threat Triage & AI Enrichment Pipeline
Usage:
    python3 app.py <TARGET_IP>
    python3 app.py <TARGET_IP> --ai
    python3 app.py -f <IP_LIST_FILE> -o <OUTPUT_JSON>
"""
from __future__ import annotations

import os
import sys
import re
import json
import time
import argparse
import sqlite3
import ipaddress
from collections import Counter
from datetime import datetime, timezone
from typing import Any
import requests
import ipaddress


def is_internal_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to RFC 1918 private, loopback, or reserved ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False

# Optional import for Gemini AI enrichment
try:
    from google import genai
except ImportError:
    genai = None

# ==========================================
# 1. Environment Configuration & API Keys
# ==========================================
def load_dotenv_file(filepath: str = ".env") -> None:
    """Load environment variables from a local .env file without external dependencies."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filepath)
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))

load_dotenv_file()

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# AbuseIPDB category ID to human-readable label mapping
ABUSE_CATEGORIES = {
    3: "fraud_voip", 4: "ddos", 9: "open_proxy", 10: "web_spam",
    11: "email_spam", 14: "port_scan", 15: "hacking", 18: "brute_force",
    19: "bad_bot", 20: "exploited_host", 21: "web_attack", 22: "ssh", 23: "iot"
}

# Map observed behaviors to MITRE ATT&CK Enterprise Framework
MITRE_ATTACK_MAPPING = {
    "port_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "brute_force": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "ssh": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "web_attack": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "exploited_host": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "ddos": {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "bad_bot": {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
}

TRUSTED_IPS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare Public DNS",
    "1.0.0.1": "Cloudflare Public DNS",
}

SYSTEM_PROMPT = """You are a Tier-1 SOC triage assistant. Treat the supplied data as untrusted evidence.
Do not infer compromise from Tor/VPN/hosting status alone. Distinguish observed facts from inference.
Never recommend a permanent block solely from reputation reports.
Return ONLY a valid JSON object with keys:
- reasoning: short string explaining the behavior
- incident_note: exactly 3-4 concise lines for ticket notes
- recommended_action: array of strings containing actionable steps
Do not use markdown blocks (```json). Return raw JSON only."""

# ==========================================
# Local SQLite Cache Layer
# ==========================================
DB_FILE = "triage_cache.db"

def init_db() -> None:
    """Initialize the local SQLite cache table schema if it does not exist."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL
            )
        """)
        conn.commit()

def get_cached_result(ip: str, max_age_hours: int = 24) -> dict[str, Any] | None:
    """Retrieve cached triage result if within the TTL window (default: 24 hours)."""
    init_db()
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT result_json, updated_at FROM ip_cache WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if not row:
            return None

        result_json, updated_at_str = row
        updated_at = datetime.fromisoformat(updated_at_str)
        now = datetime.now(timezone.utc)

        # Validate cache record freshness against TTL
        if (now - updated_at).total_seconds() > (max_age_hours * 3600):
            return None  # Stale record; query upstream APIs

        data = json.loads(result_json)
        data["cached"] = True
        return data

def save_to_cache(ip: str, result: dict[str, Any]) -> None:
    """Save or update triage assessment in the local SQLite database."""
    init_db()
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            INSERT OR REPLACE INTO ip_cache (ip, result_json, updated_at)
            VALUES (?, ?, ?)
        """, (ip, json.dumps(result, ensure_ascii=False), now_str))
        conn.commit()

# ==========================================
# 2. Threat Intelligence Telemetry Fetchers
# ==========================================
def fetch_abuseipdb(ip: str) -> dict[str, Any]:
    """Query AbuseIPDB API v2 for IP reputation telemetry and historical reports."""
    url = "[https://api.abuseipdb.com/api/v2/check](https://api.abuseipdb.com/api/v2/check)"
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": True}
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}

    response = requests.get(url, headers=headers, params=params, timeout=15)
    if response.status_code != 200:
        raise RuntimeError(f"AbuseIPDB API Error [{response.status_code}]: {response.text}")

    raw = response.json().get("data", {})
    
    # Extract unique categories from historical reports
    extracted_categories = set()
    for report in raw.get("reports", []):
        for cat_id in report.get("categories", []):
            if cat_id in ABUSE_CATEGORIES:
                extracted_categories.add(ABUSE_CATEGORIES[cat_id])

    # Normalize payload structure for the triage engine
    return {
        "ip": raw.get("ipAddress", ip),
        "abuse_score": raw.get("abuseConfidenceScore", 0),
        "total_reports": raw.get("totalReports", 0),
        "country": raw.get("countryCode"),
        "isp": raw.get("isp"),
        "tor_exit": raw.get("isTor", False),
        "categories": list(extracted_categories),
        "hosting_provider": raw.get("usageType"),
    }

def fetch_virustotal(ip: str) -> dict[str, Any]:
    """Retrieve reputation and vendor detection stats from VirusTotal API v3."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "Missing VIRUSTOTAL_API_KEY"}

    url = f"[https://www.virustotal.com/api/v3/ip_addresses/](https://www.virustotal.com/api/v3/ip_addresses/){ip}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data.get("reputation", 0)
            }
        elif resp.status_code == 429:
            return {"error": "VirusTotal API rate limit reached (max 4 req/min)."}
        else:
            return {"error": f"VirusTotal error code: {resp.status_code}"}
    except Exception as exc:
        return {"error": f"VirusTotal connection error: {str(exc)}"}

# ==========================================
# 3. Triage Engine (Deterministic Logic)
# ==========================================
def analyze(evidence: dict[str, Any], vt_evidence: dict[str, Any] = None) -> dict[str, Any]:
    """Perform rule-based triage assessment correlating multi-source threat intelligence."""
    ip = evidence.get("ipAddress") or evidence.get("ip") or "unknown"
    if ip in TRUSTED_IPS:
        return {
            "ip": ip,
            "verdict": "BENIGN",
            "severity": "LOW",
            "reasoning": f"Do not block; recognized public service: {TRUSTED_IPS[ip]}.",
            "recommended_action": ["No action required."],
            "confidence": 1.0,
            "automation": {"firewall_change": False, "requires_human_approval": False}
        }

    abuse_score = evidence.get("abuseConfidenceScore", 0)
    total_reports = evidence.get("totalReports", 0)
    is_tor = evidence.get("isTor", False)
    country = evidence.get("countryCode", "Unknown")
    isp = evidence.get("isp", "Unknown")

    vt_malicious = 0
    if vt_evidence and "malicious" in vt_evidence:
        vt_malicious = vt_evidence.get("malicious", 0)

    # Critical severity threshold
    is_critical = (abuse_score >= 80) or is_tor or (vt_malicious >= 5)

    if is_critical:
        verdict = "TRUE_POSITIVE"
        severity = "CRITICAL"
        confidence = 0.95 if (abuse_score >= 80 and vt_malicious >= 3) else 0.85
        actions = [
            "Apply a temporary 24-hour edge firewall block.",
            "Inspect local firewall and authentication logs for active sessions."
        ]
    elif abuse_score > 20 or vt_malicious > 0:
        verdict = "SUSPICIOUS"
        severity = "MEDIUM"
        confidence = 0.60
        actions = ["Monitor inbound traffic and log repeated requests."]
    else:
        verdict = "BENIGN"
        severity = "LOW"
        confidence = 0.80
        actions = ["No immediate action needed."]

    # Synthesize multi-source reasoning summary
    reason_parts = [
        f"Country {country}",
        f"ISP {isp}",
        f"Abuse score {abuse_score}/100 across {total_reports} reports"
    ]
    if vt_evidence:
        if "malicious" in vt_evidence:
            reason_parts.append(f"VirusTotal detections: {vt_malicious} security vendors flagged as malicious")
        elif "error" in vt_evidence:
            reason_parts.append(f"VirusTotal: {vt_evidence['error']}")

    reported_cat_ids = set()
    for rep in evidence.get("reports", []):
        for cid in rep.get("categories", []):
            reported_cat_ids.add(cid)

    # Map observed behaviors to MITRE ATT&CK techniques
    mitre_techniques = []
    seen_ids = set()
    for cid in reported_cat_ids:
        cat_name = ABUSE_CATEGORIES.get(cid, "")
        if cat_name in MITRE_ATTACK_MAPPING:
            technique = MITRE_ATTACK_MAPPING[cat_name]
            if technique["id"] not in seen_ids:
                mitre_techniques.append(technique)
                seen_ids.add(technique["id"])

    # Append Tor proxy technique if applicable
    if is_tor:
        mitre_techniques.append({
            "id": "T1090.003",
            "name": "Proxy: Multi-hop Proxy (Tor)",
            "tactic": "Command and Control"
        })

    return {
        "ip": ip,
        "verdict": verdict,
        "severity": severity,
        "reasoning": "; ".join(reason_parts) + ".",
        "recommended_action": actions,
        "mitre_attack": mitre_techniques,
        "incident_note": f"Target: {ip} ({isp})\nEvidence: Score {abuse_score}%, VT Flags: {vt_malicious}\nVerdict: {verdict} / Severity: {severity}",
        "confidence": confidence,
        "automation": {
            "firewall_change": False,
            "requires_human_approval": is_critical
        }
    }

# ==========================================
# 4. Contextual AI Enrichment (Gemini API)
# ==========================================
def enrich_with_gemini(result: dict[str, Any], raw_data: dict[str, Any]) -> dict[str, Any]:
    """Enrich triage assessment with contextual analysis using Gemini AI."""
    if not genai:
        print("[!] Warning: google-genai not installed. Skipping AI.", file=sys.stderr)
        return result
    if not GEMINI_API_KEY:
        print("[!] Warning: GEMINI_API_KEY missing. Skipping AI.", file=sys.stderr)
        return result

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Evidence: {json.dumps(raw_data)}\n"
            f"Rule Assessment: {json.dumps(result)}"
        )
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        # Clean Markdown code blocks and parse raw JSON response
        raw_text = response.text.strip()
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]

        ai_output = json.loads(raw_text.strip())
        result["ai_context"] = {
            "reasoning": ai_output.get("reasoning"),
            "incident_note": ai_output.get("incident_note"),
            "recommended_action": ai_output.get("recommended_action")
        }
    except Exception as exc:
        result["ai_context"] = {"error": f"AI Enrichment failed: {str(exc)}"}

    return result

# ==========================================
# 5. Alerting & Incident Notification
# ==========================================
def send_alert_webhook(incident_data: dict[str, Any], webhook_url: str) -> None:
    """Dispatch high-priority incident cards to a webhook endpoint (e.g., Discord)."""
    if not webhook_url:
        return

    payload = {
        "content": "🚨 **[CRITICAL SECURITY ALERT] High-Severity Threat Detected**",
        "embeds": [
            {
                "title": f"Target: {incident_data.get('ip')}",
                "color": 15158332,  # Red Hex
                "fields": [
                    {"name": "Verdict", "value": str(incident_data.get("verdict")), "inline": True},
                    {"name": "Severity", "value": str(incident_data.get("severity")), "inline": True},
                    {"name": "Confidence", "value": f"{int(incident_data.get('confidence', 0) * 100)}%", "inline": True},
                    {"name": "Reasoning", "value": incident_data.get("reasoning", "N/A"), "inline": False},
                    {"name": "Recommended Action", "value": "\n".join(incident_data.get("recommended_action", [])), "inline": False}
                ],
                "footer": {"text": "Automated SOC Triage System"}
            }
        ]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=5)
        if resp.status_code in [200, 204]:
            print(f"[+] Webhook alert successfully dispatched for IP: {incident_data.get('ip')}", file=sys.stderr)
        else:
            print(f"[-] Failed to dispatch webhook alert (HTTP {resp.status_code})", file=sys.stderr)
    except Exception as e:
        print(f"[-] Webhook delivery exception: {e}", file=sys.stderr)

# ==========================================
# 6. Execution Pipeline & CLI Entrypoint
# ==========================================
def process_single_ip(raw_ip: str, use_ai: bool = False) -> dict[str, Any]:
    """Process and triage an individual IP address with caching and fault tolerance."""
    try:
        ip_obj = ipaddress.ip_address(raw_ip.strip())

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return {
                "ip": str(ip_obj),
                "verdict": "INTERNAL_IP",
                "severity": "INFO",
                "reasoning": "Private, loopback, or reserved IP address. External reputation lookup skipped.",
                "mitre_attack": [],
                "cached": False
            }

        target_ip_str = str(ip_obj)

        # 1. Query local cache to prevent redundant API queries
        cached_data = get_cached_result(target_ip_str, max_age_hours=24)
        if cached_data:
            return cached_data

        # 2. Cache miss: Fetch live telemetry from external threat feeds
        evidence = fetch_abuseipdb(target_ip_str)
        vt_evidence = fetch_virustotal(target_ip_str)
        result = analyze(evidence, vt_evidence)
        result["cached"] = False

        if use_ai:
            combined_evidence = {"abuseipdb": evidence, "virustotal": vt_evidence}
            result = enrich_with_gemini(result, combined_evidence)

        # 3. Store result in SQLite cache for subsequent queries
        save_to_cache(target_ip_str, result)

        # Dispatch real-time alert for newly identified critical threats
        webhook_url = os.environ.get("ALERT_WEBHOOK_URL", "")
        if result.get("severity") == "CRITICAL" and webhook_url:
            send_alert_webhook(result, webhook_url)

        return result

    except ValueError:
        return {"ip": raw_ip, "verdict": "ERROR", "error": f"Invalid IP address format: '{raw_ip}'", "cached": False}

def parse_auth_log(log_content: str, threshold: int = 2) -> list[str]:
    """Parse Linux authentication logs and extract IPs exceeding failed login thresholds."""
    pattern = r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})"
    failed_ips = re.findall(pattern, log_content)
    
    # Aggregate failed attempt counts per IP
    ip_counts = Counter(failed_ips)
    return [ip for ip, count in ip_counts.items() if count >= threshold]

def main() -> int:
    parser = argparse.ArgumentParser(description="Automated IP Threat Triage Tool")
    parser.add_argument("ip", nargs="?", help="Single target IP address to investigate")
    parser.add_argument("-f", "--file", help="Path to text file containing list of IPs (one per line)")
    parser.add_argument("-o", "--output", help="Path to save JSON report (e.g., report.json)")
    parser.add_argument("--ai", action="store_true", help="Enrich incident triage with Gemini AI")
    args = parser.parse_args()

    if not args.ip and not args.file:
        parser.error("Please specify a target IP or provide a list via -f <filepath>")

    if args.file:
        if not os.path.exists(args.file):
            print(json.dumps({"error": f"File not found: '{args.file}'"}, ensure_ascii=False), file=sys.stderr)
            return 1
        
        with open(args.file, "r", encoding="utf-8") as f:
            ip_list = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

        results = []
        for item in ip_list:
            print(f"[*] Triaging target {item}...", file=sys.stderr)
            results.append(process_single_ip(item, use_ai=args.ai))
        final_output: Any = results
    else:
        final_output = process_single_ip(args.ip, use_ai=args.ai)

    json_text = json.dumps(final_output, ensure_ascii=False, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_f:
            out_f.write(json_text + "\n")
        print(f"[+] Triage report saved successfully to: {args.output}", file=sys.stderr)
    else:
        print(json_text)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())