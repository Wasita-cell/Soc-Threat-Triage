#!/usr/bin/env python3
"""
URL Threat Intelligence & Reputation Scanner
Queries VirusTotal API v3 and evaluates URL structural heuristics.
"""
from __future__ import annotations

import os
import re
import json
import base64
import requests
from urllib.parse import urlparse
from typing import Any
from dotenv import load_dotenv

load_dotenv()
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def defang_url(url: str) -> str:
    """Neutralize potentially dangerous URLs to prevent accidental clicks in SOC tickets."""
    clean_url = re.sub(r"^https?", lambda m: "hxxps" if m.group() == "https" else "hxxp", url)
    return clean_url.replace(".", "[.]")


def check_url_heuristics(url: str) -> list[str]:
    """Inspect URL structural components for common phishing indicators."""
    flags = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Check for raw IP address usage instead of domain name
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if re.match(ip_pattern, hostname):
        flags.append("Direct IP address used as host (Suspicious)")

    # Check for non-standard web ports
    if parsed.port and parsed.port not in [80, 443, 8080]:
        flags.append(f"Non-standard web port detected: {parsed.port}")

    # Excessive subdomain nesting common in phishing campaigns
    if hostname.count(".") >= 4:
        flags.append("High subdomain depth (Possible phishing kit structure)")

    return flags


def scan_url_virustotal(target_url: str) -> dict[str, Any]:
    """Query VirusTotal API v3 using base64-encoded URL identifier with false-positive suppression."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "Missing VIRUSTOTAL_API_KEY in environment"}

    # Encode URL identifier according to VirusTotal v3 specifications (base64url without padding)
    url_id = base64.urlsafe_b64encode(target_url.strip().encode()).decode().strip("=")
    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    heuristics = check_url_heuristics(target_url)

    try:
        response = requests.get(api_endpoint, headers=headers, timeout=12)

        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            # Correlation logic with false-positive suppression
            if malicious >= 3:
                verdict = "MALICIOUS"
                severity = "CRITICAL"
            elif (malicious >= 2) or (malicious == 1 and harmless < 10) or suspicious >= 2 or len(heuristics) > 0:
                verdict = "SUSPICIOUS"
                severity = "MEDIUM"
            else:
                verdict = "BENIGN"
                severity = "LOW"

            return {
                "original_url": target_url,
                "defanged_url": defang_url(target_url),
                "verdict": verdict,
                "severity": severity,
                "stats": stats,
                "heuristics": heuristics,
                "categories": data.get("categories", {}),
                "status": "Analysis completed"
            }

        elif response.status_code == 404:
            return {
                "original_url": target_url,
                "defanged_url": defang_url(target_url),
                "verdict": "UNRATED",
                "severity": "INFO",
                "heuristics": heuristics,
                "status": "URL not found in VirusTotal cache (Pending manual submission)"
            }
        elif response.status_code == 429:
            return {"error": "VirusTotal API rate limit exceeded (max 4 req/min)."}
        else:
            return {"error": f"VirusTotal API HTTP {response.status_code}"}

    except Exception as exc:
        return {"error": f"Connection error: {str(exc)}"}


if __name__ == "__main__":
    import sys
    test_url = sys.argv[1] if len(sys.argv) > 1 else "https://google.com"
    result = scan_url_virustotal(test_url)
    print(json.dumps(result, indent=2, ensure_ascii=False))