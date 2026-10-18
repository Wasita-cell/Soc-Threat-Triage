#!/usr/bin/env python3
"""
Phishing Email (.eml) Artifact & Header Parser
Extracts authentication telemetry, detects sender mismatches, and harvests embedded URLs.
"""
from __future__ import annotations

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Any
from urllib.parse import urlparse

from url_scanner import scan_url_virustotal, defang_url


def parse_authentication_results(auth_header: str) -> dict[str, str]:
    """Extract SPF, DKIM, and DMARC verdicts from Authentication-Results header."""
    auth_summary = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not auth_header:
        return auth_summary

    header_lower = auth_header.lower()

    # Match SPF verdict
    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none)", header_lower)
    if spf_match:
        auth_summary["spf"] = spf_match.group(1)

    # Match DKIM verdict
    dkim_match = re.search(r"dkim=(pass|fail|neutral|none)", header_lower)
    if dkim_match:
        auth_summary["dkim"] = dkim_match.group(1)

    # Match DMARC verdict
    dmarc_match = re.search(r"dmarc=(pass|fail|none)", header_lower)
    if dmarc_match:
        auth_summary["dmarc"] = dmarc_match.group(1)

    return auth_summary


def extract_urls_from_body(body_text: str) -> list[str]:
    """Extract all embedded HTTP/HTTPS URLs from raw email body content."""
    url_pattern = r'https?://[^\s<>"\')]+'
    found_urls = re.findall(url_pattern, body_text)

    # Deduplicate while preserving order and clean trailing punctuation
    cleaned_urls = []
    seen = set()
    for u in found_urls:
        cleaned = u.rstrip(".,;:")
        if cleaned not in seen:
            seen.add(cleaned)
            cleaned_urls.append(cleaned)
    return cleaned_urls


def inspect_email_file(eml_path: str, scan_links: bool = False) -> dict[str, Any]:
    """Parse raw .eml file and perform preliminary phishing triage."""
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg.get("Subject", "(No Subject)")
    sender = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    auth_header = msg.get("Authentication-Results", "")

    # Extract plain text or html payload
    body_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition"))
            if ctype in ["text/plain", "text/html"] and "attachment" not in cdispo:
                body_content += part.get_payload(decode=True).decode(errors="replace") + "\n"
    else:
        body_content = msg.get_payload(decode=True).decode(errors="replace")

    # 1. Evaluate Authentication Telemetry
    auth_verdict = parse_authentication_results(auth_header)

    # 2. Check for sender address discrepancy (Mismatched Sender)
    sender_flags = []
    sender_emails = re.findall(r"[\w\.-]+@[\w\.-]+", sender)
    return_emails = re.findall(r"[\w\.-]+@[\w\.-]+", return_path)

    if sender_emails and return_emails:
        sender_domain = sender_emails[0].split("@")[-1].lower()
        return_domain = return_emails[0].split("@")[-1].lower()
        if sender_domain != return_domain:
            sender_flags.append(f"Domain mismatch: Sender '@{sender_domain}' vs Return-Path '@{return_domain}'")

    # 3. Extract Embedded URLs
    extracted_urls = extract_urls_from_body(body_content)

    # 4. Optional: Scan extracted URLs via VirusTotal pipeline
    url_scan_results = []
    if scan_links and extracted_urls:
        for target_link in extracted_urls[:3]:  # Limit top 3 URLs to respect rate limits
            url_scan_results.append(scan_url_virustotal(target_link))

    # Determine Phishing Indicator Severity
    is_spoofed = (auth_verdict["spf"] == "fail") or (auth_verdict["dmarc"] == "fail")
    has_malicious_link = any(r.get("verdict") == "MALICIOUS" for r in url_scan_results)

    if is_spoofed or has_malicious_link:
        verdict = "SUSPICIOUS_PHISHING"
        severity = "CRITICAL"
    elif sender_flags or auth_verdict["spf"] == "softfail":
        verdict = "POTENTIAL_SPOOF"
        severity = "MEDIUM"
    else:
        verdict = "BENIGN"
        severity = "LOW"

    return {
        "subject": subject,
        "from": sender,
        "return_path": return_path,
        "reply_to": reply_to,
        "authentication": auth_verdict,
        "sender_flags": sender_flags,
        "extracted_urls": [defang_url(u) for u in extracted_urls],
        "raw_urls": extracted_urls,
        "url_scans": url_scan_results,
        "verdict": verdict,
        "severity": severity
    }


if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        res = inspect_email_file(sys.argv[1], scan_links=False)
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print("Usage: python3 email_parser.py <path_to_sample.eml>")