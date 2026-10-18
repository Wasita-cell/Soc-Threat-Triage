#!/usr/bin/env python3
"""
Phishing Email (.eml) Artifact & Header Parser
Features:
- Authentication results extraction (SPF, DKIM, DMARC)
- Freemail & Brand Impersonation detection (e.g., Bank/Support lures using @gmail.com)
- Subdomain deception and phishing URL harvesting
"""
from __future__ import annotations

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Any
from urllib.parse import urlparse

from url_scanner import scan_url_virustotal, defang_url

# Common free webmail domains exploited for impersonation
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
    "live.com", "icloud.com", "proton.me", "protonmail.com"
}

# High-value targets and authoritative brand keywords commonly abused
TARGETED_ENTITIES = {
    "bank", "anz", "asb", "westpac", "kiwibank", "paypal", "apple", 
    "microsoft", "netflix", "security", "support", "billing", "fraud", 
    "verification", "helpdesk", "account alert"
}

URGENCY_KEYWORDS = [
    r"\burgent\b", r"\bsuspend(ed)?\b", r"\bexpire\b", r"\bimmediate(ly)?\b", 
    r"\bverify your account\b", r"\b24 hours?\b", r"\bunauthorized\b", r"\baction required\b"
]


def parse_authentication_results(auth_header: str) -> dict[str, str]:
    """Extract SPF, DKIM, and DMARC verdicts from Authentication-Results header."""
    auth_summary = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not auth_header:
        return auth_summary

    header_lower = auth_header.lower()
    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none)", header_lower)
    if spf_match:
        auth_summary["spf"] = spf_match.group(1)

    dkim_match = re.search(r"dkim=(pass|fail|neutral|none)", header_lower)
    if dkim_match:
        auth_summary["dkim"] = dkim_match.group(1)

    dmarc_match = re.search(r"dmarc=(pass|fail|none)", header_lower)
    if dmarc_match:
        auth_summary["dmarc"] = dmarc_match.group(1)

    return auth_summary


def detect_impersonation_heuristics(sender_raw: str, subject: str, body_text: str) -> list[str]:
    """Flag brand impersonation attempts where attackers use freemail or urgency lures."""
    alerts = []
    sender_raw_lower = sender_raw.lower()
    subject_lower = subject.lower()
    body_lower = body_text.lower()

    # Extract email domain
    sender_emails = re.findall(r"[\w\.-]+@([\w\.-]+)", sender_raw_lower)
    sender_domain = sender_emails[0] if sender_emails else ""

    # Check for freemail impersonating high-trust entities
    if sender_domain in FREEMAIL_DOMAINS:
        matched_brands = [brand for brand in TARGETED_ENTITIES if brand in sender_raw_lower or brand in subject_lower]
        if matched_brands:
            alerts.append(
                f"High-Risk Impersonation: Freemail address (@{sender_domain}) used with authoritative brand keywords: {', '.join(matched_brands)}"
            )

    # Check for social engineering urgency patterns
    matched_urgency = [kw for kw in URGENCY_KEYWORDS if re.search(kw, subject_lower) or re.search(kw, body_lower)]
    if matched_urgency:
        alerts.append("Social Engineering Lure: Urgent or coercive language detected in subject or email body")

    return alerts


def check_subdomain_deception(url: str) -> list[str]:
    """Detect phishing URLs designed to mimic authentic brands via subdomains."""
    warnings = []
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    for brand in ["anz", "asb", "westpac", "paypal", "apple", "google", "microsoft"]:
        # If brand appears in subdomains but root domain belongs elsewhere
        if brand in hostname:
            parts = hostname.split(".")
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            if brand not in root_domain:
                warnings.append(f"Subdomain Deception: Brand '{brand}' found in subdomain, actual destination is '{root_domain}'")

    return warnings


def extract_urls_from_body(body_text: str) -> list[str]:
    """Extract and deduplicate all HTTP/HTTPS links found within body text."""
    url_pattern = r'https?://[^\s<>"\')]+'
    found_urls = re.findall(url_pattern, body_text)
    cleaned_urls = []
    seen = set()
    for u in found_urls:
        cleaned = u.rstrip(".,;:")
        if cleaned not in seen:
            seen.add(cleaned)
            cleaned_urls.append(cleaned)
    return cleaned_urls


def inspect_email_file(eml_path: str, scan_links: bool = False) -> dict[str, Any]:
    """Parse raw .eml file and perform multi-vector phishing triage."""
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg.get("Subject", "(No Subject)")
    sender = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    auth_header = msg.get("Authentication-Results", "")

    # Extract body content
    body_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition"))
            if ctype in ["text/plain", "text/html"] and "attachment" not in cdispo:
                body_content += part.get_payload(decode=True).decode(errors="replace") + "\n"
    else:
        body_content = msg.get_payload(decode=True).decode(errors="replace")

    # 1. Technical Authentication
    auth_verdict = parse_authentication_results(auth_header)

    # 2. Sender Domain Discrepancies
    sender_flags = []
    sender_emails = re.findall(r"[\w\.-]+@([\w\.-]+)", sender.lower())
    return_emails = re.findall(r"[\w\.-]+@([\w\.-]+)", return_path.lower())
    if sender_emails and return_emails and sender_emails[0] != return_emails[0]:
        sender_flags.append(f"Header Mismatch: Sender '@{sender_emails[0]}' differs from Return-Path '@{return_emails[0]}'")

    # 3. Impersonation & Social Engineering Heuristics
    impersonation_alerts = detect_impersonation_heuristics(sender, subject, body_content)

    # 4. URL Harvesting & Subdomain Checks
    extracted_urls = extract_urls_from_body(body_content)
    url_deception_flags = []
    for u in extracted_urls:
        url_deception_flags.extend(check_subdomain_deception(u))

    # 5. Optional Threat Intelligence Lookup
    url_scan_results = []
    if scan_links and extracted_urls:
        for target_link in extracted_urls[:3]:
            url_scan_results.append(scan_url_virustotal(target_link))

    # Determine Severity and Verdict
    has_malicious_link = any(r.get("verdict") == "MALICIOUS" for r in url_scan_results)
    is_spoofed_auth = (auth_verdict["spf"] == "fail") or (auth_verdict["dmarc"] == "fail")
    has_brand_impersonation = len(impersonation_alerts) > 0 or len(url_deception_flags) > 0

    if has_malicious_link or (has_brand_impersonation and is_spoofed_auth):
        verdict = "SUSPICIOUS_PHISHING"
        severity = "CRITICAL"
    elif has_brand_impersonation:
        verdict = "SUSPICIOUS_IMPERSONATION"
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
        "impersonation_alerts": impersonation_alerts,
        "url_deception_flags": url_deception_flags,
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