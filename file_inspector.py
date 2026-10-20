#!/usr/bin/env python3
"""
File Hash & Attachment Inspector
Calculates cryptographic hashes (MD5, SHA-1, SHA-256), detects risky extensions/double extensions,
and queries VirusTotal File API v3 with Privacy-First hash lookups.
"""
from __future__ import annotations

import os
import re
import json
import hashlib
import requests
from typing import Any
from dotenv import load_dotenv

load_dotenv()
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# High-risk extensions commonly leveraged by initial access payloads
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", 
    ".wsf", ".hta", ".cpl", ".iso", ".img", ".vhd", ".lnk", ".dll",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}


def calculate_hashes(data: bytes) -> dict[str, str]:
    """Compute MD5, SHA-1, and SHA-256 hashes from raw file bytes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


def check_file_heuristics(filename: str) -> list[str]:
    """Analyze filename for deceptive patterns, double extensions, and execution risks."""
    flags = []
    clean_name = filename.strip().lower()

    # Double extension detection (e.g., invoice.pdf.exe)
    parts = clean_name.split(".")
    if len(parts) > 2:
        flags.append(f"Double or multi-extension pattern detected: '{filename}'")

    # High-risk file type detection
    _, ext = os.path.splitext(clean_name)
    if ext in SUSPICIOUS_EXTENSIONS:
        flags.append(f"High-risk executable/script extension detected: '{ext}'")

    # Space padding trick to conceal extensions in Windows Explorer
    if re.search(r"\s{4,}\.[a-z0-9]+$", clean_name):
        flags.append("Excessive whitespace padding detected before file extension")

    return flags


def query_file_hash_virustotal(sha256_hash: str) -> dict[str, Any]:
    """Query VirusTotal API v3 using SHA-256 hash without exposing file contents."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "Missing VIRUSTOTAL_API_KEY in environment"}

    api_endpoint = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(api_endpoint, headers=headers, timeout=12)

        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            # Severity classification
            if malicious >= 3:
                verdict = "MALICIOUS"
                severity = "CRITICAL"
            elif malicious >= 1 or suspicious >= 2:
                verdict = "SUSPICIOUS"
                severity = "MEDIUM"
            else:
                verdict = "BENIGN"
                severity = "LOW"

            return {
                "hash": sha256_hash,
                "verdict": verdict,
                "severity": severity,
                "stats": stats,
                "file_type": data.get("type_description", "Unknown"),
                "magic_header": data.get("magic", "Unknown"),
                "threat_label": data.get("popular_threat_classification", {}).get("suggested_threat_label", "None"),
                "status": "Found in VirusTotal database"
            }

        elif response.status_code == 404:
            return {
                "hash": sha256_hash,
                "verdict": "UNKNOWN_HASH",
                "severity": "INFO",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "status": "Hash not found in VirusTotal cache (Zero-day or unindexed artifact)"
            }

        elif response.status_code == 429:
            return {"error": "VirusTotal API rate limit exceeded (max 4 req/min)."}
        else:
            return {"error": f"VirusTotal API HTTP {response.status_code}"}

    except Exception as exc:
        return {"error": f"Connection error: {str(exc)}"}


def inspect_file_payload(filename: str, file_data: bytes) -> dict[str, Any]:
    """Correlate hash telemetry, file heuristics, and MITRE mapping into a unified triage report."""
    hashes = calculate_hashes(file_data)
    heuristics = check_file_heuristics(filename)
    vt_result = query_file_hash_virustotal(hashes["sha256"])

    verdict = vt_result.get("verdict", "UNKNOWN_HASH")
    severity = vt_result.get("severity", "LOW")

    # Heuristic Elevation: Flag suspicious extensions even if hash is unknown in VT
    if heuristics and severity in ["INFO", "LOW"]:
        severity = "MEDIUM"
        verdict = "SUSPICIOUS_HEURISTICS"

    # MITRE ATT&CK Mapping
    mitre_tags = []
    _, ext = os.path.splitext(filename.lower())
    if ext in [".exe", ".scr", ".bat", ".ps1", ".vbs"]:
        mitre_tags.append({"id": "T1204.002", "name": "User Execution: Malicious File", "tactic": "Execution"})
    if ext in [".docm", ".xlsm"]:
        mitre_tags.append({"id": "T1059.005", "name": "Command and Scripting: Visual Basic", "tactic": "Execution"})
    if len(filename.split(".")) > 2:
        mitre_tags.append({"id": "T1036.007", "name": "Masquerading: Double File Extension", "tactic": "Defense Evasion"})

    return {
        "filename": filename,
        "filesize_bytes": len(file_data),
        "hashes": hashes,
        "heuristics": heuristics,
        "virustotal": vt_result,
        "verdict": verdict,
        "severity": severity,
        "mitre_attack": mitre_tags
    }


def generate_hash_containment(sha256_hash: str, filename: str) -> dict[str, str]:
    """Generate EDR and Endpoint block rules for identified malicious file hashes."""
    return {
        "Windows Defender Application Control (WDAC)": (
            f"New-CIPolicyRule -Level FilePublisher -DriverFilePath '{filename}' -Hash {sha256_hash}"
        ),
        "Microsoft Defender for Endpoint (MDE Indicator)": (
            f"Add-MpPreference -AttackSurfaceReductionOnlyExclusions '{sha256_hash}'"
        ),
        "Linux Malware Hash Watch (Yara / Auditd)": (
            f'auditctl -w /tmp -p x -k malware_exec # Monitor execution for SHA256: {sha256_hash}'
        )
    }