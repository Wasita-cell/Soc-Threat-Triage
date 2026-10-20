#!/usr/bin/env python3
"""
SOC Incident Ticket & Handover Report Generator
Formats triage telemetry, IOCs, MITRE mappings, and containment steps into standard Markdown.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


def format_incident_ticket(
    incident_type: str,
    target: str,
    verdict: str,
    severity: str,
    details: dict[str, Any],
    containment_actions: dict[str, str] | None = None
) -> str:
    """Generate a clean, standardized Markdown Incident Ticket for Tier-2 / IR handover."""
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{abs(hash(target)) % 10000:04d}"

    lines = [
        f"# 🚨 Incident Ticket: {incident_id}",
        f"**Generated at:** `{now_utc}` | **Analyst Tier:** Tier-1 Automated Triage\n",
        "---",
        "## 1. Incident Overview",
        f"- **Incident Type:** {incident_type}",
        f"- **Target / Primary Artifact:** `{target}`",
        f"- **Triage Verdict:** `{verdict}`",
        f"- **Assigned Severity:** `{severity}`",
        f"- **Confidence Score:** {int(details.get('confidence', 1.0) * 100)}%\n",
        "## 2. Technical Findings & Context"
    ]

    # Specific formatting per artifact type
    if incident_type == "IP Intelligence":
        lines.append(f"- **ISP / Organization:** {details.get('isp', 'N/A')}")
        lines.append(f"- **Country Code:** {details.get('country', 'N/A')}")
        lines.append(f"- **Abuse Confidence Score:** {details.get('abuse_score', 'N/A')}%")
        lines.append(f"- **Total Reported Incidents:** {details.get('total_reports', 'N/A')}")
        lines.append(f"- **Analyst Reasoning:** {details.get('reasoning', 'N/A')}")

    elif incident_type == "URL Investigation":
        lines.append(f"- **Defanged URL:** `{details.get('defanged_url', target)}`")
        stats = details.get("stats", {})
        lines.append(f"- **VirusTotal Flagged:** {stats.get('malicious', 0)} engines flagged as malicious")
        heuristics = details.get("heuristics", [])
        if heuristics:
            lines.append("- **Structural Heuristics:**")
            for h in heuristics:
                lines.append(f"  - {h}")

    elif incident_type == "Phishing Email Artifact":
        lines.append(f"- **Subject:** `{details.get('subject', 'N/A')}`")
        lines.append(f"- **Sender (From):** `{details.get('from', 'N/A')}`")
        lines.append(f"- **Return-Path:** `{details.get('return_path', 'N/A')}`")
        auth = details.get("authentication", {})
        lines.append(f"- **SPF / DKIM / DMARC:** `{auth.get('spf')}` / `{auth.get('dkim')}` / `{auth.get('dmarc')}`")
        
        alerts = details.get("impersonation_alerts", []) + details.get("url_deception_flags", [])
        if alerts:
            lines.append("- **Detected Threat Lures:**")
            for a in alerts:
                lines.append(f"  - {a}")

    elif incident_type == "File Hash Investigation":
        lines.append(f"- **Filename:** `{details.get('filename', target)}`")
        lines.append(f"- **File Size:** {details.get('filesize_bytes', 'N/A')} bytes")
        hashes = details.get("hashes", {})
        if hashes:
            lines.append(f"- **SHA-256:** `{hashes.get('sha256', target)}`")
            lines.append(f"- **MD5:** `{hashes.get('md5', 'N/A')}`")
            lines.append(f"- **SHA-1:** `{hashes.get('sha1', 'N/A')}`")
        else:
            lines.append(f"- **Target Hash:** `{target}`")
        vt_info = details.get("virustotal", {})
        stats = vt_info.get("stats", {})
        lines.append(f"- **VirusTotal Flagged:** {stats.get('malicious', 0)} engines flagged as malicious")
        heuristics = details.get("heuristics", [])
        if heuristics:
            lines.append("- **File Heuristic Alerts:**")
            for h in heuristics:
                lines.append(f"  - {h}")

    # MITRE ATT&CK Section
    mitre_tags = details.get("mitre_attack", [])
    if mitre_tags:
        lines.append("\n## 3. MITRE ATT&CK Mapping")
        for m in mitre_tags:
            lines.append(f"- **{m.get('id')}: {m.get('name')}** (Tactic: {m.get('tactic', 'Initial Access / Recon')})")

    # Containment & Remediation Actions
    if containment_actions:
        lines.append("\n## 4. Immediate Containment Instructions")
        for target_env, cmd in containment_actions.items():
            lines.append(f"### {target_env}")
            lines.append(f"```bash\n{cmd}\n```")

    # Next Steps for IR / Tier-2
    lines.append("\n## 5. Escalation & Tier-2 Next Steps")
    lines.append("- [ ] Verify active network sessions or host endpoint logs for lateral movement.")
    lines.append("- [ ] Execute recommended containment rules on boundary firewalls / gateways.")
    lines.append("- [ ] Notify affected end-user and initiate credential reset if account compromise is suspected.")

    return "\n".join(lines)