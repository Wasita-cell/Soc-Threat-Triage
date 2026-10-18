#!/usr/bin/env python3
"""
Unified SOC Analyst Investigation Dashboard
Supports IP Threat Triage, URL Reputation Scanning, Phishing Email (.eml) Analysis,
Automated Containment Rule Generation, and Tier-2 Incident Ticket Handover.
"""
from __future__ import annotations

import os
import json
import tempfile
import pandas as pd
import streamlit as st

from app import process_single_ip, parse_auth_log
from url_scanner import scan_url_virustotal, defang_url
from email_parser import inspect_email_file
from containment import (
    generate_ip_containment,
    generate_domain_containment,
    generate_email_containment
)
from report_generator import format_incident_ticket

# ==========================================
# Page Configuration
# ==========================================
st.set_page_config(
    page_title="SOC Analyst Investigation Toolkit",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Analyst Investigation & Triage Toolkit")
st.caption("Automated Tier-1 triage pipeline for network logs, IP reputation, suspicious URLs, and phishing artifacts.")

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Configuration")
    enable_ai = st.checkbox("Enable AI Enrichment (Gemini)", value=False)
    st.info("Automated Webhook alerts dispatch when CRITICAL severity threats are triaged.")

# Tabbed Workspace
tab_ip, tab_url, tab_email = st.tabs([
    "🌐 IP Threat Intelligence",
    "🔗 URL Reputation Scanner",
    "📧 Phishing Email Analyzer"
])

# ==========================================
# TAB 1: IP Threat Intelligence
# ==========================================
with tab_ip:
    st.subheader("IP Telemetry & Authentication Log Triage")
    
    col1, col2 = st.columns([2, 1])
    with col1:
        single_ip_input = st.text_input("Investigate Target IP Address", placeholder="e.g., 185.220.101.5")
    with col2:
        log_file = st.file_uploader("Upload Linux Auth Log (auth.log)", type=["log", "txt"])

    run_ip_triage = st.button("Run IP Triage", type="primary")

    if run_ip_triage:
        targets = []
        if log_file:
            log_data = log_file.read().decode("utf-8", errors="replace")
            parsed_ips = parse_auth_log(log_data)
            st.write(f"Parsed **{len(parsed_ips)}** suspicious IP(s) exceeding brute-force threshold from log.")
            targets.extend(parsed_ips)
        elif single_ip_input:
            targets.append(single_ip_input.strip())

        if not targets:
            st.warning("Please enter an IP address or upload an authentication log file.")
        else:
            with st.spinner("Triaging targets against local cache and threat intelligence feeds..."):
                triage_records = [process_single_ip(target, use_ai=enable_ai) for target in targets]

            # Metric Summary Cards
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Critical Threats", sum(1 for r in triage_records if r.get("severity") == "CRITICAL"))
            c2.metric("Suspicious", sum(1 for r in triage_records if r.get("severity") == "MEDIUM"))
            c3.metric("Safe / Internal", sum(1 for r in triage_records if r.get("severity") in ["LOW", "INFO"]))
            c4.metric("Format Errors", sum(1 for r in triage_records if r.get("verdict") == "ERROR"))

            # Summary Table
            st.markdown("### Triage Summary")
            df_rows = []
            for r in triage_records:
                mitre_list = [f"{m['id']} - {m['name']}" for m in r.get("mitre_attack", [])]
                df_rows.append({
                    "Target IP": r.get("ip"),
                    "Source": "⚡ Cached (Local DB)" if r.get("cached") else "🌐 Live API",
                    "Verdict": r.get("verdict"),
                    "Severity": r.get("severity"),
                    "Confidence": f"{int(r.get('confidence', 0) * 100)}%" if "confidence" in r else "N/A",
                    "MITRE ATT&CK": ", ".join(mitre_list) if mitre_list else "None",
                    "Reasoning": r.get("reasoning", "N/A")
                })
            df = pd.DataFrame(df_rows)
            st.dataframe(df, use_container_width=True)

            # Detailed Investigation & Containment Actions
            st.markdown("### Detailed Investigation & Response")
            for record in triage_records:
                ip_label = record.get("ip", "Unknown")
                verdict_label = record.get("verdict", "N/A")
                severity_label = record.get("severity", "LOW")

                with st.expander(f"📍 Target: {ip_label} — Verdict: {verdict_label} ({severity_label})"):
                    st.json(record)

                    # Containment & Escalation for Medium / Critical Threats
                    if severity_label in ["CRITICAL", "MEDIUM"]:
                        st.markdown("#### 🛑 Recommended Firewall Containment")
                        containment_cmds = generate_ip_containment(ip_label)
                        for env_name, cmd in containment_cmds.items():
                            st.code(cmd, language="bash")

                        # Generate Incident Handover Ticket
                        ticket_md = format_incident_ticket(
                            incident_type="IP Intelligence",
                            target=ip_label,
                            verdict=verdict_label,
                            severity=severity_label,
                            details=record,
                            containment_actions=containment_cmds
                        )
                        st.markdown("#### 📋 Incident Handover Ticket (Tier-2 / IR)")
                        st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=220)
                        st.download_button(
                            label=f"📥 Download Ticket ({ip_label})",
                            data=ticket_md,
                            file_name=f"incident_ticket_{ip_label}.md",
                            mime="text/markdown"
                        )

# ==========================================
# TAB 2: URL Reputation Scanner
# ==========================================
with tab_url:
    st.subheader("URL Heuristics & Reputation Lookup")
    target_url = st.text_input("Target URL to Investigate", placeholder="https://example-phish-domain.com/login")
    run_url_scan = st.button("Scan URL", type="primary")

    if run_url_scan:
        if not target_url:
            st.warning("Please provide a valid URL to analyze.")
        else:
            with st.spinner("Querying VirusTotal and evaluating URL heuristics..."):
                scan_res = scan_url_virustotal(target_url.strip())

            if "error" in scan_res:
                st.error(scan_res["error"])
            else:
                verdict_label = scan_res.get("verdict", "N/A")
                severity_label = scan_res.get("severity", "LOW")

                u1, u2, u3, u4 = st.columns(4)
                u1.metric("Verdict", verdict_label)
                u2.metric("Severity", severity_label)
                stats = scan_res.get("stats", {})
                u3.metric("Malicious Flags", stats.get("malicious", 0))
                u4.metric("Harmless Votes", stats.get("harmless", 0))

                st.markdown(f"**Defanged IOC:** `{scan_res.get('defanged_url')}`")

                heuristics = scan_res.get("heuristics", [])
                if heuristics:
                    st.warning("⚠️ **Heuristic Alerts Detected:**")
                    for h in heuristics:
                        st.markdown(f"- {h}")
                else:
                    st.success("No suspicious URL heuristic patterns detected.")

                # Containment & Incident Ticket
                if severity_label in ["CRITICAL", "MEDIUM"]:
                    st.markdown("---")
                    st.markdown("### 🛑 Recommended Domain Sinkhole / Containment")
                    containment_cmds = generate_domain_containment(target_url.strip())
                    for env_name, cmd in containment_cmds.items():
                        st.code(cmd, language="bash")

                    ticket_md = format_incident_ticket(
                        incident_type="URL Investigation",
                        target=scan_res.get("defanged_url", target_url),
                        verdict=verdict_label,
                        severity=severity_label,
                        details=scan_res,
                        containment_actions=containment_cmds
                    )
                    st.markdown("### 📋 Incident Handover Ticket (Tier-2 / IR)")
                    st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=220)
                    st.download_button(
                        label="📥 Download URL Incident Ticket",
                        data=ticket_md,
                        file_name="incident_ticket_url.md",
                        mime="text/markdown"
                    )

                with st.expander("View Raw Scanner Telemetry"):
                    st.json(scan_res)

# ==========================================
# TAB 3: Phishing Email Analyzer
# ==========================================
with tab_email:
    st.subheader("Phishing Email (.eml) Artifact Parser")
    st.caption("Upload suspect .eml files to extract authentication results, detect sender spoofing, and harvest embedded links.")

    eml_file = st.file_uploader("Upload Raw Email File (.eml)", type=["eml"])
    scan_embedded_links = st.checkbox("Automatically scan extracted URLs via VirusTotal (Respects API Limits)", value=False)
    run_email_analysis = st.button("Analyze Email", type="primary")

    if run_email_analysis:
        if not eml_file:
            st.warning("Please upload a .eml file to proceed.")
        else:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
                tmp.write(eml_file.read())
                tmp_path = tmp.name

            try:
                with st.spinner("Extracting email headers, authentication tags, and embedded links..."):
                    email_report = inspect_email_file(tmp_path, scan_links=scan_embedded_links)

                verdict_label = email_report.get("verdict", "N/A")
                severity_label = email_report.get("severity", "LOW")

                e1, e2, e3 = st.columns(3)
                e1.metric("Verdict", verdict_label)
                e2.metric("Severity", severity_label)
                e3.metric("Extracted URLs", len(email_report.get("raw_urls", [])))

                st.markdown("### Header & Sender Intelligence")
                st.markdown(f"- **Subject:** `{email_report.get('subject')}`")
                st.markdown(f"- **Display From:** `{email_report.get('from')}`")
                st.markdown(f"- **Return-Path:** `{email_report.get('return_path')}`")

                auth = email_report.get("authentication", {})
                a1, a2, a3 = st.columns(3)
                a1.markdown(f"**SPF:** `{auth.get('spf')}`")
                a2.markdown(f"**DKIM:** `{auth.get('dkim')}`")
                a3.markdown(f"**DMARC:** `{auth.get('dmarc')}`")

                sender_flags = email_report.get("sender_flags", [])
                if sender_flags:
                    st.error("🚨 **Sender Discrepancy Alerts:**")
                    for flag in sender_flags:
                        st.markdown(f"- {flag}")

                # Display Impersonation & Social Engineering Alerts
                impersonation_alerts = email_report.get("impersonation_alerts", [])
                if impersonation_alerts:
                    st.error("🚨 **Brand Impersonation & Social Engineering:**")
                    for alert in impersonation_alerts:
                        st.markdown(f"- {alert}")

                # Display Subdomain Deception Warnings
                url_deception_flags = email_report.get("url_deception_flags", [])
                if url_deception_flags:
                    st.warning("⚠️ **URL Subdomain Deception Detected:**")
                    for flag in url_deception_flags:
                        st.markdown(f"- {flag}")

                st.markdown("### Harvested Link IOCs (Defanged)")
                extracted_urls = email_report.get("extracted_urls", [])
                if extracted_urls:
                    for u in extracted_urls:
                        st.code(u, language="text")
                else:
                    st.info("No external links found in email body.")

                # Containment & Incident Ticket
                if severity_label in ["CRITICAL", "MEDIUM"]:
                    st.markdown("---")
                    st.markdown("### 🛑 Recommended Email & Tenant Containment")
                    sender_clean = email_report.get("from", "")
                    subject_clean = email_report.get("subject", "")
                    containment_cmds = generate_email_containment(sender_clean, subject_clean)
                    for env_name, cmd in containment_cmds.items():
                        st.markdown(f"**{env_name}:**")
                        st.code(cmd, language="powershell")

                    ticket_md = format_incident_ticket(
                        incident_type="Phishing Email Artifact",
                        target=f"{email_report.get('from')} - Subject: {email_report.get('subject')}",
                        verdict=verdict_label,
                        severity=severity_label,
                        details=email_report,
                        containment_actions=containment_cmds
                    )
                    st.markdown("### 📋 Incident Handover Ticket (Tier-2 / IR)")
                    st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=240)
                    st.download_button(
                        label="📥 Download Phishing Incident Ticket",
                        data=ticket_md,
                        file_name="incident_ticket_phishing.md",
                        mime="text/markdown"
                    )

                with st.expander("View Full Email Analysis JSON"):
                    st.json(email_report)

            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)