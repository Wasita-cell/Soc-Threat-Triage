#!/usr/bin/env python3
"""
Unified SOC Analyst Investigation Dashboard
Supports IP Threat Triage, URL Reputation Scanning, Phishing Email (.eml) Analysis,
File Hash Inspection, and Phone/Smishing Intelligence.
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
from file_inspector import (
    inspect_file_payload,
    query_file_hash_virustotal,
    generate_hash_containment
)
from phone_scanner import inspect_phone_number, generate_phone_containment
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
st.caption("Automated Tier-1 triage pipeline for network logs, IP reputation, suspicious URLs, phishing artifacts, file hashes, and smishing leads.")

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Configuration")
    enable_ai = st.checkbox("Enable AI Enrichment (Gemini)", value=False)
    st.info("Automated Webhook alerts dispatch when CRITICAL severity threats are triaged.")

# Tabbed Workspace (5 Vectors)
tab_ip, tab_url, tab_email, tab_file, tab_phone = st.tabs([
    "🌐 IP Threat Intelligence",
    "🔗 URL Reputation Scanner",
    "📧 Phishing Email Analyzer",
    "📁 File Hash & Malware Inspector",
    "📱 Phone & Smishing Inspector"
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

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Critical Threats", sum(1 for r in triage_records if r.get("severity") == "CRITICAL"))
            c2.metric("Suspicious", sum(1 for r in triage_records if r.get("severity") == "MEDIUM"))
            c3.metric("Safe / Internal", sum(1 for r in triage_records if r.get("severity") in ["LOW", "INFO"]))
            c4.metric("Format Errors", sum(1 for r in triage_records if r.get("verdict") == "ERROR"))

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

            st.markdown("### Detailed Investigation & Response")
            for record in triage_records:
                ip_label = record.get("ip", "Unknown")
                verdict_label = record.get("verdict", "N/A")
                severity_label = record.get("severity", "LOW")

                with st.expander(f"📍 Target: {ip_label} — Verdict: {verdict_label} ({severity_label})"):
                    st.json(record)

                    if severity_label in ["CRITICAL", "MEDIUM"]:
                        st.markdown("#### 🛑 Recommended Firewall Containment")
                        containment_cmds = generate_ip_containment(ip_label)
                        for env_name, cmd in containment_cmds.items():
                            st.code(cmd, language="bash")

                        ticket_md = format_incident_ticket(
                            incident_type="IP Intelligence",
                            target=ip_label,
                            verdict=verdict_label,
                            severity=severity_label,
                            details=record,
                            containment_actions=containment_cmds
                        )
                        st.markdown("#### 📋 Incident Handover Ticket (Tier-2 / IR)")
                        st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=220, key=f"tkt_ip_{ip_label}")
                        st.download_button(
                            label=f"📥 Download Ticket ({ip_label})",
                            data=ticket_md,
                            file_name=f"incident_ticket_{ip_label}.md",
                            mime="text/markdown",
                            key=f"dl_ip_{ip_label}"
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
                    st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=220, key="tkt_url")
                    st.download_button(
                        label="📥 Download URL Incident Ticket",
                        data=ticket_md,
                        file_name="incident_ticket_url.md",
                        mime="text/markdown",
                        key="dl_url"
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

                impersonation_alerts = email_report.get("impersonation_alerts", [])
                if impersonation_alerts:
                    st.error("🚨 **Brand Impersonation & Social Engineering:**")
                    for alert in impersonation_alerts:
                        st.markdown(f"- {alert}")

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
                    st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=240, key="tkt_eml")
                    st.download_button(
                        label="📥 Download Phishing Incident Ticket",
                        data=ticket_md,
                        file_name="incident_ticket_phishing.md",
                        mime="text/markdown",
                        key="dl_eml"
                    )

                with st.expander("View Full Email Analysis JSON"):
                    st.json(email_report)

            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

# ==========================================
# TAB 4: File Hash & Malware Inspector
# ==========================================
with tab_file:
    st.subheader("File Hash & Artifact Triage")
    st.caption("Calculate cryptographic hashes, detect deceptive extension patterns, and query VirusTotal using Privacy-First hash lookups.")

    investigation_mode = st.radio("Choose Investigation Method:", ["Upload File Artifact", "Direct SHA-256 Hash Lookup"], horizontal=True)

    if investigation_mode == "Upload File Artifact":
        uploaded_payload = st.file_uploader("Upload Suspect File / Attachment", type=None)
        run_file_inspect = st.button("Inspect File", type="primary")

        if run_file_inspect:
            if not uploaded_payload:
                st.warning("Please upload a file to analyze.")
            else:
                file_bytes = uploaded_payload.read()
                filename = uploaded_payload.name

                with st.spinner("Calculating hashes, evaluating heuristics, and querying VirusTotal..."):
                    file_report = inspect_file_payload(filename, file_bytes)

                verdict_label = file_report.get("verdict", "N/A")
                severity_label = file_report.get("severity", "LOW")

                f1, f2, f3, f4 = st.columns(4)
                f1.metric("Verdict", verdict_label)
                f2.metric("Severity", severity_label)
                vt_stats = file_report.get("virustotal", {}).get("stats", {})
                f3.metric("Malicious Flags", vt_stats.get("malicious", 0))
                f4.metric("File Size", f"{file_report.get('filesize_bytes')} bytes")

                st.markdown("### 🔑 Cryptographic Hashes (Local Calculation)")
                hashes = file_report.get("hashes", {})
                st.code(f"SHA-256: {hashes.get('sha256')}\nMD5:     {hashes.get('md5')}\nSHA-1:   {hashes.get('sha1')}", language="text")

                heuristics = file_report.get("heuristics", [])
                if heuristics:
                    st.warning("⚠️ **File Heuristic Alerts:**")
                    for h in heuristics:
                        st.markdown(f"- {h}")
                else:
                    st.success("No deceptive naming or high-risk execution extensions detected.")

                if severity_label in ["CRITICAL", "MEDIUM"]:
                    st.markdown("---")
                    st.markdown("### 🛑 Recommended Endpoint & EDR Containment")
                    containment_cmds = generate_hash_containment(hashes.get("sha256", ""), filename)
                    for env_name, cmd in containment_cmds.items():
                        st.markdown(f"**{env_name}:**")
                        st.code(cmd, language="powershell" if "Windows" in env_name or "Defender" in env_name else "bash")

                    ticket_md = format_incident_ticket(
                        incident_type="File Hash Investigation",
                        target=filename,
                        verdict=verdict_label,
                        severity=severity_label,
                        details=file_report,
                        containment_actions=containment_cmds
                    )
                    st.markdown("### 📋 Incident Handover Ticket (Tier-2 / IR)")
                    st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=220, key="tkt_file")
                    st.download_button(
                        label="📥 Download File Incident Ticket",
                        data=ticket_md,
                        file_name=f"incident_ticket_{filename}.md",
                        mime="text/markdown",
                        key="dl_file"
                    )

                with st.expander("View Full File Analysis JSON"):
                    st.json(file_report)

    else:
        manual_hash = st.text_input("Enter Target SHA-256 Hash", placeholder="e.g., 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        run_hash_lookup = st.button("Lookup Hash", type="primary")

        if run_hash_lookup:
            if not manual_hash or len(manual_hash.strip()) != 64:
                st.warning("Please provide a valid 64-character SHA-256 hash.")
            else:
                target_hash = manual_hash.strip()
                with st.spinner("Querying VirusTotal threat intelligence for hash..."):
                    vt_result = query_file_hash_virustotal(target_hash)

                if "error" in vt_result:
                    st.error(vt_result["error"])
                else:
                    verdict_label = vt_result.get("verdict", "N/A")
                    severity_label = vt_result.get("severity", "LOW")

                    h1, h2, h3, h4 = st.columns(4)
                    h1.metric("Verdict", verdict_label)
                    h2.metric("Severity", severity_label)
                    stats = vt_result.get("stats", {})
                    h3.metric("Malicious Flags", stats.get("malicious", 0))
                    h4.metric("Threat Label", vt_result.get("threat_label", "N/A"))

                    st.markdown(f"- **Identified Type:** `{vt_result.get('file_type', 'N/A')}`")
                    st.markdown(f"- **Magic Header:** `{vt_result.get('magic_header', 'N/A')}`")

                    if severity_label in ["CRITICAL", "MEDIUM"]:
                        st.markdown("---")
                        st.markdown("### 🛑 Recommended EDR Block Rules")
                        containment_cmds = generate_hash_containment(target_hash, "Target_Artifact")
                        for env_name, cmd in containment_cmds.items():
                            st.code(cmd, language="powershell" if "Windows" in env_name else "bash")

                        details_dict = {"filename": target_hash, "hashes": {"sha256": target_hash}, "virustotal": vt_result}
                        ticket_md = format_incident_ticket(
                            incident_type="File Hash Investigation",
                            target=target_hash,
                            verdict=verdict_label,
                            severity=severity_label,
                            details=details_dict,
                            containment_actions=containment_cmds
                        )
                        st.markdown("### 📋 Incident Handover Ticket (Tier-2 / IR)")
                        st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=220, key="tkt_hash")
                        st.download_button(
                            label="📥 Download Hash Incident Ticket",
                            data=ticket_md,
                            file_name=f"incident_ticket_{target_hash[:8]}.md",
                            mime="text/markdown",
                            key="dl_hash"
                        )

                    with st.expander("View Raw Threat Intelligence JSON"):
                        st.json(vt_result)

# ==========================================
# TAB 5: Phone & Smishing Inspector
# ==========================================
with tab_phone:
    st.subheader("Phone Number & SMS Short Code Triage")
    st.caption("Inspect inbound caller IDs or SMS Short Codes (e.g., 3-4 digit NZ banking codes, VoIP lines, and smishing lures).")

    p_col1, p_col2 = st.columns([3, 1])
    with p_col1:
        phone_input = st.text_input(
            "Target Phone Number or SMS Short Code", 
            placeholder="e.g., 4444 (ANZ Alert), 898 (NZ Post), or +64 21 123 4567"
        )
    with p_col2:
        default_country = st.selectbox("Default Country Code", ["NZ", "AU", "US", "GB", "TH"], index=0)

    run_phone_scan = st.button("Inspect Sender", type="primary")

    if run_phone_scan:
        if not phone_input:
            st.warning("Please provide a phone number to analyze.")
        else:
            with st.spinner("Analyzing telephone formatting, carrier metadata, and line risks..."):
                phone_res = inspect_phone_number(phone_input.strip(), default_region=default_country)

            if not phone_res.get("valid", False):
                st.error(f"❌ Validation Error: {phone_res.get('error', 'Invalid number')}")
            else:
                verdict_label = phone_res.get("verdict", "N/A")
                severity_label = phone_res.get("severity", "LOW")

                p1, p2, p3, p4 = st.columns(4)
                p1.metric("Verdict", verdict_label)
                p2.metric("Severity", severity_label)
                p3.metric("Line Type", phone_res.get("line_type", "Unknown"))
                p4.metric("Carrier", phone_res.get("carrier", "Unknown"))

                st.markdown("### 📞 Number Metadata & Formats")
                st.markdown(f"- **E.164 Standard Format:** `{phone_res.get('e164_format')}`")
                st.markdown(f"- **International Format:** `{phone_res.get('international_format')}`")
                st.markdown(f"- **National Format:** `{phone_res.get('national_format')}`")
                st.markdown(f"- **Identified Region / Location:** `{phone_res.get('region')}`")

                # Heuristics / Verification Alerts
                heuristics = phone_res.get("heuristics", [])
                if heuristics:
                    if severity_label == "LOW":
                        st.success("✅ **Verified Enterprise Sender:**")
                        for h in heuristics:
                            st.markdown(f"- {h}")
                    else:
                        st.warning("⚠️ **Heuristic Alerts Detected:**")
                        for h in heuristics:
                            st.markdown(f"- {h}")
                else:
                    st.success("Standard mobile or fixed line. No anonymous VoIP pattern detected.")

                if severity_label in ["CRITICAL", "MEDIUM"]:
                    st.markdown("---")
                    st.markdown("### 🛑 Recommended PBX & Gateway Containment")
                    e164_target = phone_res.get("e164_format", phone_input.strip())
                    containment_cmds = generate_phone_containment(e164_target)
                    for env_name, cmd in containment_cmds.items():
                        st.markdown(f"**{env_name}:**")
                        st.code(cmd, language="bash")

                    ticket_md = format_incident_ticket(
                        incident_type="Phone Intelligence",
                        target=e164_target,
                        verdict=verdict_label,
                        severity=severity_label,
                        details=phone_res,
                        containment_actions=containment_cmds
                    )
                    st.markdown("### 📋 Incident Handover Ticket (Tier-2 / IR)")
                    st.text_area("Copy-Paste Incident Ticket (Markdown)", ticket_md, height=220, key="tkt_phone")
                    st.download_button(
                        label="📥 Download Phone Incident Ticket",
                        data=ticket_md,
                        file_name=f"incident_ticket_phone_{e164_target}.md",
                        mime="text/markdown",
                        key="dl_phone"
                    )

                with st.expander("View Full Phone Telemetry JSON"):
                    st.json(phone_res)