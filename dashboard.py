import os
import json
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from app import process_single_ip

# Load environment variables
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="SOC Threat Triage Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Main Title & Subtitle
st.title("🛡️ SOC Threat Triage Dashboard")
st.markdown("Automated IP threat intelligence aggregation powered by **AbuseIPDB**, **VirusTotal**, and **Gemini AI**.")

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Configuration")
    use_ai = st.checkbox("Enable AI Enrichment (Gemini)", value=False)
    st.markdown("---")
    st.info("Automated Discord alerts will be dispatched upon detecting **CRITICAL** severity threats.")

# Input Mode Selection
input_mode = st.radio(
    "Select Input Mode:",
    ["Manual IP Input", "📂 Upload Log File (auth.log)"],
    horizontal=True
)

ip_list = []
if input_mode == "Manual IP Input":
    raw_input = st.text_area(
        "Enter IP addresses to investigate (one per line):",
        value="185.220.101.5\n8.8.8.8\n192.168.1.1\n999.999.1.1",
        height=120
    )
    if raw_input:
        ip_list = [line.strip() for line in raw_input.replace(",", "\n").splitlines() if line.strip()]
else:
    uploaded_file = st.file_uploader("Drag and drop server authentication log here:", type=["log", "txt"])
    threshold = st.slider("Detection Threshold (Minimum Failed Attempts)", min_value=1, max_value=10, value=2)
    if uploaded_file is not None:
        log_text = uploaded_file.read().decode("utf-8")
        from app import parse_auth_log
        ip_list = parse_auth_log(log_text, threshold=threshold)
        st.info(f"🔎 Detected {len(ip_list)} suspicious IP(s) exceeding {threshold} failed attempts: {', '.join(ip_list)}")

# Execution Button
if st.button("🚀 Start Triage & Analysis", type="primary"):
    if not ip_list:
        st.warning("Please provide target IPs or upload a valid log file before initiating analysis.")
    else:
        results = []
        progress_bar = st.progress(0)

        # Process IPs with automated MITRE mapping for log-derived entries
        for idx, target_ip in enumerate(ip_list):
            res = process_single_ip(target_ip, use_ai=use_ai)

            if input_mode != "Manual IP Input":
                mitre_list = res.get("mitre_attack", [])
                if not any(m.get("id") == "T1110" for m in mitre_list):
                    mitre_list.append({"id": "T1110", "name": "Brute Force"})
                res["mitre_attack"] = mitre_list

            results.append(res)
            progress_bar.progress((idx + 1) / len(ip_list))

        st.success(f"Triage completed for {len(ip_list)} target(s)!")

        # High-level Metrics Summary
        col1, col2, col3, col4 = st.columns(4)
        critical_count = sum(1 for r in results if r.get("severity") == "CRITICAL")
        suspicious_count = sum(1 for r in results if r.get("severity") == "SUSPICIOUS")
        safe_count = sum(1 for r in results if r.get("verdict") in ["BENIGN", "INTERNAL_IP"])
        error_count = sum(1 for r in results if r.get("verdict") == "ERROR")

        col1.metric("🔴 Critical Threats", critical_count)
        col2.metric("🟠 Suspicious", suspicious_count)
        col3.metric("🟢 Safe / Internal", safe_count)
        col4.metric("⚠️ Format Errors", error_count)

        # Tabular Triage Summary
        st.markdown("### 📋 Triage Summary")
        table_data = []
        for r in results:
            source_badge = "⚡ Cached (Local DB)" if r.get("cached") else "🌐 Live API"
            mitre_tags = ", ".join([f"{m['id']} ({m['name']})" for m in r.get("mitre_attack", [])]) if r.get("mitre_attack") else "None"
            confidence_val = f"{int(r.get('confidence', 0) * 100)}%" if r.get("confidence") is not None else "N/A"

            table_data.append({
                "Target IP": r.get("ip"),
                "Source": source_badge,
                "Verdict": r.get("verdict"),
                "Severity": r.get("severity"),
                "Confidence": confidence_val,
                "MITRE ATT&CK": mitre_tags,
                "Reasoning": r.get("incident_note", "").split("\n")[0]
            })

        st.dataframe(pd.DataFrame(table_data), use_container_width=True)

        # Export Options
        st.write("")
        exp_col1, exp_col2, _ = st.columns([1, 1, 2])
        
        df_export = pd.DataFrame(table_data)
        csv_data = df_export.to_csv(index=False).encode("utf-8")
        exp_col1.download_button(
            label="📥 Export Report (CSV)",
            data=csv_data,
            file_name="soc_triage_report.csv",
            mime="text/csv",
            use_container_width=True
        )

        json_data = json.dumps(results, indent=2, ensure_ascii=False)
        exp_col2.download_button(
            label="📥 Export Raw JSON",
            data=json_data,
            file_name="soc_triage_report.json",
            mime="application/json",
            use_container_width=True
        )

        # Detailed Investigation Dropdowns
        st.markdown("### 🔍 Detailed Investigation")
        for r in results:
            ip_label = r.get("ip", "Unknown")
            verdict_label = r.get("verdict", "UNKNOWN")
            with st.expander(f"📌 IP: {ip_label} — Verdict: {verdict_label}"):
                st.json(r)