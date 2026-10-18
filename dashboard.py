import streamlit as st
import json
import pandas as pd
from app import process_single_ip

# ตั้งค่าหน้าเว็บ
st.set_page_config(page_title="SOC Threat Triage Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC IP Threat Triage & Investigation")
st.markdown("ระบบวิเคราะห์ภัยคุกคาม IP อัตโนมัติ ผสานข้อมูลจาก **AbuseIPDB**, **VirusTotal** และ **Gemini AI**")

# แถบควบคุมด้านข้าง (Sidebar)
# 1. กล่องด้านข้าง (เคาะเข้าไป 4 ช่อง)
with st.sidebar:
    st.header("⚙️ การตั้งค่า")
    use_ai = st.checkbox("เปิดใช้งาน AI Enrichment (Gemini)", value=False)
    st.markdown("---")
    st.info("ระบบจะส่งการแจ้งเตือนเข้า Discord อัตโนมัติเมื่อตรวจพบระดับ **CRITICAL**")

# 2. ถอยกลับมาชิดซ้ายสุด (0 ช่อง) เพื่อให้กลับมาอยู่หน้าจอหลักตรงกลาง
input_mode = st.radio("เลือกรูปแบบการป้อนข้อมูล (Input Mode):", ["พิมพ์หรือวาง IP เอง", "📂 อัปโหลดไฟล์ Log (auth.log)"], horizontal=True)

ip_list = []
if input_mode == "พิมพ์หรือวาง IP เอง":
    raw_input = st.text_area(
        "ใส่รายการ IP ที่ต้องการตรวจสอบ (1 IP ต่อ 1 บรรทัด):",
        value="185.220.101.5\n8.8.8.8\n192.168.1.1\n999.999.1.1",
        height=120
    )
    if raw_input:
        ip_list = [line.strip() for line in raw_input.replace(",", "\n").splitlines() if line.strip()]
else:
    uploaded_file = st.file_uploader("ลากหรือเลือกไฟล์ Log มาวางที่นี่:", type=["log", "txt"])
    threshold = st.slider("เกณฑ์ตรวจจับ: ล็อกอินผิดอย่างน้อยกี่ครั้งขึ้นไป (Failed Attempts Threshold)", min_value=1, max_value=10, value=2)
    if uploaded_file is not None:
        log_text = uploaded_file.read().decode("utf-8")
        from app import parse_auth_log
        ip_list = parse_auth_log(log_text, threshold=threshold)
        st.info(f"🔎 ตรวจพบ {len(ip_list)} IP ที่ล็อกอินล้มเหลวเกิน {threshold} ครั้ง: {', '.join(ip_list)}")

if st.button("🚀 เริ่มการสแกนและวิเคราะห์", type="primary"):

        if not ip_list:
            st.warning("กรุณากรอก IP หรืออัปโหลดไฟล์ Log ก่อนเริ่มสแกน")
        else:
            results = []
            progress_bar = st.progress(0)
        
        for idx, target_ip in enumerate(ip_list):
            res = process_single_ip(target_ip, use_ai=use_ai)

            # หากข้อมูลมาจากการ Parse ไฟล์ Log ให้เติมแท็ก MITRE T1110 (Brute Force) อัตโนมัติ
            if input_mode != "พิมพ์หรือวาง IP เอง":
                mitre_list = res.get("mitre_attack", [])
                if not any(m.get("id") == "T1110" for m in mitre_list):
                    mitre_list.append({"id": "T1110", "name": "Brute Force"})
                res["mitre_attack"] = mitre_list

            results.append(res)
            progress_bar.progress((idx + 1) / len(ip_list))

        st.success(f"ตรวจสอบเสร็จสิ้นทั้งหมด {len(ip_list)} รายการ!")

        # สรุปภาพรวมด้วยการ์ดตัวเลข (Metrics)
        col1, col2, col3, col4 = st.columns(4)
        critical_count = sum(1 for r in results if r.get("severity") == "CRITICAL")
        suspicious_count = sum(1 for r in results if r.get("severity") == "MEDIUM")
        benign_count = sum(1 for r in results if r.get("verdict") in ["BENIGN", "INTERNAL_IP"])
        error_count = sum(1 for r in results if r.get("verdict") == "ERROR")

        col1.metric("🔴 Critical Threats", critical_count)
        col2.metric("🟠 Suspicious", suspicious_count)
        col3.metric("🟢 Safe / Internal", benign_count)
        col4.metric("⚠️ Format Errors", error_count)

        st.markdown("---")

        # แสดงผลตารางสรุป
        st.subheader("📋 ตารางสรุปผลการประเมิน (Summary Table)")
        table_data = []
        for r in results:
            mitre_list = r.get("mitre_attack", [])
            mitre_display = ", ".join([f"{m['id']} ({m['name']})" for m in mitre_list]) if mitre_list else "None"

            is_cached = r.get("cached", False)
            source_badge = "⚡ Cached (Local DB)" if is_cached else "🌐 Live API"

            table_data.append({
                "Target IP": r.get("ip", "N/A"),
                "Source": source_badge,
                "Verdict": r.get("verdict", "N/A"),
                "Severity": r.get("severity", "N/A"),
                "Confidence": f"{int(r.get('confidence', 0) * 100)}%" if "confidence" in r else "N/A",
                "MITRE ATT&CK": mitre_display,
                "Reasoning": r.get("reasoning", r.get("error", "N/A"))
            })
        st.dataframe(pd.DataFrame(table_data), use_container_width=True)

        # ปุ่มดาวน์โหลดรายงานผล (Export Options)
        st.write("")
        exp_col1, exp_col2, _ = st.columns([1, 1, 2])
        
        # 1. ปุ่มดาวน์โหลดเป็น CSV สำหรับเปิดใน Excel
        df_export = pd.DataFrame(table_data)
        csv_data = df_export.to_csv(index=False).encode("utf-8")
        exp_col1.download_button(
            label="📥 ดาวน์โหลดรายงาน (CSV)",
            data=csv_data,
            file_name="soc_triage_report.csv",
            mime="text/csv",
            use_container_width=True
        )

        # 2. ปุ่มดาวน์โหลด JSON เต็มรูปแบบสำหรับส่งต่อระบบ SIEM / Ticket
        json_data = json.dumps(results, indent=2, ensure_ascii=False)
        exp_col2.download_button(
            label="📥 ดาวน์โหลด Raw JSON",
            data=json_data,
            file_name="soc_triage_report.json",
            mime="application/json",
            use_container_width=True
        )
        
        # รายละเอียดเชิงลึกแบบ Dropdown ทีละ IP
        st.subheader("🔍 รายละเอียดเชิงลึก (Detailed Investigation)")
        for r in results:
            with st.expander(f"📌 IP: {r.get('ip')} — Verdict: {r.get('verdict')}"):
                st.json(r)