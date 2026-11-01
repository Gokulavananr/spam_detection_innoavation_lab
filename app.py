import io
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

import streamlit as st
from PIL import Image

# We only import what actually exists in our custom detector.py
from detector import analyze_image, score_url

try:  
    from streamlit_paste_button import paste_image_button
except ImportError:
    paste_image_button = None

BASE = Path(__file__).resolve().parent
SAMPLES = BASE / "test_images"

st.set_page_config(page_title="Spam Shield | AI Detector", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

# Session state initialization
for k, v in {"total_scans": 0, "threats": 0, "history": [], "result": None, "source": None}.items():
    st.session_state.setdefault(k, v)

st.markdown("""
<style>
.stApp {background: linear-gradient(135deg,#EEF2FF 0%,#F5F3FF 45%,#E0F7FA 100%); color:#1F2937;}
header {background: transparent !important;}
footer, #MainMenu {visibility: hidden;}
.title-text {background: linear-gradient(90deg,#7D2AE8,#00C4CC); -webkit-background-clip:text;
  -webkit-text-fill-color:transparent; font-size:3.2rem !important; font-weight:800; margin:0; letter-spacing:-1px;}
.subtitle-text {color:#6B7280; font-size:1.1rem; margin-bottom:1.2rem;}
.cyber-card {background:#FFFFFF; border:1px solid #E5E7EB;
  padding:22px; border-radius:16px; box-shadow:0 8px 30px rgba(125,42,232,.12); margin-bottom:16px;}
.badge {color:#fff; padding:6px 18px; border-radius:8px; font-weight:800; font-size:1.05rem; display:inline-block;}
.bar-bg {background:#E5E7EB; border-radius:8px; height:14px; width:100%; margin:12px 0 4px 0;}
.bar-fg {height:14px; border-radius:8px;}
.stButton>button {width:100%; border-radius:10px; font-weight:600;}
.stButton>button[kind="primary"], .stButton>button[data-testid="stBaseButton-primary"] {background:linear-gradient(90deg,#7D2AE8,#00C4CC); border:none; color:#fff;}
div[data-testid="stMetricValue"] {color:#111827 !important; font-weight:700 !important;}
</style>
""", unsafe_allow_html=True)

STYLE = {
    "HIGH RISK": ("#EF4444", "⚠️", "Do NOT scan the QR code or click any link. Delete the message and report it as phishing."),
    "MEDIUM RISK": ("#F59E0B", "⚠️", "Be cautious. Verify the sender through an official channel before acting."),
    "LOW RISK": ("#10B981", "✅", "No strong threat signals found. Still avoid entering credentials via unexpected links."),
}

def level_of(score):
    return "HIGH RISK" if score >= 70 else "MEDIUM RISK" if score >= 40 else "LOW RISK"

def run_scan(data: bytes, name: str):
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(name).suffix or ".png") as f:
        f.write(data)
        path = f.name
    try:
        return analyze_image(path)
    finally:
        os.remove(path)

def all_findings(r):
    findings = []
    if r.get("text_reason"):
        findings.append(r["text_reason"])
    findings.extend(r.get("qr_reasons", []))
    return findings

def report_text(r, name):
    lines = [f"SPAM SHIELD AI - SCAN REPORT", f"File: {name}",
             f"Time: {datetime.now():%Y-%m-%d %H:%M:%S}",
             f"Verdict: {r['risk_level']} ({r['risk_score']}/100)", "", "Findings:"]
    lines += [f" - {x}" for x in all_findings(r)] or [" - none"]
    lines += ["", "QR payloads: " + (", ".join(r["qr_urls"]) or "none")]
    return "\n".join(lines)

def render_result(r, name):
    color, icon, advice = STYLE[r["risk_level"]]
    st.markdown(f"""
    <div class="cyber-card">
      <p style="color:#6B7280;margin:0;">Overall Threat Score</p>
      <h1 style="color:#111827;margin:0;font-size:3.8rem;line-height:1.1;">{r['risk_score']}<span style="font-size:1.4rem;color:#9CA3AF;">/100</span></h1>
      <div class="bar-bg"><div class="bar-fg" style="width:{r['risk_score']}%;background:{color};"></div></div>
      <span class="badge" style="background:{color};">{icon} {r['risk_level']}</span>
      <p style="color:#374151;margin:14px 0 0 0;"><b>Recommended action:</b> {advice}</p>
    </div>""", unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    c1.metric("Text Risk", f"{r.get('text_risk', 0)}%")
    c2.metric("QR Risk", f"{r.get('qr_risk', 0)}%")
    c3.metric("QR Codes Found", r.get("qr_codes_found", 0))

    st.markdown("#### 🔎 Why was this flagged?")
    findings = all_findings(r)
    if findings:
        for f in findings:
            (st.error if r["risk_score"] >= 70 else st.warning)(f)
    else:
        st.success("No suspicious indicators found.")

    with st.expander("🔗 Decoded QR payloads"):
        if r.get("qr_urls"):
            for u in r["qr_urls"]:
                st.code(u, language="text")
        else:
            st.write("None found.")
            
    with st.expander("📝 Raw OCR text"):
        st.text(r.get("ocr_text_preview", "(no text detected)"))
    
    st.download_button("⬇️ Download report", report_text(r, name), file_name="spamshield_report.txt")
    st.download_button("⬇️ Download JSON", json.dumps(r, indent=2), file_name="spamshield_report.json")


# ---------------- Header ----------------
st.markdown('<div class="title-text">Spam Shield AI</div>', unsafe_allow_html=True)
st.markdown('<p class="subtitle-text">Multimodal quishing &amp; image-spam detection: '
            'OCR + ML text analysis + QR payload and URL threat heuristics.</p>',
            unsafe_allow_html=True)

tab_scan, tab_url, tab_about = st.tabs(["🖼️ Image Scan", "🔗 URL Checker", "ℹ️ How it works"])

# ---------------- Image scan ----------------
with tab_scan:
    left, right = st.columns([1, 1.2], gap="large")
    with left:
        st.markdown("### 📥 Evidence Input")
        uploaded = st.file_uploader("Upload screenshot", type=["png", "jpg", "jpeg"],
                                    label_visibility="collapsed")
        
        data = name = None
        if uploaded:
            data, name = uploaded.getvalue(), uploaded.name
            
        if data:
            st.image(data, caption=name)
            clicked = st.button("🚀 Initiate Deep Scan", type="primary")
            if clicked:
                with st.spinner("Extracting text, decoding QR codes, scoring URLs..."):
                    try:
                        r = run_scan(data, name)
                    except Exception as e:
                        st.error(f"Scan failed: {e}")
                    else:
                        st.session_state.result = r
                        st.session_state.source = name
                        st.session_state.total_scans += 1
                        if r["risk_level"] == "HIGH RISK":
                            st.session_state.threats += 1
                        st.session_state.history.append({
                            "Time": datetime.now().strftime("%d %b %H:%M"), "File": name,
                            "Score": r["risk_score"], "Verdict": r["risk_level"]})
                        st.rerun()
    with right:
        r = st.session_state.result
        if r:
            st.markdown("### 🛡️ Threat Intelligence")
            render_result(r, st.session_state.source)
            if st.button("Clear results"):
                st.session_state.result = None
                st.rerun()
        else:
            st.markdown("""<div class="cyber-card" style="text-align:center;padding:60px 20px;border-style:dashed;border-color:#C4B5FD;">
              <h1 style="font-size:3rem;margin-bottom:8px;">📡</h1><h3 style="color:#374151;">Awaiting Input</h3>
              <p style="color:#6B7280;">Upload a screenshot to initiate the security analysis.</p></div>""",
                        unsafe_allow_html=True)
    if st.session_state.history:
        with st.expander("🕘 Scan history", expanded=False):
            st.dataframe(st.session_state.history[::-1])

# ---------------- URL checker ----------------
with tab_url:
    st.markdown("### Check a link or QR payload")
    url = st.text_input("Paste a URL")
    if url:
        s, why = score_url(url)
        color, icon, advice = STYLE[level_of(s)]
        st.markdown(f'<span class="badge" style="background:{color};">{icon} {level_of(s)} - {s}/100</span>',
                    unsafe_allow_html=True)
        for w in why:
            st.warning(w)
        if not why:
            st.success("No suspicious indicators found.")

# ---------------- About ----------------
with tab_about:
    st.markdown("""
### Problem
Email filters inspect text and links but largely ignore **images**. Attackers hide malicious QR codes
in screenshots/PDFs ("quishing") so the payload is never seen by text filters.

### Pipeline
1. **QR decoding** - OpenCV and Pyzbar.
2. **OCR** - Tesseract on the image.
3. **Text analysis** - Machine learning classifier + keyword rules.
4. **URL heuristics** - Scoring based on HTTP, IP addresses, risky TLDs, etc.
5. **Fusion** - Combining text and URL risk for a final score.
""")

# ---------------- Sidebar ----------------
with st.sidebar:
    st.markdown("<h2 style='text-align:center;'>📊 Your Dashboard</h2>", unsafe_allow_html=True)
    st.metric("Total Scans", st.session_state.total_scans)
    st.metric("Threats Blocked", st.session_state.threats)
    st.metric("Safe / Medium", st.session_state.total_scans - st.session_state.threats)
    st.markdown("---")
    if st.button("🗑️ Clear session history"):
        st.session_state.total_scans = st.session_state.threats = 0
        st.session_state.history, st.session_state.result = [], None
        st.rerun()