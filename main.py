"""
DPDP Compliance Scanner — Unified Streamlit Interface
======================================================
Provides a complete dark-themed dashboard matching organizational specs.
Handles bulk folder input, custom ad-hoc sandboxing, and interactive inline 
document decryption/purging.
"""
import os
import io
import json
import sys
import shutil
import subprocess
import pypdf
import msoffcrypto
import pandas as pd
from pathlib import Path
from datetime import datetime
import streamlit as st

# ── PAGE CONFIGURATION ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DPDP Compliance Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── ENTERPRISE DARK CSS (MATCHING UI WIREFRAMES) ──────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background-color: #0d1117; color: #e6edf3; }
[data-testid="stSidebar"] { background-color: #161b22 !important; border-right: 1px solid #30363d; }
[data-testid="stSidebar"] * { color: #e6edf3 !important; }

/* Main Header Layout */
.app-header {
    background: linear-gradient(135deg, #1a2332 0%, #0d1117 50%, #1a1a2e 100%);
    border: 1px solid #30363d; border-radius: 12px;
    padding: 28px 36px; margin-bottom: 28px; position: relative; overflow: hidden;
}
.app-header::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, #f78166, #ff7b72, #ffa657, #3fb950);
}
.app-header h1 { font-size: 1.75rem; font-weight: 700; color: #e6edf3; margin: 0 0 6px 0; letter-spacing: -0.5px; }
.app-header p  { font-size: 0.88rem; color: #8b949e; margin: 0; }
.header-badge {
    display: inline-block; background: rgba(63,185,80,0.15);
    border: 1px solid rgba(63,185,80,0.4); color: #3fb950;
    font-size: 0.72rem; font-weight: 600; padding: 3px 10px;
    border-radius: 20px; letter-spacing: 0.5px; text-transform: uppercase; margin-top: 10px;
}

/* Section Controls */
.section-title {
    font-size: 0.78rem; font-weight: 600; color: #8b949e;
    text-transform: uppercase; letter-spacing: 1.2px;
    margin: 24px 0 12px 0; padding-bottom: 8px; border-bottom: 1px solid #21262d;
}

/* Operational Metric Grid */
.metric-card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 18px 20px; text-align: center; }
.metric-card .val { font-size: 2rem; font-weight: 700; line-height: 1; margin-bottom: 4px; }
.metric-card .lbl { font-size: 0.76rem; color: #8b949e; font-weight: 500; text-transform: uppercase; letter-spacing: 0.8px; }
.metric-card.red .val   { color: #ff7b72; }
.metric-card.amber .val { color: #ffa657; }
.metric-card.green .val { color: #3fb950; }
.metric-card.blue .val  { color: #79c0ff; }

/* Status Badges & Tags */
.violation-pill {
    display: inline-block; background: rgba(255,123,114,0.12);
    border: 1px solid rgba(255,123,114,0.35); color: #ff7b72;
    font-size: 0.74rem; font-weight: 500; padding: 3px 10px;
    border-radius: 20px; margin: 2px 3px 2px 0; font-family: 'JetBrains Mono', monospace;
}
.status-badge {
    display: inline-block; font-size: 0.72rem; font-weight: 600;
    padding: 2px 9px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.5px;
}
.status-badge.flagged { background: rgba(255,123,114,0.15); color: #ff7b72; border: 1px solid rgba(255,123,114,0.3); }
.status-badge.clean   { background: rgba(63,185,80,0.15);   color: #3fb950; border: 1px solid rgba(63,185,80,0.3);   }
.status-badge.error   { background: rgba(255,166,87,0.15);  color: #ffa657; border: 1px solid rgba(255,166,87,0.3);  }

.rule { border: none; border-top: 1px solid #21262d; margin: 24px 0; }
.log-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
.log-table th {
    background: #21262d; color: #8b949e; font-weight: 600; font-size: 0.74rem;
    padding: 10px 14px; text-align: left; border-bottom: 1px solid #30363d;
}
.log-table td { padding: 10px 14px; border-bottom: 1px solid #21262d; color: #e6edf3; }

/* Custom Form Buttons UI overrides */
.stButton > button {
    background: #21262d; color: #e6edf3; border: 1px solid #30363d;
    border-radius: 8px; font-size: 0.82rem; font-weight: 500; transition: all 0.15s ease;
}
.stButton > button:hover { background: #30363d; border-color: #8b949e; color: #ffffff; }
button[kind="primary"] { background: #238636 !important; border-color: #2ea043 !important; color: #ffffff !important; }
.purge-btn button {
    background: rgba(255,123,114,0.1) !important; border: 1px solid rgba(255,123,114,0.4) !important;
    color: #ff7b72 !important; font-size: 0.78rem !important; padding: 4px 14px !important; border-radius: 6px !important;
}
.purge-btn button:hover { background: rgba(255,123,114,0.25) !important; border-color: #ff7b72 !important; }
</style>
""", unsafe_allow_html=True)

# ── PERSISTENT RUNTIME STATE ──────────────────────────────────────────────────
DEFAULT_REPORT = Path("report.json")

if "report_data" not in st.session_state:
    st.session_state.report_data = None
if "report_path" not in st.session_state:
    st.session_state.report_path = str(DEFAULT_REPORT)
if "quarantine_dir" not in st.session_state:
    st.session_state.quarantine_dir = str(Path("quarantine").resolve())

# ── COMPLIANCE REPORT CONTROLLERS ──────────────────────────────────────────────
def load_report(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {
            "meta": {
                "scan_root": "No directory scanned yet",
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_files": 0,
                "flagged": 0,
                "clean": 0,
                "errors": 0,
                "pii_hits": 0,
            },
            "entries": []
        }
    try:
        with open(p) as f:
            data = json.load(f)
            if not data or not isinstance(data, dict):
                raise ValueError("Malformed report structure")
            return data
    except Exception as e:
        return {
            "meta": {
                "scan_root": "Error loading logs (Corrupted file)",
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_files": 0,
                "flagged": 0,
                "clean": 0,
                "errors": 0,
                "pii_hits": 0,
            },
            "entries": []
        }

def save_report_state() -> None:
    with open(st.session_state.report_path, "w") as f:
        json.dump(st.session_state.report_data, f, indent=2)

def recalculate_meta_metrics() -> None:
    if not st.session_state.report_data:
        return
    entries = st.session_state.report_data["entries"]
    flagged = [e for e in entries if e["flagged"]]
    errors  = [e for e in entries if e["error"]]
    
    st.session_state.report_data["meta"]["total_files"] = len(entries)
    st.session_state.report_data["meta"]["flagged"]     = len(flagged)
    st.session_state.report_data["meta"]["errors"]      = len(errors)
    st.session_state.report_data["meta"]["clean"]       = len(entries) - len(flagged) - len(errors)
    st.session_state.report_data["meta"]["pii_hits"]    = sum(
        sum(e["violations"].values()) for e in entries
    )
    save_report_state()

def pills_html(violations: dict[str, int]) -> str:
    parts = []
    for cat, cnt in violations.items():
        parts.append(f'<span class="violation-pill">{cat} ({cnt} found)</span>')
    return " ".join(parts)

# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR MANAGEMENT (BULK RECURSIVE SYSTEM WORKSPACE RUNNER)
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("### 🛡️ Enterprise Control Panel")
    st.markdown("<div style='height:1px;background:#30363d;margin:8px 0 16px'></div>", unsafe_allow_html=True)

    st.markdown("📂 **Scan Local System Directory**")
    local_dir = st.text_input("Enter absolute folder path:", placeholder="e.g., C:/Users/Documents/TargetFolder")
    global_pwd = st.text_input("Vault Decryption Master Passphrase:", type="password", placeholder="Optional global key")
    workers = st.slider("Parallel Worker Threads", min_value=1, max_value=16, value=4)
    resume_mode = st.checkbox("Resume Scan (Skip unchanged files)", value=True,
                               help="Re-scanning a large fileset only processes new/modified files.")
    enable_ocr = st.checkbox("Enable OCR (scanned PDFs & images)", value=True,
                              help="Requires Tesseract OCR installed locally. Slower but catches PII in photographed/scanned documents.")
    max_size_mb = st.number_input("Skip files larger than (MB)", min_value=1, value=300, step=50)

    if st.button("🚀 Execute Live System Scan", use_container_width=True, type="primary"):
        if not local_dir or not os.path.isdir(local_dir):
            st.error("Invalid target local directory. Please verify absolute structural path path configuration.")
        else:
            cmd = [
                sys.executable, "scan_cli.py", local_dir,
                "--workers", str(workers),
                "--output", st.session_state.report_path,
                "--max-size-mb", str(max_size_mb),
                "--progress",
            ]
            if resume_mode:
                cmd.append("--resume")
            if not enable_ocr:
                cmd.append("--no-ocr")
            if global_pwd:
                cmd.extend(["--password", global_pwd])

            progress_bar = st.progress(0, text="Starting scan…")
            status_line = st.empty()
            final_report = None
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, bufsize=1)
            total = 1
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if msg["type"] == "start":
                    total = max(msg["total"], 1)
                    status_line.markdown(f"Scanning {total} files ({msg['to_scan']} new/changed)…")
                elif msg["type"] == "progress":
                    pct = min(msg["done"] / total, 1.0)
                    progress_bar.progress(pct, text=f"{msg['done']}/{total} — {msg['filename']}")
                elif msg["type"] == "final":
                    final_report = msg["report"]
            proc.wait()

            if proc.returncode == 0 and final_report:
                progress_bar.progress(1.0, text="Scan complete.")
                st.success("Infrastructure execution complete.")
                st.session_state.report_data = final_report
                st.rerun()
            else:
                stderr = proc.stderr.read()
                st.error(f"Execution Error: {stderr or 'scan process exited with an error.'}")

    st.markdown("<div style='height:1px;background:#30363d;margin:16px 0'></div>", unsafe_allow_html=True)
    st.markdown("**Historical Synchronization**")
    report_path_input = st.text_input("Report JSON log destination target", value=st.session_state.report_path)

    if st.button("🔄 Sync & Sync Log Records", use_container_width=True):
        data = load_report(report_path_input)
        if data:
            st.session_state.report_data = data
            st.session_state.report_path = report_path_input
            st.rerun()
        else:
            st.error("Report ledger mapping targeted file target path invalid.")

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.markdown("**Purge Safety**")
    st.session_state.quarantine_dir = st.text_input(
        "Quarantine folder (purge moves files here instead of deleting)",
        value=st.session_state.quarantine_dir,
    )

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.caption("India DPDP Act, 2023 · Infrastructure Compliance Audit Matrix")

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN RENDER WORKSPACE
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="app-header">
    <h1>🛡️ DPDP Compliance Scanner</h1>
    <p>View PII scan results, audit flagged documents, and purge non-compliant files from the local storage systems.</p>
    <div class="header-badge">Enterprise Compliance Infrastructure Tool</div>
</div>
""", unsafe_allow_html=True)

# ── 1. INSTANT AD-HOC SANDBOX VERIFICATION (DRAG AND DROP ASSIGNMENT) ──────────
st.markdown('<div class="section-title">⚡ Instant Ad-Hoc Sandbox Verification</div>', unsafe_allow_html=True)
uploaded_files = st.file_uploader(
    "Drag and drop standalone files here to quickly verify content outside tracking logs",
    accept_multiple_files=True,
    type=["pdf", "docx", "xlsx", "pptx", "csv", "txt", "json", "xml", "html", "htm",
          "eml", "msg", "png", "jpg", "jpeg", "tif", "tiff", "bmp"],
)

if uploaded_files:
    from scan_cli import scan_file
    st.info(f"Loaded {len(uploaded_files)} ad-hoc files into temporary browser context validation matrix.")
    
    for f in uploaded_files:
        temp_path = Path(f.name)
        temp_path.write_bytes(f.read())
        
        # Determine encryption state immediately pre-flight
        is_encrypted = False
        if temp_path.suffix.lower() == ".pdf":
            try:
                with open(temp_path, "rb") as pf:
                    is_encrypted = pypdf.PdfReader(pf).is_encrypted
            except: pass
        elif temp_path.suffix.lower() in {".docx", ".xlsx"}:
            try:
                with open(temp_path, "rb") as mf:
                    is_encrypted = msoffcrypto.OfficeFile(mf).is_encrypted()
            except: pass

        # Get the password from the user if it's encrypted
        pwd = ""
        if is_encrypted:
            pwd = st.text_input(f"🔑 '{f.name}' requires a decryption key to compile validation matches:", type="password", key=f"sandbox_pwd_{f.name}")
            if not pwd:
                st.warning(f"Decryption execution halted for {f.name} until valid verification passphrase is contextually defined.")
                if temp_path.exists(): os.remove(temp_path)
                continue

        try:
            res = scan_file(temp_path, password=pwd)
            
            c_a, c_b = st.columns([6, 4])
            with c_a:
                st.markdown(f"**{f.name}**")
            with c_b:
                if res["error"] and "PasswordIncorrect" in str(res["error"]):
                    st.error("❌ Decryption failed: Incorrect Password provided.")
                elif res["error"]:
                    st.error(f"Extraction Blocked: {res['error']}")
                elif res["flagged"]:
                    st.markdown(pills_html(res["violations"]), unsafe_allow_html=True)
                else:
                    st.markdown("<span class='status-badge clean'>Clean</span>", unsafe_allow_html=True)
        finally:
            if temp_path.exists(): os.remove(temp_path)

# ── 2. METRIC VISUALIZATION OVERLAY AND TRACKED PURGE INFRASTRUCTURE ──────────
if st.session_state.report_data is None:
    st.session_state.report_data = load_report(st.session_state.report_path)

if st.session_state.report_data is None:
    st.markdown("""
    <div style='text-align:center;padding:60px 20px;color:#484f58'>
        <div style='font-size:3rem;margin-bottom:16px'>📂</div>
        <div style='font-size:1rem;font-weight:600;color:#8b949e;margin-bottom:8px'>No active compliance scanning records synced</div>
        <div style='font-size:0.84rem;'>Input your local absolute file system path directory in the sidebar panel to build data frames.</div>
    </div>""", unsafe_allow_html=True)
    st.stop()

report = st.session_state.report_data
meta   = report.get("meta", {})
entries = report.get("entries", [])

st.markdown(
    f"<p style='font-size:0.78rem;color:#8b949e;margin-bottom:12px'>"
    f"📁 Target Environment Root: <code>{meta.get('scan_root','?')}</code> &nbsp;·&nbsp; "
    f"Execution Timeframe: {meta.get('generated_at','?')}</p>",
    unsafe_allow_html=True,
)

# 5 Columns Performance Grid
c1, c2, c3, c4, c5 = st.columns(5)
c1.markdown(f'<div class="metric-card blue"><div class="val">{meta.get("total_files")}</div><div class="lbl">Files Scanned</div></div>', unsafe_allow_html=True)
c2.markdown(f'<div class="metric-card red"><div class="val">{meta.get("flagged")}</div><div class="lbl">Flagged Files</div></div>', unsafe_allow_html=True)
c3.markdown(f'<div class="metric-card green"><div class="val">{meta.get("clean")}</div><div class="lbl">Clean Files</div></div>', unsafe_allow_html=True)
c4.markdown(f'<div class="metric-card amber"><div class="val">{meta.get("errors")}</div><div class="lbl">Scan Errors</div></div>', unsafe_allow_html=True)
c5.markdown(f'<div class="metric-card red"><div class="val">{meta.get("pii_hits")}</div><div class="lbl">PII Hits</div></div>', unsafe_allow_html=True)

# Report export controls
dl1, dl2, dl3, _ = st.columns([1, 1, 1, 5])
dl1.download_button("⬇️ JSON", data=json.dumps(report, indent=2),
                     file_name="dpdp_report.json", mime="application/json", use_container_width=True)

csv_rows = []
for e in entries:
    csv_rows.append({
        "filename": e["filename"], "abs_path": e["abs_path"], "status":
            "Error" if e["error"] else ("Flagged" if e["flagged"] else "Clean"),
        "violations": "; ".join(f"{k}: {v}" for k, v in e["violations"].items()),
        "error": e["error"] or "", "size_mb": e["size_mb"], "scanned_at": e["scanned_at"],
    })
csv_df = pd.DataFrame(csv_rows)
dl2.download_button("⬇️ CSV", data=csv_df.to_csv(index=False),
                     file_name="dpdp_report.csv", mime="text/csv", use_container_width=True)

xlsx_buf = io.BytesIO()
with pd.ExcelWriter(xlsx_buf, engine="openpyxl") as writer:
    csv_df.to_excel(writer, index=False, sheet_name="Audit Matrix")
    pd.DataFrame([meta]).to_excel(writer, index=False, sheet_name="Summary")
dl3.download_button("⬇️ Excel", data=xlsx_buf.getvalue(), file_name="dpdp_report.xlsx",
                     mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     use_container_width=True)

# Filter targets matching standard PII violations or conversion blocks caused by encryption mismatches
flagged_entries = [
    e for e in entries 
    if e["flagged"] or (e["error"] and ("Password" in str(e["error"]) or "PDFPasswordIncorrect" in str(e["error"])))
]

if flagged_entries:
    st.markdown('<div class="section-title">🚨 Flagged Files — Purge Dashboard</div>', unsafe_allow_html=True)
    
    for entry in flagged_entries:
        col_name, col_path, col_v, col_act = st.columns([3, 4, 3, 1.2])
        is_crypto_err = entry["error"] and ("Password" in str(entry["error"]) or "PDFPasswordIncorrect" in str(entry["error"]))
        
        with col_name:
            st.markdown(f"**{entry['filename']}**", unsafe_allow_html=True)
            if is_crypto_err:
                st.markdown("<span class='status-badge error'>🔒 Encrypted</span>", unsafe_allow_html=True)
            else:
                st.markdown("<span class='status-badge flagged'>Flagged</span>", unsafe_allow_html=True)
                
        with col_path:
            st.code(entry["abs_path"], language=None)
            
        with col_v:
            if is_crypto_err:
                st.markdown("<span style='color:#ffa657; font-size:0.82rem;'>⚠️ File conversion failed: Incorrect or missing password.</span>", unsafe_allow_html=True)
                
                # Interactive password re-evaluation input frame
                retry_password = st.text_input(
                    "Enter correct document password:", 
                    type="password", 
                    key=f"retry_pwd_{entry['abs_path']}",
                    label_visibility="collapsed",
                    placeholder="Type document password..."
                )
                
                if retry_password:
                    if st.button("🔓 Decrypt & Re-scan", key=f"btn_retry_{entry['abs_path']}"):
                        with st.spinner("Re-evaluating document integrity metrics..."):
                            from scan_cli import scan_file
                            updated_res = scan_file(Path(entry["abs_path"]), password=retry_password)
                            
                            if not updated_res["error"]:
                                for idx, target in enumerate(st.session_state.report_data["entries"]):
                                    if target["abs_path"] == entry["abs_path"]:
                                        st.session_state.report_data["entries"][idx] = updated_res
                                        
                                recalculate_meta_metrics()
                                st.toast(f"Successfully decrypted and verified {entry['filename']}!", icon="🔓")
                                st.rerun()
                            else:
                                st.error("Decryption failed. Please verify target key credentials.")
            else:
                st.markdown(pills_html(entry["violations"]), unsafe_allow_html=True)
                
        with col_act:
            st.markdown("<div class='purge-btn'>", unsafe_allow_html=True)
            if st.button("🗑️ Quarantine", key=f"purge_{entry['abs_path']}"):
                src = Path(entry["abs_path"])
                if src.exists():
                    try:
                        qdir = Path(st.session_state.quarantine_dir)
                        qdir.mkdir(parents=True, exist_ok=True)
                        dest = qdir / src.name
                        if dest.exists():
                            dest = qdir / f"{src.stem}_{datetime.now().strftime('%Y%m%d%H%M%S')}{src.suffix}"
                        shutil.move(str(src), str(dest))
                    except Exception as ex:
                        st.error(f"OS Blocked Action: {ex}")

                # Strip file reference row configuration from log records
                st.session_state.report_data["entries"] = [
                    item for item in st.session_state.report_data["entries"] if item["abs_path"] != entry["abs_path"]
                ]
                recalculate_meta_metrics()
                st.toast("File moved to quarantine (not permanently deleted).")
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
            
        st.markdown("<div class='rule' style='margin:12px 0;'></div>", unsafe_allow_html=True)
else:
    st.success("✅ Clean Infrastructure Matrix: All evaluated entities comply with standard processing parameters.")

# Complete Environment Matrix Table View
with st.expander(f"📋 Full Infrastructure Audit Matrix ({len(entries)} tracked items)", expanded=False):
    search_q = st.text_input("🔍 Filter by filename, path, or violation type", key="audit_search")
    status_filter = st.selectbox("Status", ["All", "Flagged", "Clean", "Error"], key="audit_status_filter")

    filtered_entries = entries
    if search_q:
        q = search_q.lower()
        filtered_entries = [
            e for e in filtered_entries
            if q in e["filename"].lower() or q in e["abs_path"].lower()
            or any(q in v.lower() for v in e["violations"].keys())
        ]
    if status_filter != "All":
        filtered_entries = [
            e for e in filtered_entries
            if (status_filter == "Error" and e["error"])
            or (status_filter == "Flagged" and e["flagged"])
            or (status_filter == "Clean" and not e["flagged"] and not e["error"])
        ]

    rows_html = ""
    for e in filtered_entries:
        if e["error"]:
            status = "<span class='status-badge error'>Error</span>"
            summary = f"<span style='color:#ffa657'>{e['error']}</span>"
        elif e["flagged"]:
            status = "<span class='status-badge flagged'>Flagged</span>"
            summary = pills_html(e["violations"])
        else:
            status = "<span class='status-badge clean'>Clean</span>"
            summary = "<span style='color:#3fb950'>No violations mapped</span>"
            
        rows_html += f"<tr><td>{e['filename']}</td><td><code>{e['abs_path']}</code></td><td>{status}</td><td>{summary}</td></tr>"
        
    st.markdown(
        f"<table class='log-table'><thead><tr><th>Target Resource</th><th>Absolute System Path</th><th>Status</th><th>Notes Summary Framework</th></tr></thead>"
        f"<tbody>{rows_html}</tbody></table>", 
        unsafe_allow_html=True
    )