import streamlit as st
import requests
import difflib
import re
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Multi-Agent Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- SESSION STATE INIT ---
if "theme" not in st.session_state:
    st.session_state["theme"] = "dark"
if "audit_count" not in st.session_state:
    st.session_state["audit_count"] = 0
if "total_loc" not in st.session_state:
    st.session_state["total_loc"] = 0
if "has_run" not in st.session_state:
    st.session_state["has_run"] = False
if "last_result" not in st.session_state:
    st.session_state["last_result"] = None

def toggle_theme():
    st.session_state["theme"] = "light" if st.session_state["theme"] == "dark" else "dark"

# --- GITHUB CODE FETCHER LOGIC ---
def fetch_github_code(github_url: str) -> tuple[str, bool]:
    try:
        if "github.com" in github_url and "/blob/" in github_url:
            raw_url = github_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        elif "raw.githubusercontent.com" in github_url:
            raw_url = github_url
        else:
            return "Error: Invalid GitHub URL format. Provide a direct file URL (e.g., https://github.com/user/repo/blob/main/script.py)", False

        response = requests.get(raw_url, timeout=8)
        if response.status_code == 200:
            return response.text, True
        else:
            return f"Error: Unable to fetch file (HTTP {response.status_code}). Check repository visibility.", False
    except Exception as e:
        return f"Error connecting to GitHub: {str(e)}", False

# --- FINDINGS PARSER (turns bullet text into structured cards) ---
def parse_findings(raw_text: str) -> list[dict]:
    if not raw_text:
        return []
    findings = []
    severity_map = {
        "CRITICAL": "critical", "HIGH": "critical",
        "MEDIUM": "medium", "LOW": "low"
    }
    for line in raw_text.splitlines():
        line = line.strip().lstrip("-*•").strip()
        if not line:
            continue
        match = re.match(r"\[?(CRITICAL|HIGH|MEDIUM|LOW)\]?\s*[:\-]?\s*(.*)", line, re.IGNORECASE)
        if match:
            sev_raw = match.group(1).upper()
            text = match.group(2).strip()
            findings.append({"severity": severity_map.get(sev_raw, "medium"), "sev_label": sev_raw, "text": text})
        elif len(line) > 8:
            findings.append({"severity": "medium", "sev_label": "INFO", "text": line})
    return findings

def count_severity(findings: list[dict], sev: str) -> int:
    return sum(1 for f in findings if f["severity"] == sev)

# --- THEME COLORS ---
is_dark = st.session_state["theme"] == "dark"

bg_color = "#0d1117" if is_dark else "#ffffff"
card_bg = "#161b22" if is_dark else "#f6f8fa"
card_bg_alt = "#1c2128" if is_dark else "#eef1f4"
border_color = "#30363d" if is_dark else "#d0d7de"
text_primary = "#f0f6fc" if is_dark else "#1f2328"
text_secondary = "#8b949e" if is_dark else "#656d76"
accent_color = "#238636" if is_dark else "#1f883d"
accent_blue = "#58a6ff" if is_dark else "#0969da"
accent_purple = "#a371f7" if is_dark else "#8250df"
danger = "#f85149"
warning = "#d29922"
success = "#3fb950" if is_dark else "#1a7f37"

# --- GLOBAL CSS ---
st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* FIX: Hiding MainMenu and footer, but keeping header visible and transparent for the sidebar toggle */
    #MainMenu, footer, .stDeployButton {{ visibility: hidden; }}
    header {{ background-color: transparent !important; }}

    .stApp {{
        background-color: {bg_color};
        color: {text_primary};
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }}

    .stMarkdown p, .stRadio label p, .stTextInput label p, .stTextArea label p, h1, h2, h3, h4, h5, h6 {{
        color: {text_primary} !important;
    }}

    button[data-baseweb="tab"] div[data-testid="stMarkdownContainer"] p {{
        color: {text_secondary} !important;
        font-weight: 500 !important;
        opacity: 1 !important;
    }}
    button[data-baseweb="tab"][aria-selected="true"] div[data-testid="stMarkdownContainer"] p {{
        color: {accent_blue} !important;
        font-weight: 600 !important;
    }}
    button[data-baseweb="tab"][aria-selected="true"] {{
        border-bottom-color: {accent_blue} !important;
    }}

    [data-testid="stMetricValue"] {{ color: {text_primary} !important; }}
    [data-testid="stMetricLabel"] p {{ color: {text_secondary} !important; }}

    section[data-testid="stSidebar"] {{
        background-color: {card_bg} !important;
        border-right: 1px solid {border_color};
    }}
    section[data-testid="stSidebar"] .stMarkdown p {{
        color: {text_secondary} !important;
    }}

    /* --- HERO / HEADER --- */
    .hero-banner {{
        background: linear-gradient(135deg, {card_bg} 0%, {card_bg_alt} 100%);
        border: 1px solid {border_color};
        border-radius: 12px;
        padding: 28px 32px;
        margin-bottom: 20px;
    }}
    .title-text {{
        font-size: 2rem;
        font-weight: 800;
        color: {text_primary};
        letter-spacing: -0.03em;
        margin-bottom: 6px;
    }}
    .subtitle-text {{
        font-size: 0.98rem;
        color: {text_secondary};
        margin-bottom: 16px;
    }}

    .badge-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }}
    .badge-pill {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 0.76rem;
        font-weight: 600;
        padding: 5px 12px;
        border-radius: 999px;
        background: rgba(88, 166, 255, 0.12);
        color: {accent_blue};
        border: 1px solid rgba(88, 166, 255, 0.25);
        font-family: 'JetBrains Mono', monospace;
    }}
    .badge-pill.purple {{ background: rgba(163, 113, 247, 0.12); color: {accent_purple}; border-color: rgba(163, 113, 247, 0.25); }}
    .badge-pill.green {{ background: rgba(63, 185, 80, 0.12); color: {success}; border-color: rgba(63, 185, 80, 0.25); }}
    .badge-pill.orange {{ background: rgba(210, 153, 34, 0.12); color: {warning}; border-color: rgba(210, 153, 34, 0.25); }}

    /* --- STAT / METRIC CARDS --- */
    .stat-card {{
        background: {card_bg};
        border: 1px solid {border_color};
        border-radius: 10px;
        padding: 16px 18px;
        text-align: left;
    }}
    .stat-card .stat-value {{
        font-size: 1.6rem;
        font-weight: 700;
        color: {text_primary};
        font-family: 'JetBrains Mono', monospace;
    }}
    .stat-card .stat-label {{
        font-size: 0.78rem;
        color: {text_secondary};
        margin-top: 2px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }}

    /* --- FEATURE / EMPTY STATE CARDS --- */
    .feature-card {{
        background: {card_bg};
        border: 1px solid {border_color};
        border-radius: 10px;
        padding: 20px;
        height: 100%;
    }}
    .feature-card .feature-icon {{
        font-size: 1.6rem;
        margin-bottom: 10px;
    }}
    .feature-card .feature-title {{
        font-weight: 700;
        font-size: 0.98rem;
        color: {text_primary};
        margin-bottom: 6px;
    }}
    .feature-card .feature-desc {{
        font-size: 0.83rem;
        color: {text_secondary};
        line-height: 1.5;
    }}
    .chip-list {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }}
    .chip {{
        font-size: 0.72rem;
        padding: 3px 9px;
        border-radius: 6px;
        background: {card_bg_alt};
        border: 1px solid {border_color};
        color: {text_secondary};
        font-family: 'JetBrains Mono', monospace;
    }}

    /* --- SIDEBAR PIPELINE --- */
    .sidebar-section-title {{
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: {text_secondary};
        margin: 18px 0 8px 0;
    }}
    .pipeline-item {{
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 8px 10px;
        border-radius: 8px;
        margin-bottom: 6px;
        background: {bg_color};
        border: 1px solid {border_color};
    }}
    .pipeline-icon {{ font-size: 1rem; }}
    .pipeline-text {{ font-size: 0.8rem; font-weight: 500; color: {text_primary}; }}
    .pipeline-sub {{ font-size: 0.7rem; color: {text_secondary}; }}

    /* --- STEP BADGES (kept from original) --- */
    .step-badge {{
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 14px;
        background: {bg_color};
        border: 1px solid {border_color};
        border-radius: 6px;
        margin-bottom: 8px;
    }}
    .step-number {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        font-weight: 600;
        color: {accent_blue};
        background: rgba(88, 166, 255, 0.1);
        padding: 2px 8px;
        border-radius: 4px;
    }}
    .step-label {{ font-size: 0.88rem; font-weight: 500; color: {text_primary}; }}

    /* --- FINDINGS --- */
    .finding-box {{
        background: {card_bg};
        border: 1px solid {border_color};
        border-left: 4px solid {danger};
        border-radius: 8px;
        padding: 14px 16px;
        margin-bottom: 10px;
    }}
    .finding-box.medium {{ border-left-color: {warning}; }}
    .finding-box.low {{ border-left-color: {accent_blue}; }}
    .finding-sev {{
        display: inline-block;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        padding: 2px 8px;
        border-radius: 4px;
        margin-bottom: 6px;
        font-family: 'JetBrains Mono', monospace;
    }}
    .finding-sev.critical {{ background: rgba(248, 81, 73, 0.15); color: {danger}; }}
    .finding-sev.medium {{ background: rgba(210, 153, 34, 0.15); color: {warning}; }}
    .finding-sev.low {{ background: rgba(88, 166, 255, 0.15); color: {accent_blue}; }}
    .finding-desc {{ font-size: 0.85rem; color: {text_primary}; line-height: 1.45; }}

    .empty-panel {{
        border: 1px dashed {border_color};
        border-radius: 10px;
        padding: 40px 20px;
        text-align: center;
        color: {text_secondary};
        background: {card_bg};
    }}

    ::-webkit-input-placeholder {{ color: {text_secondary} !important; opacity: 0.7 !important; }}
    ::-moz-placeholder {{ color: {text_secondary} !important; opacity: 0.7 !important; }}
    :-ms-input-placeholder {{ color: {text_secondary} !important; opacity: 0.7 !important; }}

    .stTextArea textarea, .stTextInput input {{
        background-color: {bg_color} !important;
        color: {text_primary} !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.88rem !important;
        border: 1px solid {border_color} !important;
        border-radius: 6px !important;
    }}
    .stTextArea textarea:focus, .stTextInput input:focus {{
        border-color: {accent_blue} !important;
        box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.2) !important;
    }}

    .stButton button {{
        background-color: {accent_color} !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        border-radius: 6px !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        padding: 8px 16px !important;
        transition: opacity 0.2s ease !important;
    }}
    .stButton button:hover {{ opacity: 0.9 !important; }}
    </style>
""", unsafe_allow_html=True)

# =========================================================
# SIDEBAR
# =========================================================
with st.sidebar:
    st.markdown(f"""
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px;">
            <span style="font-size:1.6rem;">🛡️</span>
            <span style="font-weight:800; font-size:1.05rem; color:{text_primary};">SecAudit AI</span>
        </div>
        <div style="font-size:0.78rem; color:{text_secondary}; margin-bottom:6px;">
            Multi-Agent DevSecOps Pipeline
        </div>
    """, unsafe_allow_html=True)

    theme_btn_label = "☀️ Switch to Light" if is_dark else "🌙 Switch to Dark"
    st.button(theme_btn_label, on_click=toggle_theme, use_container_width=True)

    st.markdown('<div class="sidebar-section-title">Agent Pipeline</div>', unsafe_allow_html=True)
    pipeline_items = [
        ("🔎", "Security Auditor", "OWASP Top 10 · Injection · Secrets"),
        ("⚡", "Performance Lead", "Resource leaks · PEP8 · Complexity"),
        ("🛠️", "Patch Synthesizer", "Merges findings → clean patch"),
    ]
    for icon, name, sub in pipeline_items:
        st.markdown(f"""
            <div class="pipeline-item">
                <span class="pipeline-icon">{icon}</span>
                <div>
                    <div class="pipeline-text">{name}</div>
                    <div class="pipeline-sub">{sub}</div>
                </div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section-title">Tech Stack</div>', unsafe_allow_html=True)
    st.markdown(f"""
        <div class="chip-list">
            <span class="chip">CrewAI</span>
            <span class="chip">Groq LPU</span>
            <span class="chip">Llama-3.3-70B</span>
            <span class="chip">Streamlit</span>
            <span class="chip">Python 3.11</span>
        </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section-title">Session Stats</div>', unsafe_allow_html=True)
    sc1, sc2 = st.columns(2)
    with sc1:
        st.markdown(f"""
            <div class="stat-card">
                <div class="stat-value">{st.session_state['audit_count']}</div>
                <div class="stat-label">Audits Run</div>
            </div>
        """, unsafe_allow_html=True)
    with sc2:
        st.markdown(f"""
            <div class="stat-card">
                <div class="stat-value">{st.session_state['total_loc']}</div>
                <div class="stat-label">LOC Analyzed</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.caption("Built with CrewAI + Groq · Academic Project")

# =========================================================
# HEADER
# =========================================================
st.markdown(f"""
    <div class="hero-banner">
        <div class="title-text">🛡️ Multi-Agent DevSecOps Security Auditor</div>
        <div class="subtitle-text">Automated static analysis, OWASP vulnerability detection, and autonomous patch synthesis for Python codebases.</div>
        <div class="badge-row">
            <span class="badge-pill">⚡ Groq Inference</span>
            <span class="badge-pill purple">🦙 Llama-3.3-70B</span>
            <span class="badge-pill green">🤖 3-Agent Pipeline</span>
            <span class="badge-pill orange">🐍 Python SAST</span>
        </div>
    </div>
""", unsafe_allow_html=True)

# =========================================================
# INPUT SECTION
# =========================================================
default_code = """import sqlite3

def get_user_data(user_id):
    # VULNERABLE: Direct string concatenation allows SQL Injection
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(query)

    # BUG: Unclosed database connection handle
    return cursor.fetchall()
"""

if "source_code" not in st.session_state:
    st.session_state["source_code"] = default_code

input_col, pipeline_col = st.columns([1.8, 1.0], gap="large")

with input_col:
    st.markdown("##### 📥 1. Source Code Input")

    input_mode = st.radio(
        "Choose Input Method:",
        ["Paste Code Snippet", "Import from GitHub URL"],
        horizontal=True,
        label_visibility="collapsed"
    )

    if input_mode == "Import from GitHub URL":
        gh_url = st.text_input(
            "GitHub File Link:",
            placeholder="https://github.com/owner/repo/blob/main/path/to/script.py"
        )
        if st.button("📥 Fetch Code from GitHub"):
            if gh_url.strip():
                fetched_text, success = fetch_github_code(gh_url.strip())
                if success:
                    st.session_state["source_code"] = fetched_text
                    st.success("Successfully fetched file from GitHub!")
                else:
                    st.error(fetched_text)
            else:
                st.warning("Please enter a valid GitHub file URL.")

    source_code_input = st.text_area(
        "Code Editor",
        value=st.session_state["source_code"],
        height=280,
        label_visibility="collapsed"
    )
    st.session_state["source_code"] = source_code_input

    # Live code stats chips
    loc = len(source_code_input.splitlines())
    chars = len(source_code_input)
    est_tokens = max(1, chars // 4)
    st.markdown(f"""
        <div class="chip-list">
            <span class="chip">📄 {loc} lines</span>
            <span class="chip">🔤 {chars} chars</span>
            <span class="chip">🧮 ~{est_tokens} tokens</span>
        </div>
        <br>
    """, unsafe_allow_html=True)

    run_audit = st.button("⚡ Execute Multi-Agent Audit Workflow", use_container_width=True)

with pipeline_col:
    st.markdown("##### ⚙️ 2. Execution Pipeline")
    st.markdown(f"""
        <div class="feature-card" style="margin-bottom:12px;">
            <div class="step-badge">
                <span class="step-number">STEP 1</span>
                <span class="step-label">Security Vulnerability Scan</span>
            </div>
            <div class="step-badge">
                <span class="step-number">STEP 2</span>
                <span class="step-label">Performance & PEP8 Review</span>
            </div>
            <div class="step-badge">
                <span class="step-number">STEP 3</span>
                <span class="step-label">Patch Synthesis & Diff Generation</span>
            </div>
        </div>
    """, unsafe_allow_html=True)

    api_key_present = bool(os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY"))
    status_pill = '<span class="badge-pill green">🟢 Live LLM Mode</span>' if api_key_present else '<span class="badge-pill orange">🟠 Demo Mode</span>'
    st.markdown(f"""
        <div class="feature-card">
            <div class="feature-title">Connection Status</div>
            <div style="margin-top:6px;">{status_pill}</div>
            <div class="feature-desc" style="margin-top:8px;">
                {"Connected to Groq's OpenAI-compatible endpoint." if api_key_present else "No API key found — deterministic sample output will be used."}
            </div>
        </div>
    """, unsafe_allow_html=True)

# =========================================================
# EMPTY STATE (shown before first run in this session)
# =========================================================
if not run_audit and not st.session_state["has_run"]:
    st.markdown("---")
    st.markdown("##### 🧭 What This Tool Detects")
    e1, e2, e3 = st.columns(3, gap="medium")
    with e1:
        st.markdown(f"""
            <div class="feature-card">
                <div class="feature-icon">🔎</div>
                <div class="feature-title">Security Auditor</div>
                <div class="feature-desc">Flags OWASP Top 10 risks — injection flaws, hardcoded secrets, weak crypto, unsafe deserialization.</div>
                <div class="chip-list">
                    <span class="chip">SQLi</span><span class="chip">Cmd Injection</span><span class="chip">Weak Hash</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
    with e2:
        st.markdown(f"""
            <div class="feature-card">
                <div class="feature-icon">⚡</div>
                <div class="feature-title">Performance & Style Lead</div>
                <div class="feature-desc">Catches resource leaks, unclosed handles, PEP8 violations, and asymptotic bottlenecks.</div>
                <div class="chip-list">
                    <span class="chip">Leaks</span><span class="chip">PEP8</span><span class="chip">Big-O</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
    with e3:
        st.markdown(f"""
            <div class="feature-card">
                <div class="feature-icon">🛠️</div>
                <div class="feature-title">Patch Synthesizer</div>
                <div class="feature-desc">Merges all findings into one clean, production-ready rewrite — plus a unified git diff.</div>
                <div class="chip-list">
                    <span class="chip">Auto-Fix</span><span class="chip">Git Diff</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
        <div class="empty-panel">
            👆 Paste code or import from GitHub above, then click <b>Execute Multi-Agent Audit Workflow</b> to see results here.
        </div>
    """, unsafe_allow_html=True)

# =========================================================
# EXECUTION + RESULTS
# =========================================================
if run_audit:
    st.session_state["has_run"] = True
    st.session_state["audit_count"] += 1
    st.session_state["total_loc"] += loc

    st.markdown("---")
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")

    security_findings_text = ""
    performance_findings_text = ""

    with st.status("🚀 Running Multi-Agent Audit Pipeline...", expanded=True) as status:
        st.write("🔎 **Agent 1** — Security Auditor scanning for OWASP vulnerabilities...")

        if api_key:
            try:
                from src.crew_pipeline import run_crew_audit
                live_output = run_crew_audit(st.session_state["source_code"])
                remediated_code = live_output.get("remediated_code", "")
                security_findings_text = live_output.get("security_findings", "")
                performance_findings_text = live_output.get("performance_findings", "")
                st.write("✅ Agent 1 complete.")
                st.write("⚡ **Agent 2** — Performance & Style Lead reviewing code...")
                st.write("✅ Agent 2 complete.")
                st.write("🛠️ **Agent 3** — Patch Synthesizer generating remediated source...")
                st.write("✅ Agent 3 complete.")
            except Exception as e:
                st.write(f"⚠️ Live CrewAI execution skipped ({e}). Falling back to baseline analysis.")
                time.sleep(0.6)
                remediated_code = """import sqlite3

def get_user_data(user_id: str):
    \"\"\"
    Safely retrieves user records using parameterized queries
    to prevent SQL Injection vulnerabilities.
    \"\"\"
    query = "SELECT * FROM users WHERE id = ?"

    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute(query, (user_id,))
        return cursor.fetchall()
"""
                security_findings_text = (
                    "- [CRITICAL] SQL Injection in get_user_data() via string concatenation of user_id into the query.\n"
                    "- [MEDIUM] No input validation on user_id before use in database query."
                )
                performance_findings_text = (
                    "- [MEDIUM] Database connection opened without a context manager, risking connection leaks.\n"
                    "- [LOW] Function lacks type hints and docstring for maintainability."
                )
        else:
            st.write("🟠 No API key detected — running in Deterministic Demonstration Mode.")
            time.sleep(0.6)
            st.write("✅ Agent 1 complete (demo).")
            st.write("✅ Agent 2 complete (demo).")
            st.write("✅ Agent 3 complete (demo).")
            remediated_code = """import sqlite3

def get_user_data(user_id: str):
    \"\"\"
    Safely retrieves user records using parameterized queries
    to prevent SQL Injection vulnerabilities.
    \"\"\"
    query = "SELECT * FROM users WHERE id = ?"

    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute(query, (user_id,))
        return cursor.fetchall()
"""
            security_findings_text = (
                "- [CRITICAL] SQL Injection in get_user_data() via string concatenation of user_id into the query.\n"
                "- [MEDIUM] No input validation on user_id before use in database query."
            )
            performance_findings_text = (
                "- [MEDIUM] Database connection opened without a context manager, risking connection leaks.\n"
                "- [LOW] Function lacks type hints and docstring for maintainability."
            )

        status.update(label="✅ Audit Complete!", state="complete", expanded=False)

    # Generate Git Diff
    diff_lines = list(difflib.unified_diff(
        st.session_state["source_code"].splitlines(keepends=True),
        remediated_code.splitlines(keepends=True),
        fromfile='a/vulnerable_source.py',
        tofile='b/remediated_source.py'
    ))
    diff_text = "".join(diff_lines)
    additions = sum(1 for l in diff_lines if l.startswith('+') and not l.startswith('+++'))
    deletions = sum(1 for l in diff_lines if l.startswith('-') and not l.startswith('---'))

    security_findings = parse_findings(security_findings_text)
    performance_findings = parse_findings(performance_findings_text)
    all_findings = security_findings + performance_findings

    critical_count = count_severity(all_findings, "critical")
    medium_count = count_severity(all_findings, "medium")
    low_count = count_severity(all_findings, "low")
    total_findings = len(all_findings)
    risk_score = max(0, 100 - (critical_count * 25 + medium_count * 10 + low_count * 3))

    st.markdown("#### 📊 Audit Analysis & Remediation Results")

    # --- SUMMARY STAT ROW ---
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{total_findings}</div><div class="stat-label">Total Findings</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="stat-card"><div class="stat-value" style="color:{danger};">{critical_count}</div><div class="stat-label">Critical</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="stat-card"><div class="stat-value" style="color:{warning};">{medium_count}</div><div class="stat-label">Medium</div></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="stat-card"><div class="stat-value">+{additions} / -{deletions}</div><div class="stat-label">Lines Changed</div></div>', unsafe_allow_html=True)
    with m5:
        risk_color = success if risk_score >= 70 else (warning if risk_score >= 40 else danger)
        st.markdown(f'<div class="stat-card"><div class="stat-value" style="color:{risk_color};">{risk_score}/100</div><div class="stat-label">Security Score</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs([
        "✨ Refactored Code",
        "🔍 Unified Git Diff",
        "🛡️ Vulnerability Findings",
        "⚡ Code Health & Metrics"
    ])

    with tab1:
        st.code(remediated_code, language="python")

    with tab2:
        st.code(diff_text if diff_text else "# No changes required.", language="diff")

    with tab3:
        fc1, fc2 = st.columns(2, gap="large")
        with fc1:
            st.markdown(f"###### 🔎 Security Findings ({len(security_findings)})")
            if security_findings:
                for f in security_findings:
                    st.markdown(f"""
                        <div class="finding-box {f['severity']}">
                            <span class="finding-sev {f['severity']}">{f['sev_label']}</span>
                            <div class="finding-desc">{f['text']}</div>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No security findings reported.")
        with fc2:
            st.markdown(f"###### ⚡ Performance / PEP8 Findings ({len(performance_findings)})")
            if performance_findings:
                for f in performance_findings:
                    st.markdown(f"""
                        <div class="finding-box {f['severity']}">
                            <span class="finding-sev {f['severity']}">{f['sev_label']}</span>
                            <div class="finding-desc">{f['text']}</div>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No performance findings reported.")

    with tab4:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric(label="Original LOC", value=f"{len(st.session_state['source_code'].splitlines())}")
        with c2:
            st.metric(label="Refactored LOC", value=f"{len(remediated_code.splitlines())}")
        with c3:
            st.metric(label="Lines Added", value=f"+{additions}")
        with c4:
            st.metric(label="Lines Removed", value=f"-{deletions}")

        st.markdown("<br>", unsafe_allow_html=True)
        st.progress(risk_score / 100, text=f"Security Score: {risk_score}/100")
