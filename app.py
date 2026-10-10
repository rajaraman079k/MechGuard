import streamlit as st
import pandas as pd
import sqlite3
import json
import hashlib
import hmac
import secrets
from datetime import datetime
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "mechguard_history.db"

st.set_page_config(page_title="MechGuard AI | Maintenance Intelligence", page_icon="⚙️", layout="wide", initial_sidebar_state="collapsed")

# Educational demo thresholds only. Not real-world safety limits.
TEMP_WARN, TEMP_CRIT = 75.0, 90.0
VIB_WARN, VIB_CRIT = 4.5, 7.1
SERVICE_HOURS = 1000

# ---------- Database / local accounts ----------
def db():
    return sqlite3.connect(DB_PATH)

def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY COLLATE NOCASE,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            machine TEXT NOT NULL,
            temperature REAL NOT NULL,
            vibration REAL NOT NULL,
            operating_hours INTEGER NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            summary TEXT NOT NULL,
            action_plan TEXT NOT NULL,
            trace_json TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT 'local'
        )""")
        # Upgrade databases created by earlier MechGuard versions.
        cols = [r[1] for r in conn.execute("PRAGMA table_info(assessments)").fetchall()]
        if "username" not in cols:
            conn.execute("ALTER TABLE assessments ADD COLUMN username TEXT NOT NULL DEFAULT 'local'")

def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000)
    return salt.hex(), hashed.hex()

def register_user(username, password):
    username = username.strip()
    if len(username) < 3 or len(username) > 24:
        return False, "Username must be 3–24 characters."
    if not all(c.isalnum() or c in "_-." for c in username):
        return False, "Use only letters, numbers, dots, underscores, or hyphens."
    if len(password) < 8:
        return False, "Password must contain at least 8 characters."
    salt, digest = hash_password(password)
    try:
        with db() as conn:
            conn.execute("INSERT INTO users(username,salt,password_hash,created_at) VALUES(?,?,?,?)",
                         (username, salt, digest, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        return True, "Account created. You can now sign in."
    except sqlite3.IntegrityError:
        return False, "That username already exists."

def verify_user(username, password):
    with db() as conn:
        row = conn.execute("SELECT username,salt,password_hash FROM users WHERE username = ? COLLATE NOCASE",
                           (username.strip(),)).fetchone()
    if not row:
        return False
    salt, expected = row[1], row[2]
    _, actual = hash_password(password, salt)
    return hmac.compare_digest(actual, expected)

def save_assessment(report, username):
    with db() as conn:
        conn.execute("""
        INSERT INTO assessments
        (timestamp,machine,temperature,vibration,operating_hours,severity,risk_score,summary,action_plan,trace_json,username)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (report["timestamp"], report["machine"], report["temperature"], report["vibration"],
              report["hours"], report["severity"], report["risk_score"], report["summary"],
              report["action_plan"], json.dumps(report["trace"]), username))

def load_history(username, machine=None, limit=1000):
    with db() as conn:
        if machine and machine != "All machines":
            return pd.read_sql_query(
                "SELECT * FROM assessments WHERE username = ? AND machine = ? ORDER BY id DESC LIMIT ?",
                conn, params=(username, machine, limit))
        return pd.read_sql_query(
            "SELECT * FROM assessments WHERE username = ? ORDER BY id DESC LIMIT ?",
            conn, params=(username, limit))

init_db()

# ---------- Diagnostic tools ----------
def thermal_tool(temp):
    if temp >= TEMP_CRIT:
        status, score = "CRITICAL", 3
        finding = f"{temp:.1f} °C meets/exceeds the demo critical threshold ({TEMP_CRIT:.0f} °C)."
        action = "Have qualified personnel assess cooling, lubrication, and operating load before restart."
    elif temp >= TEMP_WARN:
        status, score = "WARNING", 2
        finding = f"{temp:.1f} °C is in the demo warning band."
        action = "Inspect cooling airflow, lubrication, and operating load."
    else:
        status, score = "NORMAL", 0
        finding = f"{temp:.1f} °C is below the demo warning threshold."
        action = "Continue routine monitoring."
    return {"tool":"Thermal analysis", "status":status, "score":score, "finding":finding, "action":action}

def vibration_tool(vibration):
    if vibration >= VIB_CRIT:
        status, score = "CRITICAL", 3
        finding = f"{vibration:.1f} mm/s RMS meets/exceeds the demo critical threshold ({VIB_CRIT:.1f})."
        action = "Inspect for imbalance, looseness, misalignment, and bearing issues."
    elif vibration >= VIB_WARN:
        status, score = "WARNING", 2
        finding = f"{vibration:.1f} mm/s RMS is in the demo warning band."
        action = "Check mounting bolts, alignment, imbalance, and bearing condition."
    else:
        status, score = "NORMAL", 0
        finding = f"{vibration:.1f} mm/s RMS is below the demo warning threshold."
        action = "Continue routine vibration trending."
    return {"tool":"Vibration analysis", "status":status, "score":score, "finding":finding, "action":action}

def usage_tool(hours):
    if hours >= SERVICE_HOURS:
        status, score = "SERVICE DUE", 1
        finding = f"{hours:,} operating hours meets/exceeds the demo service interval."
        action = "Review the service log and schedule maintenance specified by the manufacturer."
    else:
        status, score = "NORMAL", 0
        finding = f"{hours:,} operating hours is below the demo service interval."
        action = "Continue tracking usage against the manufacturer's maintenance schedule."
    return {"tool":"Usage/service analysis", "status":status, "score":score, "finding":finding, "action":action}

def run_agent(machine, temp, vibration, hours, historical_context=None):
    """Run an explainable, deterministic tool-using agent with adaptive replanning.

    This is agentic workflow logic, not an LLM or trained prediction model.
    The planner selects tools from the current evidence, evaluates findings,
    and can add cross-checks when the first pass reveals a reason to investigate.
    """
    historical_context = historical_context or {}
    trace = ["GOAL: Assess machine condition and produce an evidence-based maintenance plan."]
    tools = {
        "thermal_tool": lambda: thermal_tool(temp),
        "vibration_tool": lambda: vibration_tool(vibration),
        "usage_tool": lambda: usage_tool(hours),
    }
    selected = []

    # Initial plan: choose tools from current sensor values and remembered trends.
    if temp >= TEMP_WARN or historical_context.get("temperature_rising"):
        selected.append("thermal_tool")
        trace.append("PLAN: Select thermal analysis because temperature is elevated or rising against history.")
    if vibration >= VIB_WARN or historical_context.get("vibration_rising"):
        selected.append("vibration_tool")
        trace.append("PLAN: Select vibration analysis because vibration is elevated or rising against history.")
    if hours >= SERVICE_HOURS:
        selected.append("usage_tool")
        trace.append("PLAN: Select service analysis because the demo service interval has been reached.")

    if not selected:
        selected = ["thermal_tool", "vibration_tool"]
        trace.append("PLAN: No trigger found; run thermal and vibration baseline checks. Skip service analysis because its interval is not due.")

    results_by_tool = {}

    def execute(tool_name, reason):
        if tool_name in results_by_tool:
            return
        result = tools[tool_name]()
        results_by_tool[tool_name] = result
        trace.append(f"TOOL: {result['tool']} returned {result['status']} (score {result['score']}). Reason: {reason}")

    for name in selected:
        execute(name, "selected by the initial plan")

    # Evaluate the first pass and replan only when findings justify more work.
    first_pass = list(results_by_tool.values())
    first_critical = any(r["status"] == "CRITICAL" for r in first_pass)
    first_abnormal = any(r["status"] in ("WARNING", "SERVICE DUE", "CRITICAL") for r in first_pass)
    trend_warning = bool(historical_context.get("trend_warning"))

    if first_critical:
        trace.append("EVALUATE: Critical evidence found in the first pass.")
        trace.append("REPLAN: Expand to all remaining diagnostic tools for a combined inspection view.")
        for name in ("thermal_tool", "vibration_tool", "usage_tool"):
            execute(name, "critical finding requires a broader cross-check")
    elif first_abnormal:
        trace.append("EVALUATE: At least one abnormal indicator was found.")
        complementary = []
        if "thermal_tool" in results_by_tool and "vibration_tool" not in results_by_tool:
            complementary.append("vibration_tool")
        if "vibration_tool" in results_by_tool and "thermal_tool" not in results_by_tool:
            complementary.append("thermal_tool")
        if complementary:
            trace.append("REPLAN: Add a complementary sensor check to see whether the abnormality is isolated or combined.")
            for name in complementary:
                execute(name, "cross-check an abnormal sensor finding")
        if trend_warning:
            trace.append("REPLAN: Historical deterioration is present; ensure both thermal and vibration checks are included.")
            for name in ("thermal_tool", "vibration_tool"):
                execute(name, "cross-check a rising historical trend")
    elif trend_warning:
        trace.append("EVALUATE: Current thresholds look normal, but machine memory indicates deterioration.")
        trace.append("REPLAN: Run both sensor checks because change over time may matter before a fixed threshold is crossed.")
        for name in ("thermal_tool", "vibration_tool"):
            execute(name, "investigate a rising historical trend")
    else:
        trace.append("EVALUATE: Initial findings are within configured demo thresholds; no extra diagnostic pass is needed.")

    results = list(results_by_tool.values())
    critical = sum(r["status"] == "CRITICAL" for r in results)
    abnormal = sum(r["status"] in ("WARNING", "SERVICE DUE") for r in results)
    score = sum(r["score"] for r in results)

    if critical >= 1 or score >= 5:
        severity = "HIGH"
        summary = "High-priority maintenance assessment required based on the configured demo rules."
        action = ("1. Follow site safety procedures. 2. Have qualified personnel assess the machine. "
                  "3. Do not restart equipment judged unsafe by qualified staff. "
                  "4. Record findings and recheck after approved corrective work.")
    elif abnormal >= 1 or score >= 2 or trend_warning:
        severity = "MEDIUM"
        summary = "Abnormal indicators or a notable historical trend were found; inspection is recommended."
        action = ("1. Schedule an inspection. 2. Check the diagnostic findings listed above. "
                  "3. Compare readings with machine-specific baselines and manufacturer guidance. "
                  "4. Repeat measurements under comparable conditions.")
    else:
        severity = "LOW"
        summary = "No configured demo warning thresholds or notable historical trend were detected by the checks run."
        action = ("1. Continue routine monitoring. 2. Maintain a service log. "
                  "3. Compare future readings with machine-specific baselines.")

    if critical and (abnormal or len(results) > 1):
        trace.append("EVALUATE: Critical evidence coexists with other diagnostic evidence.")
        trace.append("DECISION: Prioritize a combined inspection instead of treating alerts independently.")
        action = ("1. Prioritize a combined inspection. 2. Follow site safety procedures. "
                  "3. Qualified personnel decide whether operation can continue. "
                  "4. Inspect thermal, vibration, and service-history factors together.")

    if historical_context.get("sample_count", 0):
        trace.append(
            "MEMORY: Compared this assessment with "
            f"{historical_context['sample_count']} recent saved assessment(s) for this machine."
        )
        if trend_warning:
            trace.append(
                "MEMORY: Historical change detected — "
                f"temperature delta {historical_context.get('temperature_delta', 0):+.1f} °C; "
                f"vibration delta {historical_context.get('vibration_delta', 0):+.1f} mm/s."
            )
            action += " Review the historical trend and investigate persistent increases."
    else:
        trace.append("MEMORY: No usable prior assessments for this machine; this report uses current readings only.")

    trace.append(f"OUTPUT: Final severity = {severity}; {len(results)} diagnostic tool(s) executed.")
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "machine": machine,
        "temperature": float(temp),
        "vibration": float(vibration),
        "hours": int(hours),
        "severity": severity,
        "risk_score": int(score),
        "summary": summary,
        "action_plan": action,
        "results": results,
        "trace": trace,
    }


def trend_context(history, machine, temp, vibration):
    """Compare current readings with recent saved readings for this machine."""
    empty = {
        "trend_warning": False,
        "temperature_rising": False,
        "vibration_rising": False,
        "temperature_delta": 0.0,
        "vibration_delta": 0.0,
        "sample_count": 0,
    }
    if history.empty or "machine" not in history.columns:
        return empty

    machine_history = history[history["machine"].astype(str) == str(machine)].copy()
    if machine_history.empty:
        return empty

    # History is often loaded newest-first; sort oldest-first before taking the recent baseline.
    if "id" in machine_history.columns:
        machine_history = machine_history.sort_values("id")
    recent = machine_history.tail(5)
    if recent.empty:
        return empty

    temp_values = pd.to_numeric(recent["temperature"], errors="coerce").dropna()
    vib_values = pd.to_numeric(recent["vibration"], errors="coerce").dropna()
    if temp_values.empty or vib_values.empty:
        return empty

    # Median baselines are less sensitive to a single unusual historical reading.
    temp_baseline = float(temp_values.median())
    vib_baseline = float(vib_values.median())
    temp_delta = float(temp) - temp_baseline
    vib_delta = float(vibration) - vib_baseline

    # Also flag a simple three-reading monotonic rise when there is enough history.
    temp_recent_rise = len(temp_values) >= 3 and temp_values.tail(3).is_monotonic_increasing and temp_values.iloc[-1] > temp_values.iloc[0]
    vib_recent_rise = len(vib_values) >= 3 and vib_values.tail(3).is_monotonic_increasing and vib_values.iloc[-1] > vib_values.iloc[0]
    temperature_rising = temp_delta >= 5.0 or bool(temp_recent_rise)
    vibration_rising = vib_delta >= 1.0 or bool(vib_recent_rise)

    return {
        "trend_warning": temperature_rising or vibration_rising,
        "temperature_rising": temperature_rising,
        "vibration_rising": vibration_rising,
        "temperature_delta": temp_delta,
        "vibration_delta": vib_delta,
        "sample_count": int(min(len(temp_values), len(vib_values))),
        "temperature_baseline": temp_baseline,
        "vibration_baseline": vib_baseline,
    }

# ---------- Theme and UI ----------
if "theme" not in st.session_state:
    st.session_state.theme = "Dark"
if "auth_user" not in st.session_state:
    st.session_state.auth_user = None
if "page" not in st.session_state:
    st.session_state.page = "Overview"

def inject_theme(theme):
    # A restrained product palette inspired by premium consumer-tech interfaces.
    if theme == "Dark":
        bg, panel, card, text, muted, border, accent = "#101114", "#17191D", "#1D2025", "#F5F5F7", "#A1A1AA", "#30343B", "#7DD3FC"
        input_bg = "#22252B"
    else:
        bg, panel, card, text, muted, border, accent = "#F5F5F7", "#FFFFFF", "#FFFFFF", "#1D1D1F", "#6E7075", "#E2E4E8", "#007AFF"
        input_bg = "#F2F3F5"
    st.markdown(f"""
    <style>
    :root {{ color-scheme: {'dark' if theme == 'Dark' else 'light'}; }}
    .stApp {{ background: {bg}; color: {text}; }}
    [data-testid="stHeader"] {{ background: {bg}; }}
    [data-testid="stSidebar"] {{ display:none; }}
    .block-container {{ max-width: 1320px; padding-top: 1.15rem; padding-bottom: 3rem; }}
    h1,h2,h3,h4,p,label,li {{ color: {text}; }}
    h1 {{ letter-spacing: -.045em; font-weight: 720; }}
    h2,h3 {{ letter-spacing: -.025em; font-weight: 680; }}
    p,li {{ line-height: 1.6; }}
    .muted, .stCaption {{ color: {muted} !important; }}
    .brand-lockup {{ display:flex; align-items:center; gap:.8rem; padding:.3rem 0 .7rem; }}
    .brand-mark {{ display:flex; align-items:center; justify-content:center; width:42px; height:42px; border-radius:13px; color:#101114; font-size:1.25rem; font-weight:850; background:{accent}; }}
    .brand-name {{ font-size:1.08rem; line-height:1.2; font-weight:780; letter-spacing:-.035em; color:{text}; }}
    .brand-sub {{ font-size:.65rem; letter-spacing:.13em; font-weight:700; color:{muted}; margin-top:.2rem; }}
    .top-rule {{ height:1px; background:{border}; margin:.25rem 0 1rem; }}
    .hero {{ padding:1.2rem 0 1.6rem; border-radius:0; background:transparent; border:0; border-bottom:1px solid {border}; margin:.8rem 0 1.5rem; }}
    .hero-kicker {{ color:{accent}; text-transform:uppercase; letter-spacing:.16em; font-size:.7rem; font-weight:800; }}
    .hero h1 {{ color:{text}; font-size:clamp(2.2rem,4.5vw,3.65rem); line-height:1.07; margin:.75rem 0 .9rem; max-width:850px; }}
    .hero p {{ color:{muted}; font-size:1.02rem; max-width:760px; margin-bottom:1.15rem; }}
    .pill {{ display:inline-flex; align-items:center; gap:.4rem; padding:.25rem 0; border:0; border-radius:0; color:{muted}; font-size:.76rem; font-weight:600; background:transparent; }}
    .section-eyebrow {{ color:{accent}; text-transform:uppercase; letter-spacing:.14em; font-size:.68rem; font-weight:800; margin-bottom:.4rem; }}
    .feature-card {{ background:transparent; border:0; border-radius:0; border-bottom:1px solid {border}; padding:.9rem 0 1rem; min-height:0; }}
    .feature-card h3 {{ margin:.3rem 0 .4rem; font-size:1rem; }}
    .feature-card p {{ color:{muted}; font-size:.88rem; margin:0; }}
    .feature-icon {{ display:inline-flex; align-items:center; justify-content:center; width:1.5rem; height:1.5rem; border-radius:0; background:transparent; color:{accent}; font-size:1.05rem; margin-bottom:.35rem; }}
    div[data-testid="stMetric"] {{ background:transparent; border:0; border-left:1px solid {border}; border-radius:0; padding:.25rem 1rem; box-shadow:none; }}
    div[data-testid="stHorizontalBlock"]:has(div[data-testid="stMetric"]) {{ padding:.55rem 0 1rem; border-bottom:1px solid {border}; }}
    div[data-testid="stMetricLabel"] p {{ color:{muted} !important; font-size:.78rem; font-weight:650; }}
    div[data-testid="stMetricValue"] {{ font-weight:760; letter-spacing:-.035em; }}
    div[data-testid="stDataFrame"] {{ border:0; border-radius:0; overflow:hidden; }}
    .stButton button, .stDownloadButton button, .stFormSubmitButton button {{ border-radius:7px; font-weight:600; min-height:2.35rem; transition:background .15s ease,border-color .15s ease; box-shadow:none; }}
    .stButton button[kind="primary"], .stFormSubmitButton button[kind="primary"] {{ background:{accent}; color:#101114; border:1px solid {accent}; box-shadow:none; }}
    .stButton button:hover, .stDownloadButton button:hover {{ border-color:{accent}; }}
    div[data-baseweb="input"] input, div[data-baseweb="select"] > div, textarea {{ border-radius:10px; background:{input_bg}; }}
    /* Horizontal navigation tabs: native Streamlit radio controls, styled as a clean tab strip. */
    div[data-testid="stRadio"] {{ margin:.1rem 0 .25rem; }}
    div[data-testid="stRadio"] > div {{ gap:.25rem; align-items:stretch; border-bottom:1px solid {border}; flex-wrap:nowrap; overflow-x:auto; scrollbar-width:thin; }}
    div[data-testid="stRadio"] label {{ flex:0 0 auto; border:0 !important; border-bottom:2px solid transparent !important; border-radius:0 !important; padding:.75rem .95rem !important; background:transparent !important; transition:color .15s ease,border-color .15s ease; cursor:pointer; }}
    div[data-testid="stRadio"] label > div:first-child {{ display:none !important; }}
    div[data-testid="stRadio"] label:has(input:checked) {{ border-bottom-color:{accent} !important; color:{accent} !important; font-weight:750; }}
    div[data-testid="stRadio"] label:hover {{ color:{accent} !important; }}
    div[data-testid="stRadio"] label p {{ margin:0; white-space:nowrap; }}
    .stAlert {{ border-radius:12px; border:1px solid {border}; }}
    [data-testid="stExpander"] {{ border:0; border-top:1px solid {border}; border-radius:0; background:transparent; }}
    hr {{ border-color:{border}; opacity:.8; }}
    .page-header {{ padding:.3rem 0 1rem; border-bottom:1px solid {border}; margin-bottom:1.2rem; }}
    .page-header p {{ color:{muted}; margin-top:-.25rem; }}
    @media (max-width: 800px) {{ .block-container {{ padding-top:.55rem; }} .hero {{ border-radius:16px; }} div[data-testid="stRadio"] > div {{ overflow-x:auto; }} div[data-testid="stRadio"] label {{ padding:.7rem .75rem !important; }} }}
    </style>
    """, unsafe_allow_html=True)

inject_theme(st.session_state.theme)

def show_auth_page():
    st.markdown('''
    <div class="brand-lockup"><div class="brand-mark">M</div><div><div class="brand-name">MECHGUARD AI</div><div class="brand-sub">MAINTENANCE INTELLIGENCE</div></div></div>
    <div class="top-rule"></div>
    <div class="hero"><div class="hero-kicker">ENGINEERING INSIGHT · OPERATIONAL CLARITY</div><h1>Know your machines.<br>Act with confidence.</h1><p>A focused maintenance workspace for turning sensor readings into clear diagnostics, historical context, and prioritised next steps.</p><span class="pill">Local-first&nbsp; · &nbsp;Explainable&nbsp; · &nbsp;No paid APIs</span></div>
    ''', unsafe_allow_html=True)
    left, right = st.columns([1.05, .95], gap="large", vertical_alignment="top")
    with left:
        st.markdown('<div class="section-eyebrow">BUILT FOR CLARITY</div><h2>Maintenance decisions, backed by evidence.</h2><p class="muted">Everything important, without the dashboard clutter.</p>', unsafe_allow_html=True)
        st.markdown('''
        <div class="feature-card"><div class="feature-icon">⌁</div><h3>Explainable diagnostics</h3><p>See which checks ran, what they found, and how the agent reached its recommendation.</p></div>
        <div style="height:2px"></div>
        <div class="feature-card"><div class="feature-icon">◷</div><h3>Machine history</h3><p>Compare readings over time and surface changes that may deserve attention.</p></div>
        <div style="height:2px"></div>
        <div class="feature-card"><div class="feature-icon">↗</div><h3>Sensor data, in one place</h3><p>Import CSV readings and use the same diagnostic workflow to assess them.</p></div>
        ''', unsafe_allow_html=True)
        st.caption("Educational prototype. Thresholds are illustrative, not real-world machine safety limits.")
    with right:
        with st.container(border=True):
            st.markdown('<div class="section-eyebrow">YOUR WORKSPACE</div><h2>Welcome to MechGuard</h2><p class="muted">Sign in or create a local demo account to continue.</p>', unsafe_allow_html=True)
            mode = st.radio("Account", ["Sign in", "Create account"], horizontal=True, key="auth_mode", label_visibility="collapsed")
            with st.form("auth_form", clear_on_submit=False):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                confirm = ""
                if mode == "Create account":
                    confirm = st.text_input("Confirm password", type="password", placeholder="Re-enter your password")
                    st.caption("Use 3–24 characters for the username and at least 8 characters for the password.")
                submitted = st.form_submit_button("Sign in" if mode == "Sign in" else "Create account", type="primary", use_container_width=True)
            if submitted:
                if mode == "Create account":
                    if password != confirm:
                        st.error("Passwords do not match.")
                    else:
                        ok, message = register_user(username, password)
                        if ok:
                            st.success(message + " Switch to Sign in to continue.")
                        else:
                            st.error(message)
                else:
                    if verify_user(username, password):
                        with db() as conn:
                            row = conn.execute("SELECT username FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),)).fetchone()
                        st.session_state.auth_user = row[0]
                        st.session_state.page = "Overview"
                        st.session_state.nav_radio = "Overview"
                        st.session_state.latest_report = None
                        st.session_state.latest_report_user = row[0]
                        st.rerun()
                    else:
                        st.error("Incorrect username or password.")
            st.caption("Local classroom authentication. Not intended for production multi-user security.")


def app_topnav():
    pages = ["Overview", "Agent workspace", "Machine memory", "CSV & trends", "System guide"]
    if st.session_state.page not in pages:
        st.session_state.page = "Overview"
    left, right = st.columns([1.55, 1.0], vertical_alignment="center")
    with left:
        st.markdown('<div class="brand-lockup"><div class="brand-mark">M</div><div><div class="brand-name">MECHGUARD <span style="color:var(--primary-color)">AI</span></div><div class="brand-sub">MAINTENANCE INTELLIGENCE</div></div></div>', unsafe_allow_html=True)
    with right:
        a, b, c = st.columns([1.0, 1.0, .85], vertical_alignment="center")
        with a:
            st.caption(f"Signed in as **{st.session_state.auth_user}**")
        with b:
            theme = st.selectbox("Appearance", ["Dark", "Light"], index=0 if st.session_state.theme == "Dark" else 1, key="theme_select", label_visibility="collapsed")
            if theme != st.session_state.theme:
                st.session_state.theme = theme
                st.rerun()
        with c:
            if st.button("Sign out", key="top_signout", use_container_width=True):
                st.session_state.auth_user = None
                st.session_state.page = "Overview"
                st.session_state.nav_radio = "Overview"
                st.session_state.latest_report = None
                st.session_state.latest_report_user = None
                st.rerun()
    st.markdown('<div class="top-rule"></div>', unsafe_allow_html=True)
    # The radio widget is the source of truth for navigation. Do not overwrite its
    # value from the previous page on every rerun, or clicks will appear to do nothing.
    selected = st.radio(
        "Main navigation", pages, horizontal=True, key="nav_radio",
        label_visibility="collapsed"
    )
    if selected != st.session_state.page:
        st.session_state.page = selected
    st.markdown('<div class="top-rule" style="margin-top:.35rem;margin-bottom:1.2rem"></div>', unsafe_allow_html=True)


def home_page(username):
    history = load_history(username)
    total = len(history)
    high = int((history["severity"] == "HIGH").sum()) if total else 0
    machines = int(history["machine"].nunique()) if total else 0

    st.markdown(
        f'<div class="hero"><div class="hero-kicker">OPERATIONS OVERVIEW</div>'
        f'<h1>Good to see you, {username}.</h1>'
        '<p>Monitor machine condition, review diagnostic evidence, and decide what needs attention next.</p>'
        '<span class="pill">● Local workspace · Ready</span></div>',
        unsafe_allow_html=True,
    )

    a, b, c = st.columns(3)
    a.metric("Assessments", total)
    b.metric("Machines tracked", machines)
    c.metric("High-priority", high)

    st.markdown('<div class="section-eyebrow">WORKSPACE</div><h2>Choose where to begin</h2>', unsafe_allow_html=True)
    actions = [
        ("Agent workspace", "Run a diagnostic assessment", "Enter sensor readings and review the agent’s findings."),
        ("Machine memory", "Review machine history", "Compare previous assessments and download records."),
        ("CSV & trends", "Analyse sensor data", "Import a CSV and explore changes across readings."),
    ]
    for page_name, title, description in actions:
        left, middle, right = st.columns([1.1, 3.8, 1.2], vertical_alignment="center")
        with left:
            st.markdown(f'<span style="color:var(--primary-color);font-weight:650">{page_name}</span>', unsafe_allow_html=True)
        with middle:
            st.markdown(f'**{title}**  \n\n<span class="muted">{description}</span>', unsafe_allow_html=True)
        with right:
            if st.button("Open →", key="open_" + page_name, use_container_width=True):
                st.session_state.page = page_name
                st.session_state.nav_radio = page_name
                st.rerun()
        st.markdown('<div class="top-rule" style="margin:.25rem 0 .6rem"></div>', unsafe_allow_html=True)

    st.markdown("### Recent activity")
    if history.empty:
        st.caption("No assessments yet. Run your first diagnostic to begin building machine history.")
    else:
        st.dataframe(
            history[["timestamp", "machine", "temperature", "vibration", "operating_hours", "severity", "risk_score"]].head(5),
            use_container_width=True, hide_index=True,
        )
    st.caption("Educational prototype · Thresholds are illustrative and are not machine safety limits.")

def workspace_page(username):
    st.markdown('<div class="page-header"><div class="section-eyebrow">DIAGNOSTICS / AGENT</div><h1>Agent workspace</h1><p>Configure a machine snapshot and let the agent investigate the evidence.</p></div>', unsafe_allow_html=True)
    with st.form("manual_assessment"):
        c1,c2 = st.columns(2)
        machine = c1.text_input("Machine ID / name", "Pump-M01")
        temp = c1.slider("Temperature (°C)", 20.0, 120.0, 68.0, 0.5)
        vibration = c2.slider("Vibration (mm/s RMS)", 0.0, 15.0, 3.0, 0.1)
        hours = c2.number_input("Operating hours since service", 0, 100000, 420, 10)
        run = st.form_submit_button("Run agent assessment", type="primary", use_container_width=True)
    if run:
        machine = machine.strip()
        if not machine:
            st.error("Enter a machine ID or name before running an assessment.")
        else:
            hist = load_history(username)
            context = trend_context(hist, machine, temp, vibration)
            report = run_agent(machine, temp, vibration, hours, context)
            save_assessment(report, username)
            st.session_state.latest_report = report
            st.session_state.latest_report_user = username
            st.success("Assessment saved to your local machine memory.")
    report = st.session_state.get("latest_report") if st.session_state.get("latest_report_user") == username else None
    if report:
        st.divider()
        st.subheader(f"Latest assessment · {report['machine']}")
        a,b,c,d = st.columns(4)
        a.metric("Severity", report["severity"])
        b.metric("Risk score", report["risk_score"])
        c.metric("Temperature", f"{report['temperature']:.1f} °C")
        d.metric("Vibration", f"{report['vibration']:.1f} mm/s")
        st.info(report["summary"])
        st.markdown("### Prioritized action plan")
        st.write(report["action_plan"])
        st.markdown("### Diagnostic results")
        st.dataframe(pd.DataFrame(report["results"])[["tool","status","score","finding","action"]], use_container_width=True, hide_index=True)
        st.markdown("### Agent reasoning trace")
        for i, step in enumerate(report["trace"], 1):
            st.write(f"**{i}.** {step}")
        out = pd.DataFrame([{"timestamp":report["timestamp"],"machine":report["machine"],
            "temperature_c":report["temperature"],"vibration_mm_s_rms":report["vibration"],
            "operating_hours":report["hours"],"severity":report["severity"],"risk_score":report["risk_score"],
            "summary":report["summary"],"action_plan":report["action_plan"],"trace":" | ".join(report["trace"])}])
        st.download_button("Download assessment report", out.to_csv(index=False), "mechguard_report.csv", "text/csv")

def memory_page(username):
    st.markdown('<div class="page-header"><div class="section-eyebrow">HISTORY / CONTEXT</div><h1>Machine memory</h1><p>Explore saved assessments and compare machine conditions over time.</p></div>', unsafe_allow_html=True)
    hist = load_history(username)
    if hist.empty:
        st.info("No assessments yet. Run one in Agent workspace.")
        return
    machines = ["All machines"] + sorted(hist["machine"].dropna().unique().tolist())
    selected = st.selectbox("Filter by machine", machines)
    filtered = load_history(username, selected)
    x,y,z = st.columns(3)
    x.metric("Saved assessments", len(filtered))
    y.metric("Machines", filtered["machine"].nunique())
    z.metric("High priority", int((filtered["severity"] == "HIGH").sum()))
    st.dataframe(filtered[["timestamp","machine","temperature","vibration","operating_hours","severity","risk_score"]],
                 use_container_width=True, hide_index=True)
    st.download_button("Download history CSV", filtered.to_csv(index=False), "mechguard_history.csv", "text/csv")

def csv_trends_page(username):
    st.markdown('<div class="page-header"><div class="section-eyebrow">DATA / MONITORING</div><h1>CSV & trends</h1><p>Bring sensor readings into the workspace and explore historical patterns.</p></div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Upload sensor CSV", type=["csv"], key="csv_upload")
    st.markdown("Required columns: `machine`, `temperature`, `vibration`, `operating_hours`.")
    sample = pd.DataFrame([
        {"machine":"Pump-M01","temperature":68,"vibration":3.0,"operating_hours":420},
        {"machine":"Pump-M01","temperature":80,"vibration":5.2,"operating_hours":600},
        {"machine":"Pump-M01","temperature":96,"vibration":8.0,"operating_hours":1200},
    ])
    st.download_button("Download sample CSV", sample.to_csv(index=False), "mechguard_sample.csv", "text/csv")
    if uploaded:
        try:
            data = pd.read_csv(uploaded)
            data.columns = [c.strip().lower().replace(" ","_") for c in data.columns]
            aliases = {"machine_id":"machine","temperature_c":"temperature","temp_c":"temperature",
                       "vibration_mm_s_rms":"vibration","hours":"operating_hours"}
            data = data.rename(columns={k:v for k,v in aliases.items() if k in data.columns})
            required = {"machine","temperature","vibration","operating_hours"}
            if not required.issubset(data.columns):
                st.error("Missing required columns. Download the sample CSV to see the expected format.")
            else:
                for col in ["temperature","vibration","operating_hours"]:
                    data[col] = pd.to_numeric(data[col], errors="coerce")
                data = data.dropna(subset=["machine","temperature","vibration","operating_hours"])
                data = data[(data.temperature.between(0,200)) & (data.vibration.between(0,100)) & (data.operating_hours >= 0)]
                if data.empty:
                    st.error("No valid rows found.")
                else:
                    st.success(f"Loaded {len(data)} valid row(s).")
                    st.dataframe(data, use_container_width=True, hide_index=True)
                    if st.button("Analyse latest CSV row", type="primary"):
                        row = data.iloc[-1]
                        hist = load_history(username)
                        context = trend_context(hist, str(row["machine"]), float(row["temperature"]), float(row["vibration"]))
                        report = run_agent(str(row["machine"]), float(row["temperature"]), float(row["vibration"]), int(row["operating_hours"]), context)
                        save_assessment(report, username)
                        st.session_state.latest_report = report
                        st.session_state.latest_report_user = username
                        st.success(f"Assessment saved: {report['severity']}. Open Agent workspace to view full details.")
        except Exception as e:
            st.error(f"Unable to read CSV: {e}")
    st.divider()
    hist = load_history(username)
    if not hist.empty:
        machine = st.selectbox("Machine trend", sorted(hist["machine"].dropna().unique().tolist()))
        h = hist[hist["machine"] == machine].sort_values("id")
        if len(h) >= 2:
            l,r = st.columns(2)
            with l:
                st.markdown("**Temperature trend (°C)**")
                st.line_chart(h.set_index("timestamp")[["temperature"]])
            with r:
                st.markdown("**Vibration trend (mm/s RMS)**")
                st.line_chart(h.set_index("timestamp")[["vibration"]])
        else:
            st.info("Run at least two assessments for the same machine to display trend charts.")

def guide_page():
    st.markdown('<div class="page-header"><div class="section-eyebrow">DOCUMENTATION</div><h1>System guide</h1><p>Understand the workflow, design decisions and current limitations.</p></div>', unsafe_allow_html=True)
    st.markdown("""
    ### Agent architecture
    **Goal → Planner → Diagnostic tools → Evaluator → Feedback/replanning → Action plan**

    - **Planner:** selects diagnostic tools from current readings and remembered trends.
    - **Tools:** thermal, vibration, and usage/service diagnostics.
    - **Evaluator:** checks first-pass findings and decides whether more checks are justified.
    - **Replanning:** adds complementary checks for abnormal findings or expands the investigation after critical evidence.
    - **Memory:** recent machine-specific readings can trigger trend investigation before fixed thresholds are crossed.
    - **Memory:** SQLite stores assessments locally, separated by username.
    - **Security note:** passwords are salted and hashed locally. This is a classroom demo, not enterprise-grade authentication.
    - **No paid APIs:** all logic runs locally in Python.

    ### Important limitations
    Thresholds are illustrative classroom values, not universal engineering limits. The trend check is a simple heuristic, not a trained forecasting model. The application does not connect to real sensors or control equipment. Use machine-specific manufacturer documentation and qualified personnel for real maintenance decisions.
    """)

# ---------- Route ----------
if not st.session_state.auth_user:
    show_auth_page()
else:
    app_topnav()
    user = st.session_state.auth_user
    page = st.session_state.page
    if page == "Overview":
        home_page(user)
    elif page == "Agent workspace":
        workspace_page(user)
    elif page == "Machine memory":
        memory_page(user)
    elif page == "CSV & trends":
        csv_trends_page(user)
    else:
        guide_page()
