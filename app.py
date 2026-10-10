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
    """Inject a responsive, minimalist theme without changing app behaviour."""
    if theme == "Dark":
        bg, panel, card, text, muted, border, accent = (
            "#0B100D", "#111814", "#151E18", "#EEF4EC", "#9BAA9D", "#29372D", "#C7F36A"
        )
        input_bg = "#151E18"
        accent_ink = "#172116"
        glow = "rgba(199, 243, 106, .10)"
    else:
        bg, panel, card, text, muted, border, accent = (
            "#F4F6F0", "#FFFFFF", "#FCFDF9", "#1A251D", "#707D72", "#E0E7DD", "#4F7542"
        )
        input_bg = "#F5F7F2"
        accent_ink = "#FFFFFF"
        glow = "rgba(79, 117, 66, .08)"

    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&family=DM+Mono:wght@400;500&display=swap');
    :root {{
        color-scheme: {'dark' if theme == 'Dark' else 'light'};
        --mg-bg: {bg}; --mg-panel: {panel}; --mg-card: {card};
        --mg-text: {text}; --mg-muted: {muted}; --mg-border: {border};
        --mg-accent: {accent}; --mg-input: {input_bg};
        --mg-accent-ink: {accent_ink}; --mg-glow: {glow};
        --mg-radius: 18px;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    .stApp {{
        background:
            radial-gradient(ellipse at 92% 0%, var(--mg-glow), transparent 34%),
            radial-gradient(ellipse at 0% 35%, {glow}, transparent 30%),
            {bg};
        color: {text}; font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        transition: background .25s ease, color .25s ease;
    }}
    [data-testid="stHeader"] {{ background: transparent; }}
    [data-testid="stSidebar"] {{ display:none; }}
    [data-testid="stToolbar"] {{ right: 1rem; }}
    .block-container {{ max-width: 1260px; padding-top: 1rem; padding-bottom: 3.5rem; }}
    h1,h2,h3,h4 {{ color: {text}; font-family: 'Manrope', 'DM Sans', sans-serif; letter-spacing: -.045em; }}
    h1 {{ font-weight: 750; line-height: 1.08; }}
    h2 {{ font-weight: 720; line-height: 1.16; }}
    h3,h4 {{ font-weight: 700; }}
    p,li {{ color: {text}; line-height: 1.7; }}
    p {{ overflow-wrap: anywhere; }}
    a {{ color: {accent}; text-underline-offset: 3px; }}
    .muted, .stCaption, [data-testid="stCaptionContainer"] {{ color: {muted} !important; }}

    /* Brand and page shell */
    .brand-lockup {{ display:flex; align-items:center; gap:.85rem; padding:.25rem 0 .9rem; }}
    .brand-mark {{ display:flex; align-items:center; justify-content:center; width:43px; height:43px; flex:0 0 43px; border-radius:14px; color:{accent_ink}; font:800 1.15rem 'Manrope',sans-serif; letter-spacing:-.08em; background:{accent}; box-shadow:0 8px 22px {glow}; }}
    .brand-name {{ font:800 1.02rem 'Manrope',sans-serif; line-height:1.2; letter-spacing:-.035em; color:{text}; }}
    .brand-sub {{ font:500 .62rem 'DM Mono',monospace; letter-spacing:.13em; color:{muted}; margin-top:.27rem; }}
    .top-rule {{ height:1px; background:{border}; margin:.25rem 0 1.2rem; opacity:.9; }}
    .hero {{
        position:relative; overflow:hidden; padding:clamp(1.55rem,3.5vw,3rem);
        border-radius:24px; background:linear-gradient(135deg,{panel} 0%,{bg} 100%);
        border:1px solid {border}; margin:.8rem 0 1.6rem;
        box-shadow:0 18px 55px rgba(0,0,0,.035);
        animation:mg-enter .55s cubic-bezier(.2,.75,.25,1) both;
    }}
    .hero:after {{ content:""; position:absolute; width:260px; height:260px; right:-100px; top:-140px; border-radius:50%; border:1px solid {border}; box-shadow:0 0 0 34px {glow},0 0 0 70px {glow}; pointer-events:none; }}
    .hero-kicker {{ color:{accent}; text-transform:uppercase; letter-spacing:.16em; font:500 .65rem 'DM Mono',monospace; }}
    .hero h1 {{ color:{text}; font-size:clamp(2.25rem,4.5vw,3.8rem); line-height:1.04; margin:.85rem 0 1rem; max-width:880px; position:relative; z-index:1; }}
    .hero p {{ color:{muted}; font-size:1rem; line-height:1.8; max-width:760px; margin-bottom:1.2rem; position:relative; z-index:1; }}
    .pill {{ display:inline-flex; align-items:center; gap:.4rem; padding:.45rem .78rem; border:1px solid {border}; border-radius:999px; color:{text}; font-size:.72rem; font-weight:600; background:{card}; }}
    .section-eyebrow {{ color:{accent}; text-transform:uppercase; letter-spacing:.15em; font:500 .64rem 'DM Mono',monospace; margin-bottom:.5rem; }}
    .feature-card {{ background:linear-gradient(140deg,{panel},{card}); border:1px solid {border}; border-radius:17px; padding:1.15rem 1.2rem; min-height:128px; transition:transform .22s ease,border-color .22s ease,box-shadow .22s ease; box-shadow:0 6px 22px rgba(0,0,0,.02); }}
    .feature-card:hover {{ transform:translateY(-3px); border-color:{accent}; box-shadow:0 12px 28px {glow}; }}
    .feature-card h3 {{ margin:.2rem 0 .45rem; font-size:1rem; letter-spacing:-.03em; }}
    .feature-card p {{ color:{muted}; font-size:.83rem; line-height:1.7; margin:0; }}
    .feature-icon {{ width:37px; height:37px; display:flex; align-items:center; justify-content:center; border-radius:12px; background:{input_bg}; color:{accent}; font-size:1.12rem; margin-bottom:.75rem; border:1px solid {border}; }}
    .page-header {{ padding:.45rem 0 1.2rem; animation:mg-enter .4s ease both; }}
    .page-header h1 {{ font-size:clamp(2rem,4vw,3rem); margin-bottom:.7rem; }}
    .page-header p {{ color:{muted}; margin-top:-.15rem; }}

    /* Metrics and data surfaces */
    div[data-testid="stMetric"] {{ background:linear-gradient(140deg,{panel},{card}); border:1px solid {border}; border-radius:17px; padding:1.05rem 1.15rem; box-shadow:none; transition:transform .2s ease,border-color .2s ease; }}
    div[data-testid="stMetric"]:hover {{ transform:translateY(-2px); border-color:{accent}; }}
    div[data-testid="stMetricLabel"] p {{ color:{muted} !important; font:500 .72rem 'DM Mono',monospace; letter-spacing:.03em; }}
    div[data-testid="stMetricValue"] {{ color:{text}; font:750 clamp(1.5rem,2.2vw,2rem) 'Manrope',sans-serif; letter-spacing:-.055em; }}
    div[data-testid="stDataFrame"] {{ border:1px solid {border}; border-radius:14px; overflow:hidden; background:{panel}; }}
    div[data-testid="stDataFrame"] [role="grid"] {{ border:0; }}
    [data-testid="stVerticalBlockBorderWrapper"] {{ border-radius:18px; border-color:{border}; background:{panel}; box-shadow:0 8px 28px rgba(0,0,0,.025); }}
    [data-testid="stExpander"] {{ border:1px solid {border}; border-radius:14px; background:{panel}; }}
    [data-testid="stExpander"] details summary {{ padding:.45rem .3rem; }}
    hr {{ border-color:{border}; opacity:.85; margin:1.35rem 0; }}

    /* Inputs */
    label, [data-testid="stWidgetLabel"] p {{ color:{text} !important; font-size:.82rem; font-weight:600; }}
    div[data-baseweb="input"] input, div[data-baseweb="select"] > div, div[data-baseweb="textarea"] textarea, textarea {{
        border-radius:12px !important; background:{input_bg} !important; color:{text} !important;
        border-color:{border} !important; transition:border-color .18s ease,box-shadow .18s ease;
    }}
    div[data-baseweb="input"] input:focus, div[data-baseweb="textarea"] textarea:focus {{ border-color:{accent} !important; box-shadow:0 0 0 3px {glow} !important; }}
    div[data-baseweb="select"] > div:hover {{ border-color:{accent} !important; }}
    input::placeholder, textarea::placeholder {{ color:{muted} !important; opacity:.8; }}

    /* Buttons */
    .stButton button, .stDownloadButton button, .stFormSubmitButton button {{
        min-height:2.6rem; border-radius:12px; padding:.45rem 1rem; font-weight:650;
        transition:transform .17s ease,background .17s ease,border-color .17s ease,box-shadow .17s ease;
        border-color:{border};
    }}
    .stButton button[kind="primary"], .stFormSubmitButton button[kind="primary"] {{ background:{accent}; color:{accent_ink}; border:1px solid {accent}; box-shadow:0 5px 16px {glow}; }}
    .stButton button:hover, .stDownloadButton button:hover {{ border-color:{accent}; transform:translateY(-1px); }}
    .stButton button[kind="primary"]:hover, .stFormSubmitButton button[kind="primary"]:hover {{ filter:brightness(1.04); box-shadow:0 8px 22px {glow}; }}
    .stButton button:active, .stDownloadButton button:active {{ transform:scale(.985); }}

    /* Horizontal navigation tabs / radio strip */
    div[data-testid="stRadio"] {{ margin:.15rem 0 .3rem; }}
    div[data-testid="stRadio"] > div {{ gap:.35rem; align-items:center; flex-wrap:nowrap; overflow-x:auto; scrollbar-width:thin; padding:.25rem .1rem .6rem; }}
    div[data-testid="stRadio"] label {{ flex:0 0 auto; border:1px solid transparent !important; border-radius:999px !important; padding:.55rem .9rem !important; background:transparent !important; transition:color .18s ease,background .18s ease,border-color .18s ease; cursor:pointer; }}
    div[data-testid="stRadio"] label > div:first-child {{ display:none !important; }}
    div[data-testid="stRadio"] label:has(input:checked) {{ border-color:{border} !important; background:{panel} !important; color:{accent} !important; box-shadow:0 4px 13px rgba(0,0,0,.035); }}
    div[data-testid="stRadio"] label:hover {{ color:{accent} !important; border-color:{border} !important; }}
    div[data-testid="stRadio"] label p {{ margin:0; white-space:nowrap; font-size:.8rem; }}
    .stAlert {{ border-radius:14px; border:1px solid {border}; }}
    [data-testid="stNotification"] {{ border-radius:14px; }}
    [data-testid="stFileUploader"] {{ border:1px dashed {border}; border-radius:14px; padding:.6rem; background:{panel}; }}
    [data-testid="stProgress"] > div > div {{ background:{accent}; }}

    @keyframes mg-enter {{ from {{ opacity:0; transform:translateY(9px); }} to {{ opacity:1; transform:translateY(0); }} }}
    @media (prefers-reduced-motion: reduce) {{ *, *::before, *::after {{ animation-duration:.01ms !important; animation-iteration-count:1 !important; scroll-behavior:auto !important; transition-duration:.01ms !important; }} }}
    @media (max-width: 800px) {{
        .block-container {{ padding-top:.55rem; padding-bottom:2rem; }}
        .hero {{ border-radius:19px; padding:1.35rem; }}
        .hero h1 {{ font-size:clamp(2rem,7vw,3.1rem); }}
        .feature-card {{ padding:1rem; }}
        div[data-testid="stRadio"] > div {{ overflow-x:auto; }}
        div[data-testid="stRadio"] label {{ padding:.55rem .75rem !important; }}
        div[data-testid="stMetric"] {{ padding:.8rem; }}
    }}
    @media (max-width: 520px) {{
        .block-container {{ padding-left:1rem; padding-right:1rem; }}
        .brand-mark {{ width:38px; height:38px; flex-basis:38px; border-radius:12px; }}
        .brand-name {{ font-size:.94rem; }}
        .brand-sub {{ font-size:.57rem; }}
        .hero {{ padding:1.15rem; }}
        .hero p {{ font-size:.91rem; }}
        .feature-card {{ min-height:unset; }}
        .stButton button, .stDownloadButton button, .stFormSubmitButton button {{ width:100%; }}
    }}
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
        <div style="height:10px"></div>
        <div class="feature-card"><div class="feature-icon">◷</div><h3>Machine history</h3><p>Compare readings over time and surface changes that may deserve attention.</p></div>
        <div style="height:10px"></div>
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
    st.markdown(f'<div class="hero"><div class="hero-kicker">YOUR OPERATIONS OVERVIEW</div><h1>Good to see you, {username}.</h1><p>One clear view of machine condition, diagnostic activity and maintenance signals. Start an assessment or explore the evidence behind previous reports.</p><span class="pill">● Workspace operational</span></div>', unsafe_allow_html=True)
    a,b,c = st.columns(3)
    a.metric("Assessments saved", total)
    b.metric("Machines tracked", machines)
    c.metric("High-priority reports", high)
    st.markdown('<div class="section-eyebrow">QUICK ACTIONS</div><h2>Where would you like to start?</h2>', unsafe_allow_html=True)
    c1,c2,c3 = st.columns(3, gap="medium")
    with c1:
        st.markdown('<div class="feature-card"><div class="feature-icon">◈</div><h3>Run diagnostics</h3><p>Analyse temperature, vibration, and service interval indicators.</p></div>', unsafe_allow_html=True)
        if st.button("Open agent workspace →", key="go_agent", use_container_width=True):
            st.session_state.page = "Agent workspace"; st.session_state.nav_radio = "Agent workspace"; st.rerun()
    with c2:
        st.markdown('<div class="feature-card"><div class="feature-icon">◷</div><h3>Review machine memory</h3><p>Explore previous assessments and download your history.</p></div>', unsafe_allow_html=True)
        if st.button("View machine memory →", key="go_history", use_container_width=True):
            st.session_state.page = "Machine memory"; st.session_state.nav_radio = "Machine memory"; st.rerun()
    with c3:
        st.markdown('<div class="feature-card"><div class="feature-icon">↗</div><h3>Analyse sensor data</h3><p>Upload a CSV and inspect trends across saved readings.</p></div>', unsafe_allow_html=True)
        if st.button("Open CSV & trends →", key="go_csv", use_container_width=True):
            st.session_state.page = "CSV & trends"; st.session_state.nav_radio = "CSV & trends"; st.rerun()
    st.markdown("### Recent activity")
    if history.empty:
        st.info("Your workspace is ready. Run your first assessment to start building machine memory.")
    else:
        st.dataframe(history[["timestamp","machine","temperature","vibration","operating_hours","severity","risk_score"]].head(5),
                     use_container_width=True, hide_index=True)
    st.caption("Prototype note: demo thresholds are illustrative and should not be used as real-world safety limits.")

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
