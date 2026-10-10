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
