# MechGuard AI 🛠️🤖

> **Explainable, Local-First Machine Maintenance Decision Support**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Framework](https://img.shields.io/badge/framework-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Database](https://img.shields.io/badge/database-SQLite-003B57.svg)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/license-Unlicensed-lightgrey.svg)](#license)

**MechGuard AI** is an educational Agentic AI prototype that translates raw industrial machine readings into an explainable, deterministic maintenance assessment. Built as a local-first application, it combines rule-based diagnostic tools, historical trend context, and an interactive Streamlit workspace to generate actionable maintenance plans alongside a transparent reasoning trace.

---

> [!WARNING]  
> **Safety & Classroom Prototype Notice**  
> MechGuard AI is an educational demonstration project. All diagnostic thresholds and severity rules are illustrative and **not universal machine safety limits**. Do not use this software as a substitute for manufacturer guidance, qualified engineering judgment, or site safety procedures.

---

## 📌 Executive Summary & Key Features

- **Agent Workspace:** Interactive diagnostic engine with step-by-step reasoning traces, severity assessments, and prioritized action plans.
- **Explainable Agent Architecture:** Deterministic, rule-based tool selection and evaluation workflow (no paid APIs, cloud LLMs, or black-box predictions).
- **Machine Memory & Historical Context:** SQLite-backed persistence to track past machine assessments and detect historical trend abnormalities.
- **CSV Data Ingestion & Trends:** Upload sensor datasets with automated column validation/aliasing and visualize temperature/vibration trends.
- **Secure Local Authentication:** Built-in local account registration and sign-in using salted `PBKDF2-HMAC-SHA256` password hashing.
- **Zero Cloud Dependencies:** Completely self-contained and run locally using standard Python libraries and Streamlit.

---

## ⚙️ How the Agent Works

The MechGuard agent uses a deterministic, 7-step workflow to assess machine health and determine required maintenance:

```mermaid
flowchart TD
    A[1. Receive Input Readings] --> B[2. Retrieve Historical Context]
    B --> C[3. Plan Tool Selection]
    C --> D[4. Execute Diagnostic Tools]
    D --> E[5. Evaluate Combined Signals]
    E --> F{Compound Issue or Rising Trend?}
    F -- Yes --> G[6. Replan & Adjust Severity]
    F -- No --> H[7. Generate & Persist Report]
    G --> H
