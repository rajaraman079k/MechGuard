*MechGuard AI*
Explainable, local-first machine maintenance decision support
MechGuard AI is an educational Agentic AI course project that turns machine readings into an explainable maintenance assessment. It combines deterministic diagnostic tools, a planning/evaluation workflow, historical context, and a Streamlit interface.
Safety note: This is a classroom prototype. Its thresholds are illustrative, not universal machine safety limits. Do not use its outputs as a substitute for manufacturer guidance, qualified engineering judgement, or site safety procedures.

Features
- Streamlit web interface with Overview, Agent workspace, Machine memory, CSV & trends, and System guide pages.
- Local account registration and sign-in.
- Passwords stored as salted PBKDF2-HMAC-SHA256 hashes (not plaintext).
- Diagnostic tools for temperature, vibration, and operating/service hours.
- Agent workflow with planning, tool execution, evaluation, historical trend context, and a readable reasoning trace.
- SQLite persistence for users and assessment reports.
- CSV upload and validation for sensor datasets.
- Trend charts for saved temperature and vibration readings.
- No paid APIs or cloud AI calls.
How the agent works
1. Receive input: machine name, temperature, vibration, and operating hours since service.
2. Retrieve context: inspect saved assessments for that user and machine.
3. Plan: choose diagnostic tools based on current readings and configured demo thresholds.
4. Execute tools: run thermal, vibration, and/or service checks as selected by the workflow.
5. Evaluate: combine tool results and severity signals.
6. Replan when appropriate: consider combined abnormalities or a rising historical trend.
7. Report and persist: present findings, severity, a suggested action plan, and the diagnostic trace; save the report to SQLite.
The current agent is a deterministic tool-using agent, not an LLM-powered chatbot and not a trained predictive model. The thresholds and trend checks are rule-based and should be described that way in a presentation.
Technology stack
- Python 3.10+
- Streamlit
- pandas
- SQLite (Python standard library)
- Python hashlib, hmac, and secrets for password hashing
Run locally
1. Install Python
Use a Python version supported by your installed Streamlit release. Python 3.12 is a reasonable choice.
2. Get the project
Clone the GitHub repository or download the project ZIP, then open a terminal in the project folder.
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
Replace the placeholder URL and folder name with your actual repository details.
3. Create and activate a virtual environment (recommended)
Windows CMD:
py -3.12 -m venv .venv
.venv\Scripts\activate
macOS/Linux:
python3 -m venv .venv
source .venv/bin/activate
4. Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
5. Launch the app
python -m streamlit run app.py
Streamlit prints a local URL, usually http://localhost:8501.
First use
1. Open the app.
2. Choose Create account and register a username (3–24 characters; letters, numbers, ., _, and -) and a password of at least 8 characters.
3. Sign in.
4. Open Agent workspace, enter a machine name and readings, and run an assessment.
5. Visit Machine memory to review saved assessments.
6. Open CSV & trends to upload a dataset or download the sample CSV.
CSV format
Required column names:
machine,temperature,vibration,operating_hours
Pump-M01,68,3.0,420
Pump-M01,80,5.2,600
Pump-M01,96,8.0,1200
The app also recognises some aliases such as machine_id, temperature_c, temp_c, vibration_mm_s_rms, and hours. Use the sample file sample_sensor_data.csv as a starting point.
Database and privacy
The app creates mechguard_history.db beside app.py when it runs. It contains:
- users: username, salt, password hash, account creation timestamp.
- assessments: readings, severity, risk score, summary, action plan, reasoning trace, timestamp, and username.
The database is intentionally excluded from Git by .gitignore. Do not commit a populated database, real credentials, or personal data.
Streamlit Community Cloud limitation
The app's SQLite database is stored on the app's local filesystem. On hosted environments, local files may not be durable across restarts, rebuilds, or redeployments. This version is intended for an educational demo; do not assume that hosted accounts or assessment history will persist indefinitely. A production deployment would need a managed persistent database and stronger authentication/session controls.
Configuration and demo thresholds
The current illustrative values are defined near the top of app.py:
Signal	Warning	Critical / due
Temperature	75 °C	90 °C
Vibration	4.5 mm/s RMS	7.1 mm/s RMS
Operating hours since service	—	1,000 hours


These are demonstration values only. Real thresholds depend on the machine, sensor, measurement method, operating conditions, and manufacturer recommendations.
Project files
mechguard/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── schema.sql
├── sample_sensor_data.csv
├── docs/
│   ├── PROJECT_REPORT.md
│   └── TEST_CASES.md
└── tests/
    └── MANUAL_TEST_CHECKLIST.md
Testing checklist
See [`docs/TEST_CASES.md`](docs/TEST_CASES.md) and [`tests/MANUAL_TEST_CHECKLIST.md`](tests/MANUAL_TEST_CHECKLIST.md). At minimum, test account creation, sign-in, all five navigation pages, normal and abnormal readings, history filtering, CSV validation, theme selection, and sign-out/quick-action navigation.
Known limitations
- Deterministic rules, not an LLM or trained predictive model.
- Trend detection is a simple heuristic, not statistical forecasting.
- Demo thresholds are not real-world safety limits.
- No connection to live sensors or machine control.
- Local SQLite persistence is not a production cloud database.
- Local account handling is for a classroom prototype, not enterprise identity/security.
Suggested viva explanation
“MechGuard AI is a local-first, explainable maintenance decision-support prototype. It uses a planner to select diagnostic tools, combines their results, checks historical context, and produces a prioritised action plan. It is deterministic and rule-based, so its decisions are reproducible and easy to inspect. The main future improvements would be stronger data validation, validated machine-specific thresholds, more robust trend analysis, persistent hosted storage, and evaluation against labelled maintenance data.”

License
Add a license file if your course or team requires one. Until then, the repository has no explicit open-source license.
