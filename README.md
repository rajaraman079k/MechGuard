# MechGuard AI — UI Edition

## Features
- Attractive landing/home page
- Local user registration and sign-in
- Passwords stored as salted PBKDF2-HMAC-SHA256 hashes, not plaintext
- Dark/light appearance switch
- Agent workspace, machine memory, CSV upload, trend charts, system guide
- Local SQLite assessment persistence scoped by username
- No paid APIs or cloud AI calls

## Run on Windows
Open CMD inside this folder:

```cmd
py -3.12 -m pip install -r requirements.txt
py -3.12 -m streamlit run app.py
```

If Python 3.12 is not available, use the Python version you installed and know works with Streamlit.

## First use
1. Create an account on the welcome page (username 3–24 characters; password at least 8 characters).
2. Sign in.
3. Use the sidebar to switch pages and select Dark or Light appearance.
4. Run assessments or upload a CSV.

## CSV columns
Required: `machine,temperature,vibration,operating_hours`

## Important
This local account feature is suitable for a classroom demo only. It is not a hardened multi-user production authentication system. All account and assessment data is stored on this computer. Thresholds are illustrative and are not real machine safety limits.
