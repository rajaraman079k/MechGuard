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
