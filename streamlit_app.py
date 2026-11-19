import os
import sys
from datetime import datetime

import pandas as pd
import streamlit as st

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import database as db
from agents.workflow import run_workflow
from ml import pipeline as P
from ml import sample_data as S
from services import chat, ingest, mitre, reports, threatintel

st.set_page_config(page_title="AI SOC Analyst", page_icon="SOC", layout="wide")
st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem;}
    .metric-card {border: 1px solid #26334d; border-radius: 12px; padding: 14px; background: #0f172a;}
    </style>
    """,
    unsafe_allow_html=True,
)

DATA_DIR = os.path.join(BACKEND, "datasets")
SAMPLE_CSV = os.path.join(DATA_DIR, "sample_traffic.csv")
CATEGORIES = ["Normal", "DoS", "DDoS", "PortScan", "BruteForce", "Botnet", "SuspiciousOutbound"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
STATUSES = ["Open", "Investigating", "Resolved", "False Positive"]


def ensure_ready():
    db.init_db()
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(SAMPLE_CSV):
        S.generate().to_csv(SAMPLE_CSV, index=False)
    if P.load() is None:
        with st.spinner("Training the bundled synthetic model..."):
            P.train(P.map_columns(pd.read_csv(SAMPLE_CSV))[0])


ensure_ready()


def simulate_traffic(n=600):
    df = S.generate(n_per=max(10, n // 6), seed=int(datetime.now().timestamp()) % 10000).head(n)
    df["ts"] = [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * len(df)
    ingest_report = ingest.ingest_df(df.drop(columns=["label"]), source="SIMULATED live traffic", simulated=1)
    return ingest_report, run_workflow()


def ingest_upload(uploaded_file, analyze=True):
    df = pd.read_csv(uploaded_file, skipinitialspace=True, low_memory=False)
    ingest_report = ingest.ingest_df(df, source=uploaded_file.name)
    workflow = run_workflow() if analyze else None
    return ingest_report, workflow


def dashboard_data():
    stats = db.q1(
        """
        SELECT
          (SELECT COUNT(*) FROM events) events,
          (SELECT COUNT(*) FROM alerts) alerts,
          (SELECT COUNT(*) FROM incidents WHERE severity='Critical') critical,
          (SELECT COUNT(*) FROM incidents WHERE severity='High') high,
          (SELECT COUNT(*) FROM incidents WHERE severity='Medium') medium,
          (SELECT COUNT(*) FROM incidents WHERE severity='Low') low,
          (SELECT COUNT(*) FROM incidents WHERE blocked=1) blocked,
          (SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved','False Positive')) active
        """
    )
    return {
        "stats": stats,
        "activity": db.q(
            "SELECT substr(ts,1,13)||':00' hour, COUNT(*) events, SUM(prediction!='Normal') suspicious "
            "FROM events GROUP BY 1 ORDER BY 1 LIMIT 48"
        ),
        "threat_distribution": db.q("SELECT severity name, COUNT(*) value FROM incidents GROUP BY severity"),
        "attack_categories": db.q("SELECT category name, COUNT(*) value FROM alerts GROUP BY category ORDER BY value DESC"),
        "recent_alerts": db.q(
            "SELECT id,ts,src_ip,dst_ip,category,confidence,severity FROM alerts ORDER BY id DESC LIMIT 10"
        ),
        "top_ips": db.q("SELECT src_ip, COUNT(*) alerts FROM alerts GROUP BY src_ip ORDER BY alerts DESC LIMIT 8"),
    }


def events_data(search="", protocol="", prediction="", suspicious_only=False, limit=50, offset=0):
    where, args = ["1=1"], []
    if search:
        where.append("(src_ip LIKE ? OR dst_ip LIKE ? OR CAST(dst_port AS TEXT)=?)")
        args += [f"%{search}%", f"%{search}%", search]
    if protocol:
        where.append("protocol=?")
        args.append(protocol)
    if prediction:
        where.append("prediction=?")
        args.append(prediction)
    if suspicious_only:
        where.append("prediction!='Normal'")
    clause = " AND ".join(where)
    total = db.q1(f"SELECT COUNT(*) n FROM events WHERE {clause}", args)["n"]
    rows = db.q(
        f"SELECT * FROM events WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        args + [min(limit, 500), offset],
    )
    return total, pd.DataFrame(rows)


def incidents_data(status="", severity=""):
    where, args = ["1=1"], []
    if status:
        where.append("status=?")
        args.append(status)
    if severity:
        where.append("severity=?")
        args.append(severity)
    rows = db.q(
        f"SELECT * FROM incidents WHERE {' AND '.join(where)} ORDER BY risk_score DESC",
        args,
    )
    for row in rows:
        for key in ("evidence", "response", "mitre", "intel"):
            row[key] = db.jl(row[key], {} if key != "mitre" and key != "intel" else None)
    return rows


def incident_detail(incident_id):
    row = db.q1("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not row:
        return None
    for key in ("evidence", "response", "mitre", "intel"):
        row[key] = db.jl(row[key], {} if key != "mitre" and key != "intel" else None)
    row["notes"] = db.q("SELECT * FROM notes WHERE incident_id=? ORDER BY id", (incident_id,))
    row["alerts"] = db.q("SELECT * FROM alerts WHERE incident_id=? ORDER BY id LIMIT 50", (incident_id,))
    return row


def update_incident(incident_id, status=None, severity=None, blocked=None):
    updates = []
    args = []
    if status:
        updates.append("status=?")
        args.append(status)
    if severity:
        updates.append("severity=?")
        args.append(severity)
    if blocked is not None:
        updates.append("blocked=?")
        args.append(int(blocked))
    if updates:
        db.ex(f"UPDATE incidents SET {', '.join(updates)} WHERE id=?", args + [incident_id])


def show_ingest_result(ingest_report, workflow=None, label=None):
    if label:
        st.warning(label)
    st.success(f"Ingested {ingest_report.get('rows', 0)} events.")
    st.write("Predictions:", ingest_report.get("predicted", {}))
    if workflow:
        st.write(f"Agents created {workflow['alerts_created']} alerts and {len(workflow['incidents_created'])} incidents.")
    if ingest_report.get("note"):
        st.info(ingest_report["note"])
    if ingest_report.get("sampled_to"):
        st.caption(f"Large file: a random sample of {ingest_report['sampled_to']} rows was analysed.")


def metric_cards(stats):
    cards = [
        ("Network events", stats.get("events", 0)),
        ("Security alerts", stats.get("alerts", 0)),
        ("Critical", stats.get("critical", 0)),
        ("High", stats.get("high", 0)),
        ("Medium", stats.get("medium", 0)),
        ("Low", stats.get("low", 0)),
        ("Blocked (simulated)", stats.get("blocked", 0)),
        ("Active incidents", stats.get("active", 0)),
    ]
    cols = st.columns(4)
    for index, (label, value) in enumerate(cards):
        cols[index % 4].metric(label, f"{value or 0:,}")


def dashboard_page():
    st.title("SOC Command Center")
    st.caption("All figures are computed from stored events in SQLite.")
    if st.button("Run simulated traffic", type="primary"):
        with st.spinner("Generating and analysing simulated traffic..."):
            ingest_report, workflow = simulate_traffic(600)
            show_ingest_result(
                ingest_report,
                workflow,
                "SIMULATED traffic (locally generated, not real internet monitoring)",
            )
    data = dashboard_data()
    stats = data["stats"]
    metric_cards(stats)
    if not stats or stats.get("events", 0) == 0:
        st.info("No data yet. Run simulated traffic or upload a CSV on Network Monitoring.")
        return

    left, right = st.columns([2, 1])
    with left:
        st.subheader("Network activity (events per hour)")
        activity = pd.DataFrame(data["activity"])
        if not activity.empty:
            activity["suspicious"] = activity["suspicious"].fillna(0)
            st.area_chart(activity.set_index("hour")[["events", "suspicious"]])
        else:
            st.caption("No hourly activity found.")
    with right:
        st.subheader("Threat distribution")
        threat = pd.DataFrame(data["threat_distribution"])
        if not threat.empty:
            st.bar_chart(threat.set_index("name")["value"])
        else:
            st.caption("No incidents yet.")

    left, right = st.columns([2, 1])
    with left:
        st.subheader("Attack frequency by category")
        categories = pd.DataFrame(data["attack_categories"])
        if not categories.empty:
            st.bar_chart(categories.set_index("name")["value"])
        else:
            st.caption("No alerts yet.")
    with right:
        st.subheader("Top suspicious IPs")
        if data["top_ips"]:
            st.dataframe(pd.DataFrame(data["top_ips"]), hide_index=True, use_container_width=True)
        else:
            st.caption("No suspicious IPs.")

    st.subheader("Recent security alerts")
    st.dataframe(pd.DataFrame(data["recent_alerts"]), hide_index=True, use_container_width=True)


def network_page():
    st.title("Network Traffic Monitoring")
    col1, col2 = st.columns([1, 1])
    with col1:
        uploaded = st.file_uploader("Upload a CSV file", type=["csv"])
        analyze_upload = st.checkbox("Run SOC workflow after upload", value=True)
        if uploaded and st.button("Ingest uploaded CSV", type="primary"):
            with st.spinner("Analysing CSV..."):
                try:
                    ingest_report, workflow = ingest_upload(uploaded, analyze=analyze_upload)
                    show_ingest_result(ingest_report, workflow)
                except Exception as exc:
                    st.error(f"Could not process CSV: {exc}")
    with col2:
        sim_count = st.slider("Simulated events", min_value=20, max_value=1000, value=300, step=20)
        if st.button("Generate simulated traffic"):
            with st.spinner("Generating simulated traffic..."):
                ingest_report, workflow = simulate_traffic(sim_count)
                show_ingest_result(
                    ingest_report,
                    workflow,
                    "SIMULATED traffic (locally generated, not real internet monitoring)",
                )

    st.divider()
    f1, f2, f3, f4 = st.columns([2, 1, 1, 1])
    search = f1.text_input("Search IP or port")
    protocol = f2.selectbox("Protocol", ["", "TCP", "UDP"])
    prediction = f3.selectbox("Class", [""] + CATEGORIES)
    suspicious_only = f4.checkbox("Suspicious only")

    page = st.session_state.get("network_page", 0)
    total, df = events_data(search, protocol, prediction, suspicious_only, limit=50, offset=page * 50)
    if df.empty:
        st.info("No events match. Upload a CSV or run simulated traffic.")
    else:
        display = df.copy()
        display["confidence_pct"] = (display["confidence"] * 100).round(0).astype("Int64")
        display["ip_simulated"] = display["ip_simulated"].fillna(0).astype(int)
        columns = [
            "ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packets",
            "duration", "bytes", "status", "prediction", "confidence_pct", "ip_simulated", "simulated",
        ]
        st.caption(f"{total:,} events · ip_simulated=1 means the IP was generated, not present in the dataset.")
        st.dataframe(display[columns], hide_index=True, use_container_width=True)

    prev_col, next_col = st.columns([1, 1])
    if prev_col.button("Previous", disabled=page == 0):
        st.session_state["network_page"] = max(0, page - 1)
        st.rerun()
    if next_col.button("Next", disabled=(page + 1) * 50 >= total):
        st.session_state["network_page"] = page + 1
        st.rerun()


def detection_page():
    st.title("Machine Learning Threat Detection")
    st.caption(
        "Random Forest classifies attack type; Isolation Forest flags unusual flows. "
        "Scores come from a held-out test split."
    )

    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Retrain on bundled sample", type="primary"):
            with st.spinner("Training model..."):
                metrics = P.train(P.map_columns(pd.read_csv(SAMPLE_CSV))[0])
                st.session_state["model_metrics"] = metrics
                st.success("Model retrained.")
    with col2:
        labelled = st.file_uploader("Train on labelled CSV", type=["csv"], key="training_csv")
        if labelled and st.button("Train on uploaded CSV"):
            with st.spinner("Training model..."):
                try:
                    df = pd.read_csv(labelled, skipinitialspace=True, low_memory=False)
                    mapped, mapping = P.map_columns(df)
                    if not mapping["has_label"]:
                        st.error("Training needs a 'Label' column.")
                    else:
                        metrics = P.train(mapped)
                        st.session_state["model_metrics"] = metrics
                        st.success("Model trained on uploaded CSV.")
                except Exception as exc:
                    st.error(f"Training failed: {exc}")

    metrics = P.metrics()
    if "model_metrics" in st.session_state:
        metrics = st.session_state["model_metrics"]
    if not metrics or "labels" not in metrics:
        st.info("No trained model metrics yet.")
        return

    cols = st.columns(4)
    for col, key, label in zip(cols, ["accuracy", "precision", "recall", "f1"], ["Accuracy", "Precision", "Recall", "F1-score"]):
        col.metric(label, f"{metrics[key] * 100:.2f}%")
    st.caption(
        f"Test rows: {metrics['test_rows']:,} · Train rows: {metrics['train_rows']:,} · "
        f"Isolation Forest precision {metrics['isolation_forest']['precision'] * 100:.1f}% · "
        f"recall {metrics['isolation_forest']['recall'] * 100:.1f}%"
    )

    left, right = st.columns(2)
    with left:
        st.subheader("Confusion matrix")
        labels = metrics["labels"]
        matrix = pd.DataFrame(metrics["confusion_matrix"], index=labels, columns=labels)
        st.dataframe(matrix, use_container_width=True)
    with right:
        st.subheader("Top feature importances")
        importance = pd.DataFrame(
            list(metrics["feature_importance"].items())[:10], columns=["feature", "importance"]
        )
        st.bar_chart(importance.set_index("feature"))

    st.subheader("Per-class results")
    rows = []
    for label in metrics["labels"]:
        item = metrics["per_class"][label]
        rows.append(
            {
                "Class": label,
                "Precision": f"{item['precision'] * 100:.1f}%",
                "Recall": f"{item['recall'] * 100:.1f}%",
                "F1": f"{item['f1-score'] * 100:.1f}%",
                "Support": item["support"],
            }
        )
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)


def analyst_page():
    st.title("AI SOC Analyst (6 local agents)")
    st.caption("Agents exchange structured JSON and run in this order. No external LLM or API is used.")

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = [
            {
                "from": "bot",
                "text": "I'm a local rule-based assistant, not an LLM. I answer from the SQLite database and detection engine.",
            }
        ]

    left, right = st.columns([1, 1])
    with left:
        st.subheader("Agent workflow")
        stages = [
            ("Detection", "ML + rules create alerts"),
            ("Investigation", "Correlates alerts into incidents"),
            ("Threat Intel", "Local indicator list (offline)"),
            ("Risk Assessment", "Scores severity"),
            ("Incident Response", "Recommends actions (not executed)"),
            ("Report", "Writes the summary"),
        ]
        for index, (name, description) in enumerate(stages, 1):
            st.markdown(f"**{index}. {name} Agent** — {description}")
        if st.button("Investigate new events", type="primary"):
            with st.spinner("Running six-agent workflow..."):
                result = run_workflow()
                st.session_state["workflow_result"] = result
        if "workflow_result" in st.session_state:
            result = st.session_state["workflow_result"]
            st.success(
                f"Created {result['alerts_created']} alerts and {len(result['incidents_created'])} incidents."
            )
            if result["incidents_created"]:
                st.dataframe(pd.DataFrame(result["incidents_created"]), hide_index=True)

    with right:
        st.subheader("Threat investigation chat")
        for message in st.session_state.chat_messages:
            if message["from"] == "me":
                st.chat_message("user").write(message["text"])
            else:
                st.chat_message("assistant").write(message["text"])

        suggestions = [
            "What are today's critical threats?",
            "Which attacks were detected?",
            "Show repeated failed connections",
            "Summarize the latest security events",
            "Explain incident 1",
            "What should I do about incident 1?",
        ]
        st.caption("Suggested questions")
        for suggestion in suggestions:
            if st.button(suggestion, key=f"suggest_{suggestion}"):
                st.session_state.chat_messages.append({"from": "me", "text": suggestion})
                st.session_state.chat_messages.append({"from": "bot", "text": chat.answer(suggestion)})
                st.rerun()

        question = st.text_input("Ask about threats, IPs or incidents", key="chat_input")
        if st.button("Send", disabled=not question.strip()):
            st.session_state.chat_messages.append({"from": "me", "text": question.strip()})
            st.session_state.chat_messages.append({"from": "bot", "text": chat.answer(question.strip())})
            st.rerun()


def incidents_page():
    st.title("Security Incidents")
    f1, f2 = st.columns(2)
    status_filter = f1.selectbox("Status", [""] + STATUSES)
    severity_filter = f2.selectbox("Severity", [""] + SEVERITIES)
    rows = incidents_data(status_filter, severity_filter)
    if not rows:
        st.info("No incidents. Run simulated traffic or upload a CSV.")
        return

    options = {
        f"INC-{row['id']:04d} · {row['threat_name']} · {row['severity']} · {row['status']}": row["id"]
        for row in rows
    }
    selected_label = st.selectbox("Select incident", list(options))
    selected_id = options[selected_label]
    detail = incident_detail(selected_id)
    if not detail:
        st.error("Incident not found.")
        return

    st.subheader(f"INC-{detail['id']:04d} · {detail['threat_name']}")
    cols = st.columns(3)
    fields = [
        ("Source IP", detail["src_ip"]),
        ("Destination", detail["dst_ip"]),
        ("Detected", detail["detected_at"]),
        ("Category", detail["category"]),
        ("ML prediction", detail["ml_prediction"]),
        ("Confidence", f"{detail['confidence'] * 100:.1f}%"),
        ("Risk score", detail["risk_score"]),
        ("Events", detail["event_count"]),
    ]
    for index, (label, value) in enumerate(fields):
        cols[index % 3].write(f"**{label}:** {value}")

    c1, c2, c3, c4 = st.columns(4)
    new_status = c1.selectbox("Status", STATUSES, index=STATUSES.index(detail["status"]))
    new_severity = c2.selectbox("Severity", SEVERITIES, index=SEVERITIES.index(detail["severity"]))
    if c3.button("Update incident"):
        update_incident(selected_id, status=new_status, severity=new_severity)
        st.rerun()
    if c4.button("Mark resolved"):
        update_incident(selected_id, status="Resolved")
        st.rerun()
    if st.button("Simulate block" if not detail["blocked"] else "Unmark simulated block"):
        update_incident(selected_id, blocked=not detail["blocked"])
        st.rerun()
    if detail["blocked"]:
        st.warning("This is a simulated block flag only; no network change is performed.")

    st.markdown("### Investigation summary")
    st.write(detail["summary"])
    if detail.get("intel"):
        st.info(
            f"Local intel: {detail['intel'].get('tag', 'Not listed')} "
            "(offline list, no live lookup)."
        )
    if detail.get("mitre"):
        st.write(f"**MITRE:** {detail['mitre'].get('id')} {detail['mitre'].get('name')}")

    st.markdown("### Evidence")
    evidence = detail.get("evidence") or {}
    if evidence:
        st.write(
            f"- {evidence.get('alert_count', 0)} correlated alerts, "
            f"{evidence.get('first_seen', '')} to {evidence.get('last_seen', '')}"
        )
        st.write(
            f"- {evidence.get('failed_or_empty_connections', 0)} failed/empty connections; "
            f"{evidence.get('distinct_dst_ports', 0)} distinct destination ports"
        )
        if evidence.get("unusual_ports"):
            st.write(f"- Unusual ports: {', '.join(map(str, evidence['unusual_ports']))}")
        if evidence.get("rules"):
            st.write(f"- Rules: {' | '.join(evidence['rules'])}")
        st.write(f"- Top contributing features: {evidence.get('sample_explanation', '')}")

    st.markdown("### Recommended response")
    st.caption("Recommendations only; nothing is executed.")
    response = detail.get("response") or {}
    for action in response.get("actions", []):
        st.write(f"- {action}")

    st.markdown("### Analyst notes")
    for note in detail["notes"]:
        st.write(f"**{note['created_at']} · {note['author']}**")
        st.write(note["text"])
    note_text = st.text_input("Add an investigation note", key=f"note_{selected_id}")
    if st.button("Add note") and note_text.strip():
        db.ex(
            "INSERT INTO notes(incident_id,author,text,created_at) VALUES(?,?,?,?)",
            (selected_id, "streamlit-analyst", note_text.strip(), datetime.now().isoformat(timespec="seconds")),
        )
        st.rerun()

    report_rep = reports.build("incident", selected_id)
    d1, d2 = st.columns(2)
    d1.download_button(
        "Download incident PDF",
        data=reports.to_pdf(report_rep),
        file_name=f"incident_{selected_id}_report.pdf",
        mime="application/pdf",
    )
    d2.download_button(
        "Download incident CSV",
        data=reports.to_csv(report_rep),
        file_name=f"incident_{selected_id}_report.csv",
        mime="text/csv",
    )


def mitre_page():
    st.title("MITRE ATT&CK Mapping")
    st.caption("Mappings are stored locally and applied to the attack category of each incident.")
    detected = []
    for category_row in db.q("SELECT category, COUNT(*) n, MIN(id) example FROM incidents GROUP BY category"):
        mapped = mitre.lookup(category_row["category"])
        if mapped:
            detected.append({**mapped, "category": category_row["category"], "related_incidents": category_row["n"], "example_incident": category_row["example"]})
    if not detected:
        st.info("No detected activity to map yet.")
    else:
        for item in detected:
            with st.container(border=True):
                st.write(f"**{item['id']} {item['name']}** · {item['tactic']}")
                st.write(item["description"])
                st.write(
                    f"Related detection: **{item['category']}** · {item['related_incidents']} incident(s), "
                    f"e.g. INC-{item['example_incident']:04d}"
                )
                st.write(f"**Mitigation:** {item['mitigation']}")

    st.subheader("Local technique reference")
    st.dataframe(pd.DataFrame(list(mitre.MITRE.values())), hide_index=True, use_container_width=True)


def reports_page():
    st.title("Reports & Analytics")
    report_types = [
        ("daily", "Daily security report", "Incidents by severity, top incidents and alert categories."),
        ("weekly", "Weekly threat summary", "Same breakdown framed as a weekly summary of stored data."),
        ("traffic", "Network traffic analysis", "Protocols, top talkers and most-used destination ports."),
        ("classification", "Attack classification report", "Model predictions and average confidence per class."),
    ]
    for kind, title, description in report_types:
        with st.container(border=True):
            st.subheader(title)
            st.write(description)
            rep = reports.build(kind)
            c1, c2 = st.columns(2)
            c1.download_button(
                "PDF",
                data=reports.to_pdf(rep),
                file_name=f"{kind}_report.pdf",
                mime="application/pdf",
            )
            c2.download_button(
                "CSV",
                data=reports.to_csv(rep),
                file_name=f"{kind}_report.csv",
                mime="text/csv",
            )
    st.caption("Incident investigation reports are available on the Incidents page. Reports use data currently in the database.")


def settings_page():
    st.title("Settings")
    st.subheader("System status")
    st.write(f"Model: {'trained' if P.load() is not None else 'not trained'}")
    st.caption("Everything runs locally inside Streamlit. No external APIs, API keys or cloud services are used.")

    st.subheader("Threat intelligence")
    st.dataframe(pd.DataFrame(list(threatintel.LOCAL_INTEL.items()), columns=["ip", "details"]), hide_index=True)

    st.subheader("Data")
    confirmed = st.checkbox("I understand this deletes all events, alerts, incidents and notes")
    if st.button("Clear all events and incidents", disabled=not confirmed):
        db.reset_db()
        st.success("Database cleared. Trained models are kept.")
        st.rerun()


PAGES = {
    "Dashboard": dashboard_page,
    "Network Monitoring": network_page,
    "Threat Detection": detection_page,
    "AI SOC Analyst": analyst_page,
    "Incidents": incidents_page,
    "MITRE ATT&CK": mitre_page,
    "Reports & Analytics": reports_page,
    "Settings": settings_page,
}

st.sidebar.title("SOC ANALYST")
st.sidebar.caption("LOCAL · NO EXTERNAL APIs")
page = st.sidebar.radio("Navigate", list(PAGES))
PAGES[page]()
