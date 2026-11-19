import html as html_lib
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
    :root {
        --bg: #050816;
        --panel: #0b1220;
        --panel-2: #111a2e;
        --border: #243352;
        --text: #e5edf8;
        --muted: #8ea0bd;
        --cyan: #22d3ee;
        --blue: #60a5fa;
        --green: #34d399;
        --amber: #fbbf24;
        --orange: #fb923c;
        --red: #f87171;
    }

    html, body, .stApp {
        background:
            radial-gradient(circle at top left, rgba(34, 211, 238, 0.10), transparent 28%),
            radial-gradient(circle at top right, rgba(96, 165, 250, 0.10), transparent 30%),
            linear-gradient(180deg, #050816 0%, #08101f 100%);
        color: var(--text);
    }

    .block-container {padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1500px;}
    [data-testid="stHeader"] {background: transparent;}
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a1120 0%, #0d1830 100%);
        border-right: 1px solid var(--border);
    }
    [data-testid="stSidebar"] .stRadio > div {gap: 0.35rem;}
    [data-testid="stSidebar"] .stRadio label {
        padding: 0.72rem 0.8rem;
        border-radius: 12px;
        color: #aebbd2;
        border: 1px solid transparent;
    }
    [data-testid="stSidebar"] .stRadio label:has(input:checked) {
        background: rgba(34, 211, 238, 0.12);
        border-color: rgba(34, 211, 238, 0.35);
        color: #ffffff;
    }

    .soc-hero {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
        margin-bottom: 1.25rem;
        padding: 1.1rem 1.25rem;
        border: 1px solid var(--border);
        border-radius: 18px;
        background: linear-gradient(135deg, rgba(17, 26, 46, 0.92), rgba(8, 16, 31, 0.88));
        box-shadow: 0 18px 50px rgba(0, 0, 0, 0.25);
    }
    .soc-hero h1 {margin: 0; font-size: 2rem; letter-spacing: -0.03em;}
    .soc-hero p {margin: 0.35rem 0 0; color: var(--muted);}
    .soc-hero-meta {display: flex; gap: 0.5rem; flex-wrap: wrap; justify-content: flex-end;}

    .soc-kpi {
        min-height: 112px;
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem;
        background: linear-gradient(145deg, rgba(17, 26, 46, 0.95), rgba(10, 18, 32, 0.9));
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
    }
    .soc-kpi-label {font-size: 0.78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em;}
    .soc-kpi-value {font-size: 1.9rem; font-weight: 800; margin-top: 0.35rem; letter-spacing: -0.04em;}
    .soc-kpi-hint {font-size: 0.75rem; color: var(--muted); margin-top: 0.25rem;}
    .soc-kpi-cyan .soc-kpi-value {color: var(--cyan);}
    .soc-kpi-blue .soc-kpi-value {color: var(--blue);}
    .soc-kpi-green .soc-kpi-value {color: var(--green);}
    .soc-kpi-amber .soc-kpi-value {color: var(--amber);}
    .soc-kpi-orange .soc-kpi-value {color: var(--orange);}
    .soc-kpi-red .soc-kpi-value {color: var(--red);}

    .soc-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        border-radius: 999px;
        padding: 0.2rem 0.65rem;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        border: 1px solid transparent;
        white-space: nowrap;
    }
    .soc-badge-cyan {color: #a5f3fc; background: rgba(34,211,238,.12); border-color: rgba(34,211,238,.28);}
    .soc-badge-blue {color: #bfdbfe; background: rgba(96,165,250,.12); border-color: rgba(96,165,250,.28);}
    .soc-badge-green {color: #bbf7d0; background: rgba(52,211,153,.12); border-color: rgba(52,211,153,.28);}
    .soc-badge-amber {color: #fde68a; background: rgba(251,191,36,.12); border-color: rgba(251,191,36,.28);}
    .soc-badge-orange {color: #fed7aa; background: rgba(251,146,60,.12); border-color: rgba(251,146,60,.28);}
    .soc-badge-red {color: #fecaca; background: rgba(248,113,113,.12); border-color: rgba(248,113,113,.30);}
    .soc-badge-slate {color: #cbd5e1; background: rgba(148,163,184,.12); border-color: rgba(148,163,184,.25);}

    .soc-panel {
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 1rem;
        background: rgba(11, 18, 32, 0.78);
    }
    .soc-panel-title {font-size: 1rem; font-weight: 800; margin: 0 0 0.75rem;}
    .soc-panel-subtitle {color: var(--muted); font-size: 0.82rem; margin-top: -0.5rem; margin-bottom: 1rem;}

    .stButton > button {
        border-radius: 12px;
        border: 1px solid var(--border);
        background: #111a2e;
        color: var(--text);
        font-weight: 650;
        transition: transform .15s ease, border-color .15s ease, background .15s ease;
    }
    .stButton > button:hover {
        border-color: rgba(34, 211, 238, 0.45);
        transform: translateY(-1px);
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #0891b2, #2563eb);
        border-color: rgba(96, 165, 250, 0.5);
        color: white;
    }
    .stButton > button[kind="primary"]:hover {filter: brightness(1.08);}

    [data-testid="stMetric"] {
        background: linear-gradient(145deg, rgba(17,26,46,.95), rgba(10,18,32,.9));
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem;
    }
    [data-testid="stDataFrame"], [data-testid="stTable"] {
        border: 1px solid var(--border);
        border-radius: 14px;
        overflow: hidden;
    }
    [data-baseweb="tab-list"] {gap: 0.4rem;}
    [data-baseweb="tab"] {
        border-radius: 12px 12px 0 0;
        border: 1px solid var(--border);
        background: #0d1730;
        color: #aebbd2;
    }
    [data-baseweb="tab"][aria-selected="true"] {
        background: #13213b;
        color: #fff;
        border-bottom-color: #13213b;
    }
    .streamlit-expanderHeader {
        border: 1px solid var(--border);
        border-radius: 14px;
        background: rgba(17,26,46,.75);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

DATA_DIR = os.path.join(BACKEND, "datasets")
SAMPLE_CSV = os.path.join(DATA_DIR, "sample_traffic.csv")
CATEGORIES = ["Normal", "DoS", "DDoS", "PortScan", "BruteForce", "Botnet", "SuspiciousOutbound"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
STATUSES = ["Open", "Investigating", "Resolved", "False Positive"]
SEVERITY_TONES = {
    "Critical": "red",
    "High": "orange",
    "Medium": "amber",
    "Low": "cyan",
    "Normal": "green",
}
NAV_LABELS = {
    "Dashboard": "01 · Dashboard",
    "Network Monitoring": "02 · Network Monitoring",
    "Threat Detection": "03 · Threat Detection",
    "AI SOC Analyst": "04 · AI SOC Analyst",
    "Incidents": "05 · Incidents",
    "MITRE ATT&CK": "06 · MITRE ATT&CK",
    "Reports & Analytics": "07 · Reports & Analytics",
    "Settings": "08 · Settings",
}


def esc(value):
    return html_lib.escape(str(value))


def badge(text, tone="cyan"):
    return f'<span class="soc-badge soc-badge-{tone}">{esc(text)}</span>'


def severity_badge(value):
    return badge(value, SEVERITY_TONES.get(value, "slate"))


def page_header(title, subtitle="", badges=None):
    meta = "".join(badges or [])
    st.markdown(
        f"""
        <div class="soc-hero">
            <div>
                <h1>{esc(title)}</h1>
                <p>{esc(subtitle)}</p>
            </div>
            <div class="soc-hero-meta">{meta}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def panel(title, subtitle=None):
    subtitle_html = f'<div class="soc-panel-subtitle">{esc(subtitle)}</div>' if subtitle else ""
    st.markdown(f'<div class="soc-panel-title">{esc(title)}</div>{subtitle_html}', unsafe_allow_html=True)


def kpi(label, value, hint="", tone="cyan"):
    st.markdown(
        f"""
        <div class="soc-kpi soc-kpi-{tone}">
            <div class="soc-kpi-label">{esc(label)}</div>
            <div class="soc-kpi-value">{esc(value)}</div>
            <div class="soc-kpi-hint">{esc(hint)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def empty_state(title="No data yet", message="Run simulated traffic or upload a CSV to populate the SOC dashboard."):
    st.markdown(
        f"""
        <div class="soc-panel" style="text-align:center; padding:2rem;">
            <div style="font-size:1.15rem;font-weight:800;margin-bottom:.4rem;">{esc(title)}</div>
            <div style="color:var(--muted);">{esc(message)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


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
    ) or {}
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
    suspicious = db.q1(
        f"SELECT COUNT(*) n FROM events WHERE {clause} AND prediction!='Normal'", args
    )["n"]
    rows = db.q(
        f"SELECT * FROM events WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        args + [min(limit, 500), offset],
    )
    return total, suspicious, pd.DataFrame(rows)


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
            row[key] = db.jl(row[key], {} if key in ("evidence", "response") else None)
    return rows


def incident_detail(incident_id):
    row = db.q1("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not row:
        return None
    for key in ("evidence", "response", "mitre", "intel"):
        row[key] = db.jl(row[key], {} if key in ("evidence", "response") else None)
    row["notes"] = db.q("SELECT * FROM notes WHERE incident_id=? ORDER BY id", (incident_id,))
    row["alerts"] = db.q("SELECT * FROM alerts WHERE incident_id=? ORDER BY id LIMIT 50", (incident_id,))
    return row


def update_incident(incident_id, status=None, severity=None, blocked=None):
    updates, args = [], []
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
    with st.container(border=True):
        panel("Ingest complete")
        cols = st.columns(3)
        cols[0].metric("Rows analysed", f"{ingest_report.get('rows', 0):,}")
        if workflow:
            cols[1].metric("Alerts created", workflow.get("alerts_created", 0))
            cols[2].metric("Incidents created", len(workflow.get("incidents_created", [])))
        else:
            cols[1].metric("Predicted classes", len(ingest_report.get("predicted", {})))
            cols[2].metric("Sampled", ingest_report.get("sampled_to", "No"))
        st.write("Predictions:", ingest_report.get("predicted", {}))
        if ingest_report.get("note"):
            st.info(ingest_report["note"])
        if ingest_report.get("sampled_to"):
            st.caption(f"Large file: a random sample of {ingest_report['sampled_to']} rows was analysed.")


def metric_cards(stats):
    cards = [
        ("Network events", stats.get("events", 0), "Stored flow records", "cyan"),
        ("Security alerts", stats.get("alerts", 0), "Detection engine output", "blue"),
        ("Critical", stats.get("critical", 0), "Highest priority incidents", "red"),
        ("High", stats.get("high", 0), "Requires urgent review", "orange"),
        ("Medium", stats.get("medium", 0), "Needs investigation", "amber"),
        ("Low", stats.get("low", 0), "Monitor and correlate", "cyan"),
        ("Blocked", stats.get("blocked", 0), "Simulated block flag only", "blue"),
        ("Active incidents", stats.get("active", 0), "Open or in progress", "green"),
    ]
    for row_start in range(0, len(cards), 4):
        cols = st.columns(4)
        for col, (label, value, hint, tone) in zip(cols, cards[row_start:row_start + 4]):
            with col:
                kpi(label, f"{value or 0:,}", hint, tone)


def style_events(df):
    def prediction_style(value):
        if value == "Normal":
            return "color:#86efac;background:rgba(52,211,153,.10);"
        return "color:#fecaca;background:rgba(248,113,113,.12);font-weight:700;"

    if df.empty:
        return df
    return df.style.map(prediction_style, subset=["prediction"])


def go_to_page(page_name):
    st.session_state["nav_select"] = page_name


def dashboard_page():
    page_header(
        "SOC Command Center",
        "Live operational view computed from stored SQLite events and the local detection workflow.",
        [badge("LOCAL", "green"), badge("NO EXTERNAL APIs", "blue"), badge("SIMULATION LABELLED", "amber")],
    )

    action1, action2, action3 = st.columns([1, 1, 1])
    with action1:
        if st.button("Run simulated traffic", type="primary", width="stretch"):
            with st.spinner("Generating and analysing simulated traffic..."):
                ingest_report, workflow = simulate_traffic(600)
                show_ingest_result(
                    ingest_report,
                    workflow,
                    "SIMULATED traffic (locally generated, not real internet monitoring)",
                )
    with action2:
        if st.button("Investigate new events", width="stretch"):
            with st.spinner("Running six-agent workflow..."):
                result = run_workflow()
                st.session_state["workflow_result"] = result
                st.success(f"Created {result['alerts_created']} alerts and {len(result['incidents_created'])} incidents.")
    with action3:
        st.button("Open incidents", on_click=go_to_page, args=("Incidents",), width="stretch")

    data = dashboard_data()
    stats = data["stats"]
    metric_cards(stats)
    if not stats.get("events"):
        empty_state()
        return

    tab_activity, tab_alerts, tab_recent = st.tabs(["Activity & Threats", "Attack Analytics", "Recent Alerts"])
    with tab_activity:
        left, right = st.columns([3, 2])
        with left:
            panel("Network activity", "Events and suspicious predictions per hour")
            activity = pd.DataFrame(data["activity"])
            if not activity.empty:
                activity["suspicious"] = activity["suspicious"].fillna(0)
                st.area_chart(activity.set_index("hour")[["events", "suspicious"]])
            else:
                st.caption("No hourly activity found.")
        with right:
            panel("Threat distribution", "Incidents grouped by severity")
            threat = pd.DataFrame(data["threat_distribution"])
            if not threat.empty:
                st.bar_chart(threat.set_index("name")["value"])
            else:
                st.caption("No incidents yet.")

    with tab_alerts:
        left, right = st.columns([3, 2])
        with left:
            panel("Attack frequency", "Alert count by category")
            categories = pd.DataFrame(data["attack_categories"])
            if not categories.empty:
                st.bar_chart(categories.set_index("name")["value"])
            else:
                st.caption("No alerts yet.")
        with right:
            panel("Top suspicious IPs", "Highest alert-producing sources")
            if data["top_ips"]:
                st.dataframe(pd.DataFrame(data["top_ips"]), hide_index=True, width="stretch")
            else:
                st.caption("No suspicious IPs.")

    with tab_recent:
        panel("Recent security alerts", "Latest correlated detections")
        recent = pd.DataFrame(data["recent_alerts"])
        if not recent.empty:
            recent["confidence_pct"] = (recent["confidence"] * 100).round(0).astype("Int64")
            recent = recent.rename(columns={"confidence_pct": "confidence_pct"})
            st.dataframe(recent, hide_index=True, width="stretch")
        else:
            st.caption("No recent alerts.")


def network_page():
    page_header(
        "Network Traffic Monitoring",
        "Upload labelled or unlabelled CSV flow data, generate simulated traffic, and inspect stored events.",
        [badge("CSV UPLOAD", "blue"), badge("LOCAL INFERENCE", "green")],
    )

    left, right = st.columns([3, 2])
    with left:
        with st.container(border=True):
            panel("Ingest traffic")
            uploaded = st.file_uploader("Upload a CSV file", type=["csv"])
            analyze_upload = st.checkbox("Run SOC workflow after upload", value=True)
            if uploaded and st.button("Ingest uploaded CSV", type="primary", width="stretch"):
                with st.spinner("Analysing CSV..."):
                    try:
                        ingest_report, workflow = ingest_upload(uploaded, analyze=analyze_upload)
                        show_ingest_result(ingest_report, workflow)
                    except Exception as exc:
                        st.error(f"Could not process CSV: {exc}")
    with right:
        with st.container(border=True):
            panel("Simulated traffic")
            sim_count = st.slider("Events to generate", min_value=20, max_value=1000, value=300, step=20)
            if st.button("Generate simulated traffic", width="stretch"):
                with st.spinner("Generating simulated traffic..."):
                    ingest_report, workflow = simulate_traffic(sim_count)
                    show_ingest_result(
                        ingest_report,
                        workflow,
                        "SIMULATED traffic (locally generated, not real internet monitoring)",
                    )

    st.divider()
    with st.container(border=True):
        panel("Event explorer", "Filter stored network events")
        f1, f2, f3, f4 = st.columns([2, 1, 1, 1])
        search = f1.text_input("Search IP or port", placeholder="e.g. 203.0.113.45 or 443")
        protocol = f2.selectbox("Protocol", ["", "TCP", "UDP"])
        prediction = f3.selectbox("Class", [""] + CATEGORIES)
        suspicious_only = f4.checkbox("Suspicious only")

    page = st.session_state.get("network_page", 0)
    filter_key = (search, protocol, prediction, suspicious_only)
    if st.session_state.get("network_filter_key") != filter_key:
        st.session_state["network_filter_key"] = filter_key
        st.session_state["network_page"] = 0
        page = 0

    total, suspicious, df = events_data(search, protocol, prediction, suspicious_only, limit=50, offset=page * 50)
    cols = st.columns(4)
    cols[0].metric("Matching events", f"{total:,}")
    cols[1].metric("Suspicious matches", f"{suspicious:,}")
    cols[2].metric("Page", f"{page + 1}")
    cols[3].metric("Rows on page", f"{len(df):,}")

    if df.empty:
        empty_state("No matching events", "Adjust filters, upload a CSV, or run simulated traffic.")
    else:
        display = df.copy()
        display["confidence_pct"] = (display["confidence"] * 100).round(0).astype("Int64")
        display["ip_simulated"] = display["ip_simulated"].fillna(0).astype(int)
        columns = [
            "ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packets",
            "duration", "bytes", "status", "prediction", "confidence_pct", "ip_simulated", "simulated",
        ]
        st.caption("ip_simulated=1 means the IP was generated locally and is not present in the source dataset.")
        st.dataframe(style_events(display[columns]), hide_index=True, width="stretch")

    prev_col, page_col, next_col = st.columns([1, 2, 1])
    prev_col.button("Previous", disabled=page == 0, width="stretch", on_click=lambda: st.session_state.update(network_page=max(0, page - 1)))
    page_col.markdown(f"<div style='text-align:center;color:var(--muted);padding-top:.6rem;'>Showing {page * 50 + 1:,}–{min(total, (page + 1) * 50):,} of {total:,}</div>", unsafe_allow_html=True)
    next_col.button("Next", disabled=(page + 1) * 50 >= total, width="stretch", on_click=lambda: st.session_state.update(network_page=page + 1))
    if page_col.button("Refresh view", width="stretch"):
        st.rerun()


def confusion_heatmap(matrix, labels):
    frame = pd.DataFrame(matrix, index=labels, columns=labels)
    max_value = max(1, frame.values.max())

    def heat(value):
        alpha = 0.08 + (0.55 * value / max_value)
        return f"background-color: rgba(34,211,238,{alpha:.2f}); color:#fff; font-weight:600;"

    return frame.style.map(heat)


def detection_page():
    page_header(
        "Machine Learning Threat Detection",
        "Random Forest classifies attack type while Isolation Forest flags unusual flows using held-out test metrics.",
        [badge("RANDOM FOREST", "blue"), badge("ISOLATION FOREST", "cyan")],
    )

    col1, col2 = st.columns([1, 1])
    with col1:
        with st.container(border=True):
            panel("Bundled model")
            st.write("Retrain using the synthetic CICIDS-style sample dataset.")
            if st.button("Retrain on bundled sample", type="primary", width="stretch"):
                with st.spinner("Training model..."):
                    metrics = P.train(P.map_columns(pd.read_csv(SAMPLE_CSV))[0])
                    st.session_state["model_metrics"] = metrics
                    st.success("Model retrained.")
    with col2:
        with st.container(border=True):
            panel("Custom labelled data")
            labelled = st.file_uploader("Train on labelled CSV", type=["csv"], key="training_csv")
            st.caption("The CSV must include a Label column.")
            if labelled and st.button("Train on uploaded CSV", width="stretch"):
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

    metrics = st.session_state.get("model_metrics") or P.metrics()
    if not metrics or "labels" not in metrics:
        empty_state("No trained model metrics", "Train the bundled sample or upload a labelled CSV.")
        return

    cards = [
        ("Accuracy", metrics["accuracy"], "Overall test accuracy", "green"),
        ("Precision", metrics["precision"], "Weighted precision", "cyan"),
        ("Recall", metrics["recall"], "Weighted recall", "blue"),
        ("F1-score", metrics["f1"], "Weighted F1", "amber"),
    ]
    cols = st.columns(4)
    for col, (label, value, hint, tone) in zip(cols, cards):
        with col:
            kpi(label, f"{value * 100:.2f}%", hint, tone)
    st.caption(
        f"Test rows: {metrics['test_rows']:,} · Train rows: {metrics['train_rows']:,} · "
        f"Isolation Forest precision {metrics['isolation_forest']['precision'] * 100:.1f}% · "
        f"recall {metrics['isolation_forest']['recall'] * 100:.1f}%"
    )

    tab_matrix, tab_features, tab_classes = st.tabs(["Confusion Matrix", "Feature Importance", "Per-Class Results"])
    with tab_matrix:
        with st.container(border=True):
            panel("Confusion matrix", "Rows are actual labels; columns are predictions")
            st.dataframe(
                confusion_heatmap(metrics["confusion_matrix"], metrics["labels"]),
                width="stretch",
            )
    with tab_features:
        with st.container(border=True):
            panel("Top feature importances", "Most influential model features")
            importance = pd.DataFrame(
                list(metrics["feature_importance"].items())[:12], columns=["feature", "importance"]
            )
            st.bar_chart(importance.set_index("feature"))
    with tab_classes:
        with st.container(border=True):
            panel("Per-class results", "Precision, recall and F1 by attack category")
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
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def append_chat_message(sender, text):
    st.session_state.chat_messages.append({"from": sender, "text": text})


def analyst_page():
    page_header(
        "AI SOC Analyst",
        "Six local agents investigate events sequentially and a rule-based assistant answers from stored data.",
        [badge("6 AGENTS", "cyan"), badge("RULE-BASED CHAT", "blue"), badge("NO LLM", "amber")],
    )

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = [
            {
                "from": "bot",
                "text": "I'm a local rule-based assistant, not an LLM. I answer from the SQLite database and detection engine.",
            }
        ]

    left, right = st.columns([2, 3])
    with left:
        with st.container(border=True):
            panel("Agent workflow", "Detection → Investigation → Threat Intel → Risk → Response → Report")
            stages = [
                ("01", "Detection", "ML + rules create alerts"),
                ("02", "Investigation", "Correlates alerts into incidents"),
                ("03", "Threat Intel", "Local indicator list (offline)"),
                ("04", "Risk Assessment", "Scores severity"),
                ("05", "Incident Response", "Recommends actions"),
                ("06", "Report", "Writes the summary"),
            ]
            for number, name, description in stages:
                st.markdown(
                    f"""
                    <div style="display:flex;gap:.75rem;align-items:flex-start;margin:.55rem 0;">
                        <div style="min-width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;background:rgba(34,211,238,.12);border:1px solid rgba(34,211,238,.3);color:#67e8f9;font-weight:800;">{number}</div>
                        <div><div style="font-weight:750;">{esc(name)}</div><div style="color:var(--muted);font-size:.82rem;">{esc(description)}</div></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            if st.button("Investigate new events", type="primary", width="stretch"):
                with st.spinner("Running six-agent workflow..."):
                    result = run_workflow()
                    st.session_state["workflow_result"] = result
            if "workflow_result" in st.session_state:
                result = st.session_state["workflow_result"]
                st.success(f"Created {result['alerts_created']} alerts and {len(result['incidents_created'])} incidents.")
                if result["incidents_created"]:
                    st.dataframe(pd.DataFrame(result["incidents_created"]), hide_index=True, width="stretch")

    with right:
        with st.container(border=True):
            panel("Threat investigation chat", "Ask about threats, IPs, failed connections and incidents")
            chat_box = st.container(height=430)
            with chat_box:
                for message in st.session_state.chat_messages[-30:]:
                    if message["from"] == "me":
                        st.chat_message("user").write(message["text"])
                    else:
                        st.chat_message("assistant").write(message["text"])

            st.caption("Suggested questions")
            suggestions = [
                "What are today's critical threats?",
                "Which attacks were detected?",
                "Show repeated failed connections",
                "Summarize the latest security events",
                "Explain incident 1",
                "What should I do about incident 1?",
            ]
            for index in range(0, len(suggestions), 2):
                cols = st.columns(2)
                for col, suggestion in zip(cols, suggestions[index:index + 2]):
                    if col.button(suggestion, key=f"suggest_{index}_{suggestion}", width="stretch"):
                        append_chat_message("me", suggestion)
                        append_chat_message("bot", chat.answer(suggestion))
                        st.rerun()

            question = st.text_input("Ask about threats, IPs or incidents", key="chat_input", label_visibility="collapsed")
            if st.button("Send message", type="primary", width="stretch", disabled=not question.strip()):
                append_chat_message("me", question.strip())
                append_chat_message("bot", chat.answer(question.strip()))
                st.rerun()


def incident_field(label, value):
    st.markdown(
        f"""
        <div style="border:1px solid var(--border);border-radius:12px;padding:.7rem;background:rgba(17,26,46,.7);">
            <div style="font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;">{esc(label)}</div>
            <div style="font-weight:700;margin-top:.25rem;word-break:break-word;">{esc(value)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def incidents_page():
    page_header(
        "Security Incidents",
        "Investigate correlated alerts, update workflow state, add analyst notes and export reports.",
        [badge("CORRELATION ENGINE", "cyan"), badge("RECOMMENDATIONS ONLY", "amber")],
    )
    f1, f2 = st.columns(2)
    status_filter = f1.selectbox("Status", [""] + STATUSES)
    severity_filter = f2.selectbox("Severity", [""] + SEVERITIES)
    rows = incidents_data(status_filter, severity_filter)
    if not rows:
        empty_state("No incidents found", "Run simulated traffic or upload a CSV, then investigate new events.")
        return

    left, right = st.columns([2, 3])
    with left:
        with st.container(border=True):
            panel("Incident queue", f"{len(rows)} matching incident(s)")
            options = {
                f"INC-{row['id']:04d} · {row['threat_name']} · {row['severity']} · {row['status']}": row["id"]
                for row in rows
            }
            selected_label = st.selectbox("Select incident", list(options), label_visibility="collapsed")
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "id": f"INC-{row['id']:04d}",
                            "threat": row["threat_name"],
                            "severity": row["severity"],
                            "status": row["status"],
                            "risk": row["risk_score"],
                            "alerts": row["event_count"],
                        }
                        for row in rows[:20]
                    ]
                ),
                hide_index=True,
                width="stretch",
            )

    with right:
        detail = incident_detail(options[selected_label])
        if not detail:
            st.error("Incident not found.")
            return
        with st.container(border=True):
            panel(f"INC-{detail['id']:04d} · {detail['threat_name']}", f"Detected {detail['detected_at']}")
            tabs = st.tabs(["Overview", "Evidence", "Response", "Notes & Reports"])
            with tabs[0]:
                cols = st.columns(4)
                fields = [
                    ("Source IP", detail["src_ip"]),
                    ("Destination", detail["dst_ip"]),
                    ("Category", detail["category"]),
                    ("ML prediction", detail["ml_prediction"]),
                    ("Confidence", f"{detail['confidence'] * 100:.1f}%"),
                    ("Risk score", detail["risk_score"]),
                    ("Events", detail["event_count"]),
                    ("Status", detail["status"]),
                ]
                for index, (label, value) in enumerate(fields):
                    with cols[index % 4]:
                        incident_field(label, value)
                st.divider()
                c1, c2, c3, c4 = st.columns(4)
                new_status = c1.selectbox("Status", STATUSES, index=STATUSES.index(detail["status"]), key=f"status_{detail['id']}")
                new_severity = c2.selectbox("Severity", SEVERITIES, index=SEVERITIES.index(detail["severity"]), key=f"severity_{detail['id']}")
                if c3.button("Update", key=f"update_{detail['id']}", width="stretch"):
                    update_incident(detail["id"], status=new_status, severity=new_severity)
                    st.rerun()
                if c4.button("Mark resolved", key=f"resolve_{detail['id']}", width="stretch"):
                    update_incident(detail["id"], status="Resolved")
                    st.rerun()
                if st.button("Simulate block" if not detail["blocked"] else "Unmark simulated block", key=f"block_{detail['id']}"):
                    update_incident(detail["id"], blocked=not detail["blocked"])
                    st.rerun()
                if detail["blocked"]:
                    st.warning("Simulated block flag only; no real network change is performed.")
                st.markdown("### Investigation summary")
                st.write(detail["summary"])
                if detail.get("intel"):
                    st.info(f"Local intel: {detail['intel'].get('tag', 'Not listed')} (offline list, no live lookup).")
                if detail.get("mitre"):
                    st.write(f"**MITRE:** {detail['mitre'].get('id')} {detail['mitre'].get('name')}")

            with tabs[1]:
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
                else:
                    st.caption("No structured evidence stored for this incident.")
                if detail["alerts"]:
                    st.subheader("Related alerts")
                    st.dataframe(pd.DataFrame(detail["alerts"]), hide_index=True, width="stretch")

            with tabs[2]:
                st.markdown("### Recommended response")
                st.caption("Recommendations only; nothing is executed.")
                response = detail.get("response") or {}
                actions = response.get("actions", [])
                if actions:
                    for action in actions:
                        st.markdown(f"- {esc(action)}")
                else:
                    st.caption("No response actions stored.")

            with tabs[3]:
                st.markdown("### Analyst notes")
                if detail["notes"]:
                    for note in detail["notes"]:
                        with st.container(border=True):
                            st.write(f"**{note['created_at']} · {note['author']}**")
                            st.write(note["text"])
                else:
                    st.caption("No notes yet.")
                note_text = st.text_input("Add an investigation note", key=f"note_{detail['id']}")
                if st.button("Add note", key=f"add_note_{detail['id']}", disabled=not note_text.strip()):
                    db.ex(
                        "INSERT INTO notes(incident_id,author,text,created_at) VALUES(?,?,?,?)",
                        (detail["id"], "streamlit-analyst", note_text.strip(), datetime.now().isoformat(timespec="seconds")),
                    )
                    st.rerun()
                st.divider()
                rep = reports.build("incident", detail["id"])
                d1, d2 = st.columns(2)
                d1.download_button(
                    "Download incident PDF",
                    data=reports.to_pdf(rep),
                    file_name=f"incident_{detail['id']}_report.pdf",
                    mime="application/pdf",
                    width="stretch",
                )
                d2.download_button(
                    "Download incident CSV",
                    data=reports.to_csv(rep),
                    file_name=f"incident_{detail['id']}_report.csv",
                    mime="text/csv",
                    width="stretch",
                )


def mitre_page():
    page_header(
        "MITRE ATT&CK Mapping",
        "Technique mappings are stored locally and applied to the attack category of each incident.",
        [badge("LOCAL TECHNIQUES", "green"), badge("OFFLINE", "blue")],
    )
    detected = []
    for category_row in db.q("SELECT category, COUNT(*) n, MIN(id) example FROM incidents GROUP BY category"):
        mapped = mitre.lookup(category_row["category"])
        if mapped:
            detected.append({**mapped, "category": category_row["category"], "related_incidents": category_row["n"], "example_incident": category_row["example"]})
    if not detected:
        empty_state("No detected activity to map", "Generate traffic and run the SOC workflow first.")
    else:
        for index in range(0, len(detected), 2):
            cols = st.columns(2)
            for col, item in zip(cols, detected[index:index + 2]):
                with col:
                    with st.container(border=True):
                        st.markdown(
                            f"""
                            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;">
                                <div>
                                    <div style="font-size:1.15rem;font-weight:850;"><span style="color:#67e8f9;font-family:monospace;">{esc(item['id'])}</span> {esc(item['name'])}</div>
                                    <div style="color:var(--muted);font-size:.82rem;margin-top:.2rem;">{esc(item['tactic'])}</div>
                                </div>
                                {badge(item['category'], 'blue')}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        st.write(item["description"])
                        st.write(
                            f"Related detection: **{item['category']}** · {item['related_incidents']} incident(s), "
                            f"e.g. INC-{item['example_incident']:04d}"
                        )
                        st.write(f"**Mitigation:** {item['mitigation']}")

    with st.container(border=True):
        panel("Local technique reference")
        st.dataframe(pd.DataFrame(list(mitre.MITRE.values())), hide_index=True, width="stretch")


def reports_page():
    page_header(
        "Reports & Analytics",
        "Generate PDF and CSV reports from the current SQLite dataset.",
        [badge("PDF", "red"), badge("CSV", "green")],
    )
    report_types = [
        ("daily", "Daily security report", "Incidents by severity, top incidents and alert categories."),
        ("weekly", "Weekly threat summary", "Same breakdown framed as a weekly summary of stored data."),
        ("traffic", "Network traffic analysis", "Protocols, top talkers and most-used destination ports."),
        ("classification", "Attack classification report", "Model predictions and average confidence per class."),
    ]
    for kind, title, description in report_types:
        with st.container(border=True):
            panel(title, description)
            rep = reports.build(kind)
            with st.expander("Preview tables"):
                for name, rows in rep["tables"].items():
                    st.markdown(f"**{esc(name)}**")
                    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
            c1, c2 = st.columns(2)
            c1.download_button(
                "Download PDF",
                data=reports.to_pdf(rep),
                file_name=f"{kind}_report.pdf",
                mime="application/pdf",
                width="stretch",
            )
            c2.download_button(
                "Download CSV",
                data=reports.to_csv(rep),
                file_name=f"{kind}_report.csv",
                mime="text/csv",
                width="stretch",
            )
    st.caption("Incident investigation reports are available on the Incidents page. Reports use data currently in the database.")


def settings_page():
    page_header(
        "Settings",
        "System status, local threat indicators and database maintenance.",
        [badge("LOCAL ONLY", "green"), badge("NO SECRETS", "blue")],
    )
    model_trained = P.load() is not None
    cols = st.columns(3)
    with cols[0]:
        kpi("Model status", "Trained" if model_trained else "Not trained", "Random Forest + Isolation Forest", "green" if model_trained else "amber")
    with cols[1]:
        kpi("Database", "SQLite", "backend/soc.db", "cyan")
    with cols[2]:
        kpi("External APIs", "None", "Fully local operation", "blue")

    with st.container(border=True):
        panel("Threat intelligence", "Small offline indicator list; no live lookups are performed")
        intel_rows = [{"ip": ip, **details} for ip, details in threatintel.LOCAL_INTEL.items()]
        st.dataframe(pd.DataFrame(intel_rows), hide_index=True, width="stretch")

    with st.container(border=True):
        panel("Danger zone", "Database maintenance")
        st.warning("This deletes all events, alerts, incidents and notes. Trained models are kept.")
        confirmed = st.checkbox("I understand this deletes all stored SOC data")
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

st.session_state.setdefault("nav_select", "Dashboard")
st.sidebar.title("SOC ANALYST")
st.sidebar.caption("Local security operations center")
sidebar_stats = db.q1(
    "SELECT (SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved','False Positive')) active, "
    "(SELECT COUNT(*) FROM alerts) alerts, (SELECT COUNT(*) FROM events) events"
) or {}
st.sidebar.metric("Active incidents", sidebar_stats.get("active", 0))
st.sidebar.caption(f"{sidebar_stats.get('alerts', 0):,} alerts · {sidebar_stats.get('events', 0):,} events")
page = st.sidebar.radio("Navigate", list(PAGES), key="nav_select", format_func=lambda name: NAV_LABELS[name])
PAGES[page]()
