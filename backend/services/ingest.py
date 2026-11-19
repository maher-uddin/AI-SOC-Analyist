import pandas as pd, numpy as np
from ml import pipeline as P, sample_data as S
from detection.rules import apply_rules
from database import conn

def ingest_df(df, source="upload", simulated=0, max_rows=20000, seed=3):
    mapped, report = P.map_columns(df)
    if len(mapped) > max_rows: mapped = mapped.sample(max_rows, random_state=seed).reset_index(drop=True); report["sampled_to"] = max_rows
    ip_sim = 0
    if not report["has_ip"]:
        mapped = S.add_network_meta(mapped, seed); ip_sim = 1  # IPs/timestamps invented, independent of label
        report["note"] = "Dataset has no IP/timestamp columns; simulated IPs and timestamps were generated (not real)."
    else:
        for c, v in (("dst_ip", "unknown"), ("src_port", 0), ("protocol", "TCP")):
            if c not in mapped: mapped[c] = v
        if "ts" not in mapped: mapped["ts"] = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    pred = P.predict(mapped); rules = apply_rules(mapped)
    n = lambda c: pd.to_numeric(mapped[c], errors="coerce").fillna(0)
    ev = pd.DataFrame({"ts": mapped.ts.astype(str), "src_ip": mapped.src_ip, "dst_ip": mapped.dst_ip, "src_port": n("src_port").astype(int),
        "dst_port": n("dst_port").astype(int), "protocol": mapped.protocol, "packets": (n("fwd_packets") + n("bwd_packets")).astype(int),
        "duration": (n("flow_duration") / 1e6).round(6), "bytes": n("fwd_bytes") + n("bwd_bytes"), "prediction": pred.prediction.values,
        "confidence": pred.confidence.values.round(4), "anomaly": pred.anomaly.values, "anomaly_score": pred.anomaly_score.values.round(4),
        "rule_hits": rules, "explanation": pred.explanation.values, "status": "new", "source": source, "simulated": simulated, "ip_simulated": ip_sim})
    with conn() as c: ev.to_sql("events", c, if_exists="append", index=False)
    report.update(rows=len(ev), predicted=ev.prediction.value_counts().to_dict())
    return report
