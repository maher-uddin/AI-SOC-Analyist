"""Feature mapping, training (RandomForest + IsolationForest), evaluation, prediction, explanation."""
import os, json, numpy as np, pandas as pd, joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
FEATURES = ["dst_port", "flow_duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
            "fwd_pkt_len_mean", "bwd_pkt_len_mean", "flow_bytes_s", "flow_packets_s", "flow_iat_mean",
            "syn_flags", "rst_flags", "psh_flags", "ack_flags", "avg_packet_size",
            "init_win_fwd", "init_win_bwd", "down_up_ratio"]
ALIASES = {
 "destination port": "dst_port", "dst port": "dst_port", "dport": "dst_port", "dsport": "dst_port",
 "flow duration": "flow_duration", "dur": "flow_duration",
 "total fwd packets": "fwd_packets", "spkts": "fwd_packets", "tot fwd pkts": "fwd_packets",
 "total backward packets": "bwd_packets", "dpkts": "bwd_packets", "tot bwd pkts": "bwd_packets",
 "total length of fwd packets": "fwd_bytes", "sbytes": "fwd_bytes",
 "total length of bwd packets": "bwd_bytes", "dbytes": "bwd_bytes",
 "fwd packet length mean": "fwd_pkt_len_mean", "bwd packet length mean": "bwd_pkt_len_mean",
 "flow bytes/s": "flow_bytes_s", "flow packets/s": "flow_packets_s", "flow iat mean": "flow_iat_mean",
 "syn flag count": "syn_flags", "rst flag count": "rst_flags", "psh flag count": "psh_flags",
 "ack flag count": "ack_flags", "average packet size": "avg_packet_size",
 "init_win_bytes_forward": "init_win_fwd", "init_win_bytes_backward": "init_win_bwd",
 "down/up ratio": "down_up_ratio",
 "source ip": "src_ip", "src ip": "src_ip", "srcip": "src_ip", "destination ip": "dst_ip", "dst ip": "dst_ip",
 "dstip": "dst_ip", "source port": "src_port", "src port": "src_port", "sport": "src_port",
 "protocol": "protocol", "proto": "protocol", "timestamp": "ts", "stime": "ts",
 "label": "label", "attack_cat": "label",
}
LABEL_MAP = {"benign": "Normal", "normal": "Normal", "ddos": "DDoS", "portscan": "PortScan",
             "ftp-patator": "BruteForce", "ssh-patator": "BruteForce", "bot": "Botnet",
             "dos hulk": "DoS", "dos goldeneye": "DoS", "dos slowloris": "DoS", "dos slowhttptest": "DoS",
             "dos": "DoS", "backdoor": "Botnet", "exploits": "Exploit", "reconnaissance": "PortScan"}
CATEGORIES = ["Normal", "DoS", "DDoS", "PortScan", "BruteForce", "Botnet", "SuspiciousOutbound"]

def map_columns(df):
    seen, ren = set(), {}
    for c in df.columns:
        t = ALIASES.get(str(c).strip().lower())
        if t and t not in seen: ren[c] = t; seen.add(t)
    out = df.rename(columns=ren)
    out = out.loc[:, ~out.columns.duplicated()].copy()
    missing = [f for f in FEATURES if f not in out.columns]
    for f in missing: out[f] = 0.0
    if "label" in out.columns:
        out["label"] = out["label"].astype(str).str.strip().map(lambda s: LABEL_MAP.get(s.lower(), s))
    return out, {"mapped": sorted(seen & set(FEATURES)), "missing_filled_with_zero": missing,
                 "has_label": "label" in out.columns, "has_ip": "src_ip" in out.columns}

def _x(df):
    a = df[FEATURES].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0).to_numpy(float)
    return np.sign(a) * np.log1p(np.abs(a))

def train(df, seed=42, max_rows=60000):
    """Test split is held out BEFORE fitting any model; metrics come only from the held-out part."""
    df = df.dropna(subset=["label"])
    if len(df) > max_rows:
        per = max_rows // df.label.nunique()
        df = pd.concat([g.sample(min(len(g), per), random_state=seed) for _, g in df.groupby("label")])
    X, y = _x(df), df["label"].to_numpy()
    strat = y if pd.Series(y).value_counts().min() >= 2 else None
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=seed, stratify=strat)
    rf = RandomForestClassifier(n_estimators=120, max_depth=18, n_jobs=-1, random_state=seed, class_weight="balanced").fit(Xtr, ytr)
    bn = Xtr[ytr == "Normal"] if (ytr == "Normal").any() else Xtr
    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=seed).fit(bn)
    pred = rf.predict(Xte); labels = sorted(set(y))
    p, r, f, _ = precision_recall_fscore_support(yte, pred, average="weighted", zero_division=0)
    ip, ir, if_, _ = precision_recall_fscore_support(yte != "Normal", iso.predict(Xte) == -1, average="binary", zero_division=0)
    metrics = {"accuracy": accuracy_score(yte, pred), "precision": p, "recall": r, "f1": f,
               "labels": labels, "confusion_matrix": confusion_matrix(yte, pred, labels=labels).tolist(),
               "per_class": classification_report(yte, pred, output_dict=True, zero_division=0),
               "isolation_forest": {"precision": ip, "recall": ir, "f1": if_},
               "train_rows": int(len(Xtr)), "test_rows": int(len(Xte)),
               "feature_importance": dict(sorted(zip(FEATURES, map(float, rf.feature_importances_)), key=lambda t: -t[1]))}
    stats = {"med": np.median(bn, 0), "std": bn.std(0) + 1e-6}
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({"rf": rf, "iso": iso, "stats": stats}, os.path.join(MODEL_DIR, "soc_models.joblib"))
    json.dump(metrics, open(os.path.join(MODEL_DIR, "metrics.json"), "w"), indent=1)
    _cache.clear()
    return metrics

_cache = {}
def load():
    p = os.path.join(MODEL_DIR, "soc_models.joblib")
    if not os.path.exists(p): return None
    m = os.path.getmtime(p)
    if _cache.get("m") != m: _cache.update(m=m, b=joblib.load(p))
    return _cache["b"]

def metrics():
    p = os.path.join(MODEL_DIR, "metrics.json")
    return json.load(open(p)) if os.path.exists(p) else None

def predict(df):
    b = load()
    if b is None: raise RuntimeError("No trained model. Train first.")
    X = _x(df); rf, iso = b["rf"], b["iso"]
    proba = rf.predict_proba(X); idx = proba.argmax(1)
    out = pd.DataFrame({"prediction": rf.classes_[idx], "confidence": proba.max(1),
                        "anomaly_score": -iso.score_samples(X), "anomaly": (iso.predict(X) == -1).astype(int)}, index=df.index)
    z = np.abs((X - b["stats"]["med"]) / b["stats"]["std"]) * rf.feature_importances_
    top = np.argsort(-z, 1)[:, :3]
    raw = df[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy()
    out["explanation"] = [", ".join(f"{FEATURES[j]}={raw[i, j]:.4g}" for j in top[i]) for i in range(len(df))]
    return out
