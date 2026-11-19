"""Synthetic CICIDS-style sample dataset (clearly synthetic) covering all 7 categories + simulated IPs/timestamps."""
import numpy as np, pandas as pd
from datetime import datetime, timedelta

def _rows(rng, n, cat):
    r = lambda a, b: rng.uniform(a, b, n); i = lambda a, b: rng.integers(a, b + 1, n)
    d = dict(dst_port=rng.choice([80, 443, 53, 22, 8080, 3389, 25], n), flow_duration=rng.lognormal(12, 1.5, n),
             fwd_packets=i(2, 20), bwd_packets=i(2, 20), fwd_bytes=r(200, 8000), bwd_bytes=r(300, 20000),
             syn_flags=i(0, 1), rst_flags=np.zeros(n), psh_flags=i(0, 1), ack_flags=np.ones(n),
             init_win_fwd=rng.choice([8192, 29200, 65535], n), init_win_bwd=rng.choice([229, 8192, 28960], n))
    if cat == "DoS":
        d.update(dst_port=rng.choice([80, 8080, 443], n), flow_duration=rng.lognormal(14, 1, n), fwd_packets=i(40, 400),
                 bwd_packets=i(0, 4), fwd_bytes=r(2000, 60000), bwd_bytes=r(0, 800), syn_flags=i(1, 3), init_win_bwd=np.full(n, -1))
    elif cat == "DDoS":
        d.update(dst_port=rng.choice([80, 443], n), flow_duration=rng.lognormal(4, 1.5, n), fwd_packets=i(1, 5),
                 bwd_packets=i(0, 2), fwd_bytes=r(0, 80), bwd_bytes=r(0, 200), syn_flags=i(0, 2), init_win_fwd=rng.choice([256, 8192, 29200], n),
                 init_win_bwd=rng.choice([-1, 235, 8192], n))
    elif cat == "PortScan":
        d.update(dst_port=rng.integers(1, 65535, n), flow_duration=rng.lognormal(3, 1, n), fwd_packets=i(1, 2), bwd_packets=i(0, 1),
                 fwd_bytes=r(0, 70), bwd_bytes=r(0, 70), syn_flags=np.ones(n), rst_flags=i(0, 1), ack_flags=i(0, 1),
                 init_win_fwd=rng.choice([1024, 2048, 4096], n), init_win_bwd=np.full(n, -1))
    elif cat == "BruteForce":
        d.update(dst_port=rng.choice([22, 21, 3389], n), flow_duration=rng.lognormal(13, .6, n), fwd_packets=i(10, 30), bwd_packets=i(9, 28),
                 fwd_bytes=r(1000, 3500), bwd_bytes=r(1500, 4500), psh_flags=np.ones(n), init_win_fwd=np.full(n, 29200))
    elif cat == "Botnet":
        d.update(dst_port=rng.choice([6667, 8080, 4444, 1337], n), flow_duration=rng.lognormal(15, .5, n), fwd_packets=i(3, 8), bwd_packets=i(3, 8),
                 fwd_bytes=r(100, 500), bwd_bytes=r(100, 500), init_win_fwd=np.full(n, 8192))
    elif cat == "SuspiciousOutbound":
        d.update(dst_port=rng.choice([443, 21, 8443, 53], n), flow_duration=rng.lognormal(15.5, .8, n), fwd_packets=i(200, 900),
                 bwd_packets=i(5, 40), fwd_bytes=r(5e5, 8e6), bwd_bytes=r(500, 5000), psh_flags=np.ones(n))
    df = pd.DataFrame(d)
    df["fwd_pkt_len_mean"] = df.fwd_bytes / df.fwd_packets.clip(lower=1); df["bwd_pkt_len_mean"] = df.bwd_bytes / df.bwd_packets.clip(lower=1)
    secs = (df.flow_duration / 1e6).clip(lower=1e-6)
    df["flow_bytes_s"] = (df.fwd_bytes + df.bwd_bytes) / secs; df["flow_packets_s"] = (df.fwd_packets + df.bwd_packets) / secs
    df["flow_iat_mean"] = df.flow_duration / (df.fwd_packets + df.bwd_packets).clip(lower=1)
    df["avg_packet_size"] = (df.fwd_bytes + df.bwd_bytes) / (df.fwd_packets + df.bwd_packets).clip(lower=1)
    df["down_up_ratio"] = (df.bwd_packets / df.fwd_packets.clip(lower=1)).round()
    # add overlap/noise so models are not trivially perfect
    for c in ("fwd_bytes", "bwd_bytes", "flow_duration"): df[c] = df[c] * rng.lognormal(0, .35, n)
    df["label"] = cat
    return df

def generate(n_per=1500, seed=7):
    rng = np.random.default_rng(seed)
    cats = {"Normal": 3.0, "DoS": 1, "DDoS": 1, "PortScan": 1, "BruteForce": 1, "Botnet": .7, "SuspiciousOutbound": .6}
    df = pd.concat([_rows(rng, int(n_per * w), c) for c, w in cats.items()], ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)
    df.attrs["ip_pool_by_label"] = True
    return add_network_meta(df, seed)

ATTACKERS = ["203.0.113.45", "198.51.100.23", "203.0.113.99", "192.0.2.77"]  # documentation ranges (safe, fictional)
def add_network_meta(df, seed=1, base=None):
    """Adds src/dst IP, ports, protocol, timestamp. Marked simulated: these are NOT in the original CICIDS CSV."""
    rng = np.random.default_rng(seed); n = len(df)
    internal = [f"192.168.1.{k}" for k in range(10, 40)]; external = [f"172.217.{a}.{b}" for a in (1, 2) for b in range(5, 15)]
    lab = df["label"].astype(str) if "label" in df else pd.Series(["Normal"] * n)
    src = rng.choice(internal + external, n).astype(object)
    mask = (lab != "Normal").to_numpy()
    # synthetic data only: attackers cluster on a few IPs so correlation is demonstrable
    if "ip_pool_by_label" in df.attrs and df.attrs["ip_pool_by_label"]:
        by_cat = {"DDoS": ATTACKERS[0], "PortScan": ATTACKERS[1], "BruteForce": ATTACKERS[2], "Botnet": ATTACKERS[3], "DoS": "203.0.113.200", "SuspiciousOutbound": "192.168.1.25"}
        src[mask] = [by_cat.get(l, ATTACKERS[0]) for l in lab[mask]]  # one primary attacker per category (synthetic only)
    out = df.copy()
    out["src_ip"] = src; out["dst_ip"] = np.where(out["dst_port"].isin([80, 443, 8080]), "10.0.0.10", rng.choice(["10.0.0.10", "10.0.0.20", "10.0.0.30"], n))
    out["src_port"] = rng.integers(1025, 65535, n)
    out["protocol"] = np.where(out["dst_port"] == 53, "UDP", "TCP")
    t0 = base or datetime.now() - timedelta(hours=24)
    out["ts"] = [(t0 + timedelta(seconds=float(s))).strftime("%Y-%m-%d %H:%M:%S") for s in np.sort(rng.uniform(0, 86000, n))]
    return out
