"""Signature / behavioural rules evaluated per event (vectorised). Returns list of rule names per row."""
import pandas as pd
SUSPICIOUS_PORTS = {4444, 6667, 1337, 31337, 5555, 9001}
def apply_rules(df):
    hits = [[] for _ in range(len(df))]
    def add(mask, name):
        for i in mask.to_numpy().nonzero()[0]: hits[i].append(name)
    p = lambda c: pd.to_numeric(df[c], errors="coerce").fillna(0)
    add(p("dst_port").isin(SUSPICIOUS_PORTS), "R1 known backdoor/C2 port")
    add((p("syn_flags") >= 1) & (p("bwd_packets") == 0) & (p("fwd_packets") <= 2) & (p("flow_packets_s") > 10000), "R2 high-rate SYN with no reply (flood)")
    add((p("fwd_packets") <= 2) & (p("bwd_packets") <= 1) & (p("fwd_bytes") < 80) & (p("dst_port") > 1024) & (p("syn_flags") >= 1) & (p("init_win_bwd") < 0), "R3 probe pattern (scan)")
    add(p("dst_port").isin({21, 22, 3389}) & (p("fwd_packets") >= 10) & (p("psh_flags") >= 1) & (p("fwd_bytes") < 4000), "R4 repeated auth-like session")
    add((p("fwd_bytes") > 5e5) & (p("bwd_bytes") < 10000), "R5 large outbound transfer (possible exfiltration)")
    return ["; ".join(h) for h in hits]
