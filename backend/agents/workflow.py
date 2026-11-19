"""Six-agent sequential SOC workflow. Agents are plain functions exchanging JSON-serialisable dicts. No external APIs."""
import json, pandas as pd
from datetime import datetime
from database import conn, q, ex
from services import mitre, threatintel

ATTACK_WEIGHT = {"DDoS": 0.9, "DoS": 0.8, "SuspiciousOutbound": 0.95, "Botnet": 0.9, "BruteForce": 0.7, "PortScan": 0.45}
NORMAL_PORTS = {80, 443, 53, 22, 25, 8080, 3389, 21}

def detection_agent(limit_ids=None):
    """Agent 1: turns suspicious stored events (ML != Normal, or anomaly + rule hit) into alerts."""
    ev = pd.DataFrame(q("SELECT * FROM events WHERE status='new'"))
    if ev.empty: return {"agent": "detection", "alerts": 0, "df": ev}
    sus = ev[(ev.prediction != "Normal") | ((ev.anomaly == 1) & (ev.rule_hits != ""))].copy()
    sus["category"] = sus.apply(lambda r: r.prediction if r.prediction != "Normal" else "Anomaly", axis=1)
    al = pd.DataFrame({"event_id": sus.id, "ts": sus.ts, "src_ip": sus.src_ip, "dst_ip": sus.dst_ip, "category": sus.category,
                       "confidence": sus.confidence, "severity": "Low", "explanation": sus.explanation, "rule_hits": sus.rule_hits})
    with conn() as c:
        al.to_sql("alerts", c, if_exists="append", index=False)
        c.execute("UPDATE events SET status='analyzed' WHERE status='new'")
        c.execute("UPDATE events SET status='suspicious' WHERE prediction!='Normal' AND status='analyzed'")
    return {"agent": "detection", "alerts": int(len(al)), "df": ev}

def investigation_agent():
    """Agent 2: correlates un-assigned alerts into incidents per (source IP, category); checks failed connections, ports."""
    al = pd.DataFrame(q("SELECT * FROM alerts WHERE incident_id IS NULL AND category!='Anomaly'"))
    out = []
    if al.empty: return {"agent": "investigation", "incidents": out}
    for (src, cat), g in al.groupby(["src_ip", "category"]):
        if len(g) < 3: continue  # isolated alerts stay as alerts; incidents need >=3 correlated alerts
        ev = pd.DataFrame(q(f"SELECT * FROM events WHERE id IN ({','.join(map(str, g.event_id.tolist()[:5000]))})"))
        related = q("SELECT COUNT(*) n FROM events WHERE src_ip=?", (src,))[0]["n"]
        failed = int(((ev.packets <= 2) & (ev.bytes < 100)).sum()) if len(ev) else 0
        uports = sorted(set(ev.dst_port.astype(int))) if len(ev) else []
        unusual = [p for p in uports if p not in NORMAL_PORTS][:15]
        out.append({"src_ip": src, "category": cat, "alert_ids": g.id.tolist(), "alert_count": len(g),
            "first_seen": g.ts.min(), "last_seen": g.ts.max(), "dst_ips": sorted(set(g.dst_ip))[:10],
            "avg_confidence": float(g.confidence.mean()), "related_events_from_ip": int(related),
            "failed_or_empty_connections": failed, "distinct_dst_ports": len(uports), "unusual_ports": unusual,
            "rules": sorted({r for rs in g.rule_hits.fillna("") for r in rs.split("; ") if r}),
            "sample_explanation": g.explanation.iloc[0], "top_events": ev.head(5)[["ts", "dst_ip", "dst_port", "packets", "bytes"]].to_dict("records") if len(ev) else []})
    return {"agent": "investigation", "incidents": out}

def threat_intel_agent(inc):
    return {"agent": "threat_intel", **threatintel.check(inc["src_ip"])}

def risk_agent(inc, intel):
    """Agent 4: score = confidence, attack type, frequency, impact (ports/targets) and local intel match."""
    freq = min(1.0, inc["alert_count"] / 1000)
    impact = min(1.0, 0.15 * len(inc["dst_ips"]) + 0.002 * inc["distinct_dst_ports"])
    score = 100 * (0.30 * inc["avg_confidence"] + 0.30 * ATTACK_WEIGHT.get(inc["category"], .5) + 0.20 * freq + 0.10 * impact + 0.10 * (1 if intel["listed"] else 0))
    sev = "Critical" if score >= 80 else "High" if score >= 65 else "Medium" if score >= 45 else "Low"
    return {"agent": "risk", "risk_score": round(score, 1), "severity": sev,
            "factors": {"confidence": round(inc["avg_confidence"], 2), "attack_weight": ATTACK_WEIGHT.get(inc["category"], .5), "frequency": round(freq, 2), "impact": round(impact, 2), "intel_match": intel["listed"]}}

RESP = {
 "DDoS": ["Enable upstream rate limiting / DDoS scrubbing for the targeted service", "Recommend blocking the source IP at the perimeter firewall (recommendation only)", "Review firewall and load-balancer connection limits"],
 "DoS": ["Apply per-IP connection limits and SYN protection on the target", "Recommend blocking the source IP (recommendation only)", "Check service health and resource usage on the destination host"],
 "PortScan": ["Recommend blocking the scanning IP", "Review which ports are exposed and close unnecessary ones", "Review firewall rules for the scanned subnet"],
 "BruteForce": ["Check authentication logs on the targeted host for failed logins", "Enforce account lockout and MFA", "Recommend blocking the source IP; reset credentials if any login succeeded"],
 "Botnet": ["Isolate the affected host(s) from the network (simulation only)", "Block outbound connections to the suspicious ports", "Run an endpoint malware scan and review DNS logs"],
 "SuspiciousOutbound": ["Isolate the sending host pending review (simulation only)", "Review what data left, and to where", "Restrict egress with allow-lists; review firewall rules"],
}
def response_agent(inc, risk):
    acts = list(RESP.get(inc["category"], ["Review the related events manually"]))
    if risk["severity"] in ("Critical", "High"): acts.insert(0, "Escalate to the senior analyst / incident commander")
    return {"agent": "response", "actions": acts, "note": "Recommendations only; no real blocking or network change is performed."}

def report_agent(inc, intel, risk, resp, mt):
    s = (f"{inc['category']} activity from {inc['src_ip']} against {', '.join(inc['dst_ips'][:3])}: {inc['alert_count']} alerts between {inc['first_seen']} and {inc['last_seen']}. "
         f"Mean model confidence {inc['avg_confidence']:.0%}; severity {risk['severity']} (risk score {risk['risk_score']}). "
         f"Key evidence: {inc['sample_explanation']}. "
         + (f"Rules matched: {', '.join(inc['rules'])}. " if inc["rules"] else "")
         + (f"The source IP is on the local indicator list ({intel.get('tag')}). " if intel["listed"] else "The source IP is not on the local indicator list. ")
         + (f"Mapped to MITRE ATT&CK {mt['id']} ({mt['name']})." if mt else ""))
    return {"agent": "report", "summary": s}

def run_workflow():
    """Detection -> Investigation -> Threat Intel -> Risk -> Response -> Report, persisting incidents."""
    d = detection_agent(); inv = investigation_agent(); created = []
    for inc in inv["incidents"]:
        intel = threat_intel_agent(inc); risk = risk_agent(inc, intel); resp = response_agent(inc, risk)
        mt = mitre.lookup(inc["category"]); rep = report_agent(inc, intel, risk, resp, mt)
        iid = ex("""INSERT INTO incidents(threat_name,src_ip,dst_ip,detected_at,severity,category,ml_prediction,confidence,status,event_count,evidence,response,mitre,intel,summary,risk_score)
                    VALUES(?,?,?,?,?,?,?,?,'Open',?,?,?,?,?,?,?)""",
            (f"{inc['category']} from {inc['src_ip']}", inc["src_ip"], ", ".join(inc["dst_ips"][:3]), inc["first_seen"], risk["severity"], inc["category"],
             inc["category"], inc["avg_confidence"], inc["alert_count"], json.dumps(inc, default=str), json.dumps(resp), json.dumps(mt), json.dumps(intel),
             rep["summary"], risk["risk_score"]))
        with conn() as c:
            ids = inc["alert_ids"]
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                c.execute(f"UPDATE alerts SET incident_id=?, severity=? WHERE id IN ({','.join('?' * len(chunk))})", (iid, risk["severity"], *chunk))
        created.append({"incident_id": iid, "severity": risk["severity"], "category": inc["category"], "src_ip": inc["src_ip"]})
    return {"alerts_created": d["alerts"], "incidents_created": created,
            "trace": ["detection", "investigation", "threat_intel", "risk", "response", "report"]}
