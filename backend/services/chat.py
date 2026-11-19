"""Local rule-based assistant. NOT an LLM: keyword intents answered from SQLite data."""
import re, json
from database import q, q1, jl
from services import mitre, threatintel

def _inc_list(rows): return "\n".join(f"- INC-{r['id']:04d} [{r['severity']}] {r['threat_name']} ({r['status']}, {r['event_count']} alerts)" for r in rows)

def answer(msg):
    m = msg.lower(); ids = re.findall(r"(?:inc-?|incident\s*#?)(\d+)", m); ip = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", msg)
    if ids or "this incident" in m or "explain" in m and ("alert" in m or "incident" in m):
        i = int(ids[0]) if ids else (q1("SELECT id FROM incidents ORDER BY risk_score DESC LIMIT 1") or {}).get("id")
        r = q1("SELECT * FROM incidents WHERE id=?", (i,)) if i else None
        if not r: return "No incidents stored yet. Upload traffic or run simulated traffic, then analyze."
        if "what should" in m or "do about" in m or "respond" in m:
            acts = jl(r["response"], {}).get("actions", [])
            return f"Recommended response for INC-{r['id']:04d}:\n" + "\n".join(f"- {a}" for a in acts) + "\n(Recommendations only; nothing is executed.)"
        return f"INC-{r['id']:04d}: {r['summary']}"
    if ip and ("why" in m or "suspicious" in m or "ip" in m):
        a = ip.group(); evs = q("SELECT prediction, COUNT(*) n, ROUND(AVG(confidence),2) c FROM events WHERE src_ip=? GROUP BY prediction", (a,))
        if not evs: return f"No events from {a} in the database."
        ti = threatintel.check(a)
        return f"{a}: " + "; ".join(f"{e['n']} events classified {e['prediction']} (avg confidence {e['c']})" for e in evs) + \
               (f". Local indicator list: {ti['tag']}." if ti["listed"] else ". Not on the local indicator list.")
    if "failed" in m or "repeated" in m:
        r = q("SELECT src_ip, COUNT(*) n FROM events WHERE packets<=2 AND bytes<100 GROUP BY src_ip ORDER BY n DESC LIMIT 5")
        return "Sources with the most failed/empty connections (<=2 packets, <100 bytes):\n" + "\n".join(f"- {x['src_ip']}: {x['n']}" for x in r) if r else "No failed-connection patterns found."
    if "critical" in m or "high" in m:
        sev = "Critical" if "critical" in m else "High"
        r = q("SELECT * FROM incidents WHERE severity=? ORDER BY id DESC LIMIT 10", (sev,))
        return f"{sev} incidents:\n" + _inc_list(r) if r else f"There are no {sev} incidents."
    if "which attack" in m or "attacks were detected" in m or "categor" in m:
        r = q("SELECT category, COUNT(*) n FROM alerts GROUP BY category ORDER BY n DESC")
        return "Detected attack categories:\n" + "\n".join(f"- {x['category']}: {x['n']} alerts" for x in r) if r else "No alerts yet."
    if "mitre" in m or "technique" in m:
        cats = [x["category"] for x in q("SELECT DISTINCT category FROM incidents")]
        return "\n".join(f"- {mitre.lookup(c)['id']} {mitre.lookup(c)['name']} <- {c}" for c in cats if mitre.lookup(c)) or "No incidents to map."
    if "summar" in m or "latest" in m or "overview" in m:
        s = q1("SELECT (SELECT COUNT(*) FROM events) e,(SELECT COUNT(*) FROM alerts) a,(SELECT COUNT(*) FROM incidents) i,(SELECT COUNT(*) FROM incidents WHERE status!='Resolved') o")
        return f"{s['e']} events analysed, {s['a']} alerts, {s['i']} incidents ({s['o']} unresolved).\n" + _inc_list(q("SELECT * FROM incidents ORDER BY id DESC LIMIT 5"))
    return ("I'm a local rule-based assistant (not an LLM). Try: 'What are today's critical threats?', 'Explain incident 3', 'Why is 203.0.113.45 suspicious?', "
            "'Show repeated failed connections', 'Which attacks were detected?', 'What should I do about incident 2?', 'Summarize the latest security events'.")
