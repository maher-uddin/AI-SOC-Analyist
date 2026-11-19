import io, pandas as pd
from datetime import datetime
from database import q

def build(kind, incident_id=None):
    t = datetime.now().strftime("%Y-%m-%d %H:%M")
    if kind == "incident":
        r = q("SELECT id,threat_name,src_ip,dst_ip,severity,category,confidence,status,event_count,risk_score,summary FROM incidents WHERE id=?", (incident_id,))
        return {"title": f"Incident Investigation Report INC-{incident_id:04d}", "generated": t, "tables": {"Incident": r}}
    if kind == "traffic":
        return {"title": "Network Traffic Analysis Report", "generated": t, "tables": {
            "By protocol": q("SELECT protocol, COUNT(*) events, SUM(bytes) bytes FROM events GROUP BY protocol"),
            "Top talkers": q("SELECT src_ip, COUNT(*) events, SUM(bytes) bytes FROM events GROUP BY src_ip ORDER BY events DESC LIMIT 10"),
            "Top destination ports": q("SELECT dst_port, COUNT(*) events FROM events GROUP BY dst_port ORDER BY events DESC LIMIT 10")}}
    if kind == "classification":
        return {"title": "Attack Classification Report", "generated": t, "tables": {
            "Predictions": q("SELECT prediction, COUNT(*) events, ROUND(AVG(confidence),3) avg_confidence FROM events GROUP BY prediction ORDER BY events DESC")}}
    days = 7 if kind == "weekly" else 1
    return {"title": ("Weekly Threat Summary" if days == 7 else "Daily Security Report"), "generated": t, "tables": {
        "Incidents by severity": q("SELECT severity, COUNT(*) n FROM incidents GROUP BY severity"),
        "Incidents": q("SELECT id,threat_name,severity,category,status,event_count FROM incidents ORDER BY risk_score DESC LIMIT 25"),
        "Alerts by category": q("SELECT category, COUNT(*) n FROM alerts GROUP BY category")}}

def to_csv(rep):
    buf = io.StringIO(); buf.write(f"# {rep['title']} ({rep['generated']})\n")
    for name, rows in rep["tables"].items():
        buf.write(f"\n## {name}\n"); pd.DataFrame(rows).to_csv(buf, index=False)
    return buf.getvalue().encode()

def to_pdf(rep):
    from reportlab.lib.pagesizes import A4; from reportlab.lib import colors; from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
    buf = io.BytesIO(); st = getSampleStyleSheet(); els = [Paragraph(rep["title"], st["Title"]), Paragraph("Generated " + rep["generated"] + " by the local SOC platform (no external services)", st["Normal"]), Spacer(1, 12)]
    for name, rows in rep["tables"].items():
        els.append(Paragraph(name, st["Heading2"]))
        if not rows: els.append(Paragraph("No data.", st["Normal"])); continue
        hdr = list(rows[0].keys()); body = [[Paragraph(str(r[h])[:300], st["BodyText"]) for h in hdr] for r in rows]
        t = Table([hdr] + body, repeatRows=1); t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2a43")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        els += [t, Spacer(1, 10)]
    SimpleDocTemplate(buf, pagesize=A4).build(els); return buf.getvalue()
