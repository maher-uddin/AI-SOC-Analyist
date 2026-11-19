"""FastAPI app: run with `uvicorn main:app --reload` from the backend folder."""
import io, os, json, pandas as pd
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
import database as db
from ml import pipeline as P, sample_data as S
from agents.workflow import run_workflow
from services import ingest, chat, reports, mitre, threatintel

app = FastAPI(title="AI-Powered SOC Analyst (local, no external APIs)")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])
DATA_DIR = os.path.join(os.path.dirname(__file__), "datasets")

@app.on_event("startup")
def startup():
    db.init_db(); os.makedirs(DATA_DIR, exist_ok=True)
    sp = os.path.join(DATA_DIR, "sample_traffic.csv")
    if not os.path.exists(sp): S.generate().to_csv(sp, index=False)
    if P.load() is None: P.train(P.map_columns(pd.read_csv(sp))[0])  # first run: train on the synthetic sample

def _read(upload: UploadFile):
    try: return pd.read_csv(io.BytesIO(upload.file.read()), skipinitialspace=True, low_memory=False)
    except Exception as e: raise HTTPException(400, f"Could not read CSV: {e}")

@app.get("/api/health")
def health(): return {"ok": True, "model_trained": P.load() is not None}

@app.get("/api/dashboard")
def dashboard():
    s = db.q1("""SELECT (SELECT COUNT(*) FROM events) events,(SELECT COUNT(*) FROM alerts) alerts,
      (SELECT COUNT(*) FROM incidents WHERE severity='Critical') critical,(SELECT COUNT(*) FROM incidents WHERE severity='High') high,
      (SELECT COUNT(*) FROM incidents WHERE severity='Medium') medium,(SELECT COUNT(*) FROM incidents WHERE severity='Low') low,
      (SELECT COUNT(*) FROM incidents WHERE blocked=1) blocked,(SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved','False Positive')) active""")
    return {"stats": s,
      "activity": db.q("SELECT substr(ts,1,13)||':00' hour, COUNT(*) events, SUM(prediction!='Normal') suspicious FROM events GROUP BY 1 ORDER BY 1 LIMIT 48"),
      "threat_distribution": db.q("SELECT severity name, COUNT(*) value FROM incidents GROUP BY severity"),
      "attack_categories": db.q("SELECT category name, COUNT(*) value FROM alerts GROUP BY category ORDER BY value DESC"),
      "recent_alerts": db.q("SELECT id,ts,src_ip,dst_ip,category,confidence,severity FROM alerts ORDER BY id DESC LIMIT 10"),
      "top_ips": db.q("SELECT src_ip, COUNT(*) alerts FROM alerts GROUP BY src_ip ORDER BY alerts DESC LIMIT 8")}

@app.get("/api/events")
def events(search: str = "", protocol: str = "", prediction: str = "", suspicious_only: bool = False, limit: int = 100, offset: int = 0):
    w, a = ["1=1"], []
    if search: w.append("(src_ip LIKE ? OR dst_ip LIKE ? OR CAST(dst_port AS TEXT)=?)"); a += [f"%{search}%", f"%{search}%", search]
    if protocol: w.append("protocol=?"); a.append(protocol)
    if prediction: w.append("prediction=?"); a.append(prediction)
    if suspicious_only: w.append("prediction!='Normal'")
    where = " AND ".join(w)
    return {"total": db.q1(f"SELECT COUNT(*) n FROM events WHERE {where}", a)["n"], "rows": db.q(f"SELECT * FROM events WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?", a + [min(limit, 500), offset])}

@app.post("/api/upload")
def upload(file: UploadFile = File(...), analyze: bool = True):
    if not file.filename.lower().endswith(".csv"): raise HTTPException(400, "Please upload a .csv file")
    rep = ingest.ingest_df(_read(file), source=file.filename)
    return {"ingest": rep, "workflow": run_workflow() if analyze else None}

@app.post("/api/simulate")
def simulate(n: int = Query(300, ge=20, le=5000)):
    import numpy as np
    df = S.generate(n_per=max(10, n // 6), seed=int(datetime.now().timestamp()) % 10000).head(n)
    df["ts"] = [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * len(df)
    rep = ingest.ingest_df(df.drop(columns=["label"]), source="SIMULATED live traffic", simulated=1)
    return {"label": "SIMULATED traffic (locally generated, not real internet monitoring)", "ingest": rep, "workflow": run_workflow()}

@app.post("/api/analyze")
def analyze(): return run_workflow()

@app.post("/api/train")
def train(file: UploadFile = File(None)):
    if file is None: df = pd.read_csv(os.path.join(DATA_DIR, "sample_traffic.csv"))
    else: df = _read(file)
    mapped, rep = P.map_columns(df)
    if not rep["has_label"]: raise HTTPException(400, "Training needs a 'Label' column.")
    return {"mapping": rep, "metrics": P.train(mapped)}

@app.get("/api/model/metrics")
def model_metrics(): return P.metrics() or {}

@app.get("/api/incidents")
def incidents(status: str = "", severity: str = ""):
    w, a = ["1=1"], []
    if status: w.append("status=?"); a.append(status)
    if severity: w.append("severity=?"); a.append(severity)
    rows = db.q(f"SELECT * FROM incidents WHERE {' AND '.join(w)} ORDER BY risk_score DESC", a)
    for r in rows: r["evidence"] = None; r["response"] = db.jl(r["response"], {}); r["mitre"] = db.jl(r["mitre"]); r["intel"] = db.jl(r["intel"])
    return rows

@app.get("/api/incidents/{iid}")
def incident(iid: int):
    r = db.q1("SELECT * FROM incidents WHERE id=?", (iid,))
    if not r: raise HTTPException(404, "Incident not found")
    for k in ("evidence", "response", "mitre", "intel"): r[k] = db.jl(r[k])
    r["notes"] = db.q("SELECT * FROM notes WHERE incident_id=? ORDER BY id", (iid,)); r["alerts"] = db.q("SELECT * FROM alerts WHERE incident_id=? ORDER BY id LIMIT 50", (iid,))
    return r

class Patch(BaseModel):
    status: str | None = None; severity: str | None = None; blocked: bool | None = None
@app.patch("/api/incidents/{iid}")
def patch_incident(iid: int, p: Patch):
    if p.status and p.status not in ("Open", "Investigating", "Resolved", "False Positive"): raise HTTPException(400, "Invalid status")
    if p.severity and p.severity not in ("Critical", "High", "Medium", "Low"): raise HTTPException(400, "Invalid severity")
    if not db.q1("SELECT id FROM incidents WHERE id=?", (iid,)): raise HTTPException(404, "Incident not found")
    for col, v in (("status", p.status), ("severity", p.severity), ("blocked", None if p.blocked is None else int(p.blocked))):
        if v is not None: db.ex(f"UPDATE incidents SET {col}=? WHERE id=?", (v, iid))  # 'blocked' is a SIMULATED flag only
    return incident(iid)

class Note(BaseModel): text: str; author: str = "analyst"
@app.post("/api/incidents/{iid}/notes")
def add_note(iid: int, n: Note):
    if not n.text.strip(): raise HTTPException(400, "Note is empty")
    db.ex("INSERT INTO notes(incident_id,author,text,created_at) VALUES(?,?,?,?)", (iid, n.author, n.text.strip(), datetime.now().isoformat(timespec="seconds")))
    return incident(iid)

@app.get("/api/mitre")
def mitre_view():
    out = []
    for c in db.q("SELECT category, COUNT(*) n, MIN(id) example FROM incidents GROUP BY category"):
        m = mitre.lookup(c["category"])
        if m: out.append({**m, "category": c["category"], "related_incidents": c["n"], "example_incident": c["example"]})
    return {"detected": out, "reference": list(mitre.MITRE.values())}

class Chat(BaseModel): message: str
@app.post("/api/chat")
def chat_ep(c: Chat): return {"reply": chat.answer(c.message), "engine": "local rule-based assistant (no LLM)"}

@app.get("/api/reports/{kind}.{fmt}")
def report(kind: str, fmt: str, incident_id: int | None = None):
    if kind not in ("daily", "weekly", "incident", "traffic", "classification") or fmt not in ("pdf", "csv"): raise HTTPException(404, "Unknown report")
    if kind == "incident" and not incident_id: raise HTTPException(400, "incident_id required")
    rep = reports.build(kind, incident_id)
    body, mt = (reports.to_pdf(rep), "application/pdf") if fmt == "pdf" else (reports.to_csv(rep), "text/csv")
    return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{kind}_report.{fmt}"'})

@app.get("/api/intel")
def intel(): return threatintel.LOCAL_INTEL

@app.post("/api/reset")
def reset(): db.reset_db(); return {"ok": True}
