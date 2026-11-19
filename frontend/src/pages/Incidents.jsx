import { useState } from 'react'
import { FileDown, StickyNote, Ban } from 'lucide-react'
import useApi from '../hooks/useApi'
import { get, patch, post, reportUrl } from '../services/api'
import { Card, Loading, Empty, ErrorBox, Sev, Tag } from '../components/ui'

const STATUSES = ['Open', 'Investigating', 'Resolved', 'False Positive'], SEVS = ['Critical', 'High', 'Medium', 'Low']
export default function Incidents() {
  const [f, setF] = useState({ status: '', severity: '' })
  const { data, error, loading, reload } = useApi('/incidents?' + new URLSearchParams(f))
  const [sel, setSel] = useState(null), [note, setNote] = useState(''), [err, setErr] = useState(null)
  const open = async (id) => { setErr(null); try { setSel(await get('/incidents/' + id)) } catch (e) { setErr(e.message) } }
  const upd = async (body) => { try { setSel(await patch('/incidents/' + sel.id, body)); reload() } catch (e) { setErr(e.message) } }
  const addNote = async () => { if (!note.trim()) return; try { setSel(await post(`/incidents/${sel.id}/notes`, { text: note })); setNote('') } catch (e) { setErr(e.message) } }
  const ev = sel?.evidence
  return (
    <div className="grid gap-4 xl:grid-cols-5">
      <div className="space-y-3 xl:col-span-2">
        <h1 className="text-xl font-bold">Security Incidents</h1>
        <div className="flex gap-2"><select className="inp" value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })}><option value="">All statuses</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select>
          <select className="inp" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}><option value="">All severities</option>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></div>
        <ErrorBox msg={error || err} />
        <Card className="max-h-[70vh] overflow-y-auto !p-0">
          {loading && !data ? <Loading /> : !data?.length ? <Empty text="No incidents. Run simulated traffic or upload a CSV." /> : data.map((i) => (
            <button key={i.id} onClick={() => open(i.id)} className={`block w-full border-b border-edge/60 p-3 text-left hover:bg-white/5 ${sel?.id === i.id ? 'bg-accent/10' : ''}`}>
              <div className="flex items-center justify-between"><span className="font-mono text-xs text-slate-400">INC-{String(i.id).padStart(4, '0')}</span><Sev v={i.severity} /></div>
              <div className="mt-1 text-sm font-medium">{i.threat_name}</div><div className="text-xs text-slate-400">{i.status} · {i.event_count} alerts · risk {i.risk_score}</div></button>))}
        </Card>
      </div>
      <div className="xl:col-span-3">
        {!sel ? <Card><Empty text="Select an incident to investigate." /></Card> : (
          <Card title={`INC-${String(sel.id).padStart(4, '0')} · ${sel.threat_name}`} right={<div className="flex gap-2"><a className="btn" href={reportUrl('incident', 'pdf', sel.id)}><FileDown size={14} />PDF</a><a className="btn" href={reportUrl('incident', 'csv', sel.id)}>CSV</a></div>}>
            <div className="grid grid-cols-2 gap-2 text-sm md:grid-cols-3">{[['Source IP', sel.src_ip], ['Destination', sel.dst_ip], ['Detected', sel.detected_at], ['Category', sel.category], ['ML prediction', sel.ml_prediction], ['Confidence', (sel.confidence * 100).toFixed(1) + '%']].map(([k, v]) => <div key={k}><div className="text-xs text-slate-400">{k}</div><div className="font-mono">{v}</div></div>)}</div>
            <div className="my-3 flex flex-wrap items-center gap-2"><span className="text-xs text-slate-400">Status</span><select className="inp" value={sel.status} onChange={(e) => upd({ status: e.target.value })}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select>
              <span className="text-xs text-slate-400">Severity</span><select className="inp" value={sel.severity} onChange={(e) => upd({ severity: e.target.value })}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select>
              <button className="btn" onClick={() => upd({ blocked: !sel.blocked })}><Ban size={14} />{sel.blocked ? 'Unmark simulated block' : 'Simulate block'}</button>{sel.blocked ? <Tag tone="amber">simulated block</Tag> : null}
              <button className="btn btn-primary" onClick={() => upd({ status: 'Resolved' })}>Mark resolved</button></div>
            <h4 className="mt-2 text-sm font-semibold">Investigation summary</h4><p className="text-sm text-slate-300">{sel.summary}</p>
            {sel.intel && <p className="mt-2 text-sm"><Tag>local intel</Tag> {sel.intel.listed ? sel.intel.tag : 'Not on the local indicator list.'} <span className="text-xs text-slate-500">(offline list, no live lookup)</span></p>}
            {sel.mitre && <p className="mt-2 text-sm"><Tag>MITRE</Tag> {sel.mitre.id} {sel.mitre.name}</p>}
            <h4 className="mt-3 text-sm font-semibold">Evidence</h4>
            {ev && <ul className="list-disc pl-5 text-sm text-slate-300"><li>{ev.alert_count} correlated alerts, {ev.first_seen} to {ev.last_seen}</li><li>{ev.failed_or_empty_connections} failed/empty connections; {ev.distinct_dst_ports} distinct destination ports</li>{ev.unusual_ports?.length > 0 && <li>Unusual ports: {ev.unusual_ports.join(', ')}</li>}{ev.rules?.length > 0 && <li>Rules: {ev.rules.join(' | ')}</li>}<li>Top contributing features: {ev.sample_explanation}</li></ul>}
            <h4 className="mt-3 text-sm font-semibold">Recommended response <span className="text-xs font-normal text-slate-500">(recommendations only, nothing is executed)</span></h4>
            <ul className="list-disc pl-5 text-sm text-slate-300">{sel.response?.actions?.map((a) => <li key={a}>{a}</li>)}</ul>
            <h4 className="mt-3 flex items-center gap-1 text-sm font-semibold"><StickyNote size={14} />Analyst notes</h4>
            <div className="space-y-1">{sel.notes.length === 0 && <p className="text-xs text-slate-500">No notes yet.</p>}{sel.notes.map((n) => <div key={n.id} className="rounded border border-edge p-2 text-sm"><span className="text-xs text-slate-400">{n.created_at} · {n.author}</span><div>{n.text}</div></div>)}</div>
            <div className="mt-2 flex gap-2"><input className="inp flex-1" placeholder="Add an investigation note" value={note} onChange={(e) => setNote(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addNote()} /><button className="btn btn-primary" onClick={addNote}>Add</button></div>
          </Card>)}
      </div>
    </div>
  )
}
