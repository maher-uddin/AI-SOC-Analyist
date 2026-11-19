import { useEffect, useRef, useState } from 'react'
import { Bot, Send, Workflow, CheckCircle2 } from 'lucide-react'
import { post } from '../services/api'
import { Card, ErrorBox, Sev } from '../components/ui'

const STAGES = [['Detection', 'ML + rules create alerts'], ['Investigation', 'Correlates alerts into incidents'], ['Threat Intel', 'Local indicator list (offline)'], ['Risk Assessment', 'Scores severity'], ['Incident Response', 'Recommends actions (not executed)'], ['Report', 'Writes the summary']]
const SUGGEST = ["What are today's critical threats?", 'Which attacks were detected?', 'Show repeated failed connections', 'Summarize the latest security events', 'Explain incident 1', 'What should I do about incident 1?']

export default function Analyst() {
  const [run, setRun] = useState(null), [busy, setBusy] = useState(false), [err, setErr] = useState(null)
  const [msgs, setMsgs] = useState([{ from: 'bot', text: "I'm a local rule-based assistant, not an LLM. I answer from the SQLite database and the detection engine." }]), [text, setText] = useState(''), [wait, setWait] = useState(false), end = useRef()
  useEffect(() => { end.current?.scrollIntoView({ behavior: 'smooth' }) }, [msgs])
  const analyze = async () => { setBusy(true); setErr(null); try { setRun(await post('/analyze')) } catch (e) { setErr(e.message) } setBusy(false) }
  const send = async (t) => { t = (t ?? text).trim(); if (!t || wait) return; setText(''); setMsgs((m) => [...m, { from: 'me', text: t }]); setWait(true)
    try { const r = await post('/chat', { message: t }); setMsgs((m) => [...m, { from: 'bot', text: r.reply }]) } catch (e) { setMsgs((m) => [...m, { from: 'bot', text: 'Error: ' + e.message }]) } setWait(false) }
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="space-y-4">
        <h1 className="text-xl font-bold">AI SOC Analyst (6 local agents)</h1>
        <ErrorBox msg={err} />
        <Card title="Agent workflow" right={<button className="btn btn-primary" disabled={busy} onClick={analyze}><Workflow size={14} />{busy ? 'Investigating…' : 'Investigate new events'}</button>}>
          <ol className="space-y-2">{STAGES.map(([n, d], i) => <li key={n} className="flex items-center gap-3 rounded-lg border border-edge p-2"><CheckCircle2 size={16} className={run ? 'text-emerald-400' : 'text-slate-600'} /><div><div className="text-sm font-medium">{i + 1}. {n} Agent</div><div className="text-xs text-slate-400">{d}</div></div></li>)}</ol>
          <p className="mt-3 text-xs text-slate-400">Agents exchange structured JSON and run in this order. Only events not yet analysed are processed.</p>
          {run && <div className="mt-3 rounded-lg border border-edge p-3 text-sm">Created <b>{run.alerts_created}</b> alerts and <b>{run.incidents_created.length}</b> incidents.
            <div className="mt-2 flex flex-wrap gap-2">{run.incidents_created.slice(0, 12).map((i) => <span key={i.incident_id} className="flex items-center gap-1 text-xs">INC-{String(i.incident_id).padStart(4, '0')} <Sev v={i.severity} /></span>)}</div></div>}
        </Card>
      </div>
      <Card title="Threat investigation chat" className="flex h-[620px] flex-col" right={<Bot size={16} className="text-accent" />}>
        <div className="flex-1 space-y-3 overflow-y-auto pr-1">{msgs.map((m, i) => <div key={i} className={`flex ${m.from === 'me' ? 'justify-end' : ''}`}><div className={`max-w-[85%] whitespace-pre-wrap rounded-xl px-3 py-2 text-sm ${m.from === 'me' ? 'bg-accent/15 text-accent' : 'border border-edge bg-bg'}`}>{m.text}</div></div>)}{wait && <div className="text-xs text-slate-500">Searching the database…</div>}<div ref={end} /></div>
        <div className="my-2 flex flex-wrap gap-1">{SUGGEST.map((s) => <button key={s} className="btn !px-2 !py-1 text-xs" onClick={() => send(s)}>{s}</button>)}</div>
        <div className="flex gap-2"><input className="inp flex-1" value={text} placeholder="Ask about threats, IPs or incidents…" onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && send()} /><button className="btn btn-primary" onClick={() => send()}><Send size={14} /></button></div>
      </Card>
    </div>
  )
}
