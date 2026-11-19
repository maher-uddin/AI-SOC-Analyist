import { useState } from 'react'
import { Trash2 } from 'lucide-react'
import useApi from '../hooks/useApi'
import { post } from '../services/api'
import { Card, ErrorBox } from '../components/ui'
export default function Settings() {
  const { data, error, reload } = useApi('/health'), [msg, setMsg] = useState(null), [err, setErr] = useState(null)
  const reset = async () => { if (!window.confirm('Delete all events, alerts, incidents and notes? Trained models are kept.')) return
    try { await post('/reset'); setMsg('Database cleared.'); reload() } catch (e) { setErr(e.message) } }
  return (<div className="max-w-2xl space-y-4"><h1 className="text-xl font-bold">Settings</h1><ErrorBox msg={error || err} />
    <Card title="System status"><p className="text-sm">Backend: {data ? <span className="text-emerald-400">connected</span> : <span className="text-red-400">unreachable</span>} · Model: {data?.model_trained ? <span className="text-emerald-400">trained</span> : <span className="text-amber-300">not trained</span>}</p>
      <p className="mt-2 text-xs text-slate-400">Everything runs locally. No external APIs, API keys or cloud services are used. Traffic marked "simulated" is locally generated, not real internet monitoring.</p></Card>
    <Card title="Data"><button className="btn !border-red-500/50 !text-red-300" onClick={reset}><Trash2 size={14} />Clear all events and incidents</button>{msg && <p className="mt-2 text-sm text-emerald-400">{msg}</p>}</Card></div>)
}
