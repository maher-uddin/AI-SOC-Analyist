import { useEffect, useRef, useState } from 'react'
import { Upload, Play, Search } from 'lucide-react'
import useApi from '../hooks/useApi'
import { upload, post } from '../services/api'
import { Card, Loading, Empty, ErrorBox, Tag } from '../components/ui'

export default function Network() {
  const [f, setF] = useState({ search: '', protocol: '', prediction: '', suspicious_only: false }), [page, setPage] = useState(0)
  const qs = new URLSearchParams({ ...f, suspicious_only: f.suspicious_only, limit: 50, offset: page * 50 }).toString()
  const { data, error, loading, reload } = useApi('/events?' + qs)
  const [busy, setBusy] = useState(''), [msg, setMsg] = useState(null), [err, setErr] = useState(null)
  const fileRef = useRef()
  useEffect(() => { setPage(0) }, [f])
  const run = async (name, fn) => { setBusy(name); setErr(null); setMsg(null); try { const r = await fn(); setMsg(r); reload() } catch (e) { setErr(e.message) } setBusy('') }
  const onFile = (e) => { const file = e.target.files[0]; e.target.value = ''; if (file) run('upload', () => upload('/upload', file)) }
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2"><h1 className="text-xl font-bold">Network Traffic Monitoring</h1>
        <div className="flex gap-2"><input ref={fileRef} type="file" accept=".csv" hidden onChange={onFile} />
          <button className="btn" disabled={!!busy} onClick={() => fileRef.current.click()}><Upload size={14} />{busy === 'upload' ? 'Analysing (large files take a while)…' : 'Upload CSV & analyze'}</button>
          <button className="btn btn-primary" disabled={!!busy} onClick={() => run('sim', () => post('/simulate?n=300'))}><Play size={14} />{busy === 'sim' ? 'Generating…' : 'Simulated live traffic'}</button></div></div>
      <ErrorBox msg={err} />
      {msg && <Card><div className="text-sm">{msg.label && <div className="mb-1"><Tag tone="amber">simulated</Tag> {msg.label}</div>}
        Ingested <b>{msg.ingest.rows}</b> events. Predictions: {Object.entries(msg.ingest.predicted).map(([k, v]) => `${k} ${v}`).join(', ')}.
        {msg.workflow && <> Agents created <b>{msg.workflow.alerts_created}</b> alerts and <b>{msg.workflow.incidents_created.length}</b> incidents.</>}
        {msg.ingest.note && <div className="mt-1 text-amber-300">{msg.ingest.note}</div>}
        {msg.ingest.sampled_to && <div className="text-slate-400">Large file: a random sample of {msg.ingest.sampled_to} rows was analysed.</div>}</div></Card>}
      <Card>
        <div className="mb-3 flex flex-wrap gap-2">
          <div className="relative"><Search size={14} className="absolute left-2.5 top-2.5 text-slate-500" /><input className="inp pl-8" placeholder="Search IP or port" value={f.search} onChange={(e) => setF({ ...f, search: e.target.value })} /></div>
          <select className="inp" value={f.protocol} onChange={(e) => setF({ ...f, protocol: e.target.value })}><option value="">All protocols</option><option>TCP</option><option>UDP</option></select>
          <select className="inp" value={f.prediction} onChange={(e) => setF({ ...f, prediction: e.target.value })}><option value="">All classes</option>{['Normal', 'DoS', 'DDoS', 'PortScan', 'BruteForce', 'Botnet', 'SuspiciousOutbound'].map((c) => <option key={c}>{c}</option>)}</select>
          <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={f.suspicious_only} onChange={(e) => setF({ ...f, suspicious_only: e.target.checked })} />Suspicious only</label>
        </div>
        {loading && !data ? <Loading /> : error ? <ErrorBox msg={error} /> : !data.rows.length ? <Empty text="No events match. Upload a CSV or run simulated traffic." /> : (<>
          <div className="overflow-x-auto"><table className="w-full"><thead><tr><th>Time</th><th>Source IP</th><th>Dest IP</th><th>SPort</th><th>DPort</th><th>Proto</th><th>Pkts</th><th>Duration (s)</th><th>Bytes</th><th>Status</th><th>Class</th><th>Conf.</th></tr></thead>
            <tbody>{data.rows.map((e) => <tr key={e.id}><td>{e.ts}</td><td className="font-mono">{e.src_ip}{e.ip_simulated ? <span title="IP generated, not in dataset" className="ml-1 text-amber-400">*</span> : null}</td><td className="font-mono">{e.dst_ip}</td><td>{e.src_port}</td><td>{e.dst_port}</td><td>{e.protocol}</td><td>{e.packets}</td><td>{e.duration}</td><td>{Math.round(e.bytes).toLocaleString()}</td>
              <td><span className={e.prediction === 'Normal' ? 'text-emerald-400' : 'text-red-400'}>{e.prediction === 'Normal' ? 'Normal' : 'Suspicious'}</span>{e.simulated ? <span className="ml-1"><Tag tone="amber">sim</Tag></span> : null}</td><td>{e.prediction}</td><td>{(e.confidence * 100).toFixed(0)}%</td></tr>)}</tbody></table></div>
          <div className="mt-3 flex items-center justify-between text-sm text-slate-400"><span>{data.total.toLocaleString()} events · * = IP simulated</span>
            <div className="flex gap-2"><button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>Prev</button><button className="btn" disabled={(page + 1) * 50 >= data.total} onClick={() => setPage(page + 1)}>Next</button></div></div></>)}
      </Card>
    </div>
  )
}
