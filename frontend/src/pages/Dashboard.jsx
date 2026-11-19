import { useState } from 'react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'
import { Activity, ShieldAlert, Flame, AlertOctagon, AlertTriangle, Info, Ban, Radar, Play, RefreshCw } from 'lucide-react'
import useApi from '../hooks/useApi'
import { post } from '../services/api'
import { Card, Loading, Empty, ErrorBox, Sev, Tag, SEV_HEX, tooltipStyle } from '../components/ui'

export default function Dashboard({ go }) {
  const { data, error, loading, reload } = useApi('/dashboard')
  const [busy, setBusy] = useState(false), [err, setErr] = useState(null)
  const sim = async () => { setBusy(true); setErr(null); try { await post('/simulate?n=600'); await reload() } catch (e) { setErr(e.message) } setBusy(false) }
  if (loading && !data) return <Loading />
  if (error) return <ErrorBox msg={error} />
  const s = data.stats
  const cards = [['Network events', s.events, Activity, 'text-accent'], ['Security alerts', s.alerts, ShieldAlert, 'text-blue-400'], ['Critical', s.critical, Flame, 'text-red-400'], ['High', s.high, AlertOctagon, 'text-orange-400'],
    ['Medium', s.medium, AlertTriangle, 'text-yellow-300'], ['Low', s.low, Info, 'text-cyan-300'], ['Blocked (simulated)', s.blocked, Ban, 'text-slate-300'], ['Active incidents', s.active, Radar, 'text-red-300']]
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div><h1 className="text-xl font-bold">SOC Command Center</h1><p className="text-xs text-slate-400">All figures are computed from stored events in SQLite.</p></div>
        <div className="flex gap-2"><button className="btn" onClick={reload}><RefreshCw size={14} />Refresh</button>
          <button className="btn btn-primary" disabled={busy} onClick={sim}><Play size={14} />{busy ? 'Analysing…' : 'Run simulated traffic'}</button></div>
      </div>
      <ErrorBox msg={err} />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {cards.map(([l, v, I, c]) => <Card key={l}><div className="flex items-center justify-between"><div><div className="text-xs text-slate-400">{l}</div><div className="mt-1 text-2xl font-bold">{(v ?? 0).toLocaleString()}</div></div><I className={c} size={22} /></div></Card>)}
      </div>
      {s.events === 0 ? <Card><Empty text="No data yet. Run simulated traffic, or upload a CSV on the Network Monitoring page."><button className="btn btn-primary" onClick={sim} disabled={busy}>Run simulated traffic</button></Empty></Card> : (<>
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Network activity (events per hour)" className="lg:col-span-2" right={<Tag>from stored events</Tag>}>
            <ResponsiveContainer width="100%" height={240}><AreaChart data={data.activity}><CartesianGrid stroke="#1c2a45" strokeDasharray="3 3" /><XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 10 }} tickFormatter={(h) => h.slice(5, 13)} /><YAxis tick={{ fill: '#64748b', fontSize: 10 }} /><Tooltip {...tooltipStyle} />
              <Area dataKey="events" stroke="#22d3ee" fill="#22d3ee33" name="All events" /><Area dataKey="suspicious" stroke="#ef4444" fill="#ef444433" name="Suspicious" /></AreaChart></ResponsiveContainer>
          </Card>
          <Card title="Threat distribution (incidents)">
            {data.threat_distribution.length ? <ResponsiveContainer width="100%" height={240}><PieChart><Pie data={data.threat_distribution} dataKey="value" nameKey="name" innerRadius={50} outerRadius={85} paddingAngle={3}>{data.threat_distribution.map((d) => <Cell key={d.name} fill={SEV_HEX[d.name] || '#64748b'} />)}</Pie><Tooltip {...tooltipStyle} /></PieChart></ResponsiveContainer> : <Empty text="No incidents yet." />}
          </Card>
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Attack frequency by category" className="lg:col-span-2">
            {data.attack_categories.length ? <ResponsiveContainer width="100%" height={220}><BarChart data={data.attack_categories}><CartesianGrid stroke="#1c2a45" strokeDasharray="3 3" /><XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10 }} /><YAxis tick={{ fill: '#64748b', fontSize: 10 }} /><Tooltip {...tooltipStyle} /><Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer> : <Empty text="No alerts yet." />}
          </Card>
          <Card title="Top suspicious IPs">
            {data.top_ips.length ? <ul className="space-y-2">{data.top_ips.map((i) => <li key={i.src_ip} className="flex justify-between font-mono text-sm"><span>{i.src_ip}</span><span className="text-red-400">{i.alerts} alerts</span></li>)}</ul> : <Empty text="No suspicious IPs." />}
          </Card>
        </div>
        <Card title="Recent security alerts" right={<button className="btn" onClick={() => go('incidents')}>View incidents</button>}>
          <div className="overflow-x-auto"><table className="w-full"><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Category</th><th>Confidence</th><th>Severity</th></tr></thead>
            <tbody>{data.recent_alerts.map((a) => <tr key={a.id}><td>{a.ts}</td><td className="font-mono">{a.src_ip}</td><td className="font-mono">{a.dst_ip}</td><td>{a.category}</td><td>{(a.confidence * 100).toFixed(0)}%</td><td><Sev v={a.severity} /></td></tr>)}</tbody></table></div>
        </Card>
      </>)}
    </div>
  )
}
