import { useRef, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { Brain, Upload } from 'lucide-react'
import useApi from '../hooks/useApi'
import { upload } from '../services/api'
import { Card, Loading, Empty, ErrorBox, tooltipStyle } from '../components/ui'

export default function Detection() {
  const { data: m, loading, reload } = useApi('/model/metrics')
  const [busy, setBusy] = useState(false), [err, setErr] = useState(null), [map, setMap] = useState(null), ref = useRef()
  const train = async (file) => { setBusy(true); setErr(null); try { const r = await upload('/train', file); setMap(r.mapping); await reload() } catch (e) { setErr(e.message) } setBusy(false) }
  if (loading && !m) return <Loading />
  const has = m && m.labels
  const max = has ? Math.max(1, ...m.confusion_matrix.flat()) : 1
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2"><h1 className="text-xl font-bold">Machine Learning Threat Detection</h1>
        <div className="flex gap-2"><input ref={ref} type="file" accept=".csv" hidden onChange={(e) => { const f = e.target.files[0]; e.target.value = ''; if (f) train(f) }} />
          <button className="btn" disabled={busy} onClick={() => train(null)}><Brain size={14} />Retrain on bundled sample</button>
          <button className="btn btn-primary" disabled={busy} onClick={() => ref.current.click()}><Upload size={14} />{busy ? 'Training…' : 'Train on my labelled CSV'}</button></div></div>
      <ErrorBox msg={err} />
      <p className="text-xs text-slate-400">Random Forest classifies the attack type; Isolation Forest flags unusual flows. 75/25 train/test split is made before fitting; all scores are from held-out test rows. The bundled sample is synthetic. Train on the same kind of data you analyse.</p>
      {map && <Card><div className="text-sm">Feature mapping: {map.mapped.length}/19 columns matched.{map.missing_filled_with_zero.length > 0 && <span className="text-amber-300"> Missing (filled with 0): {map.missing_filled_with_zero.join(', ')}</span>}</div></Card>}
      {!has ? <Card><Empty text="No trained model metrics yet. Click retrain." /></Card> : (<>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{['accuracy', 'precision', 'recall', 'f1'].map((k) => <Card key={k}><div className="text-xs uppercase text-slate-400">{k === 'f1' ? 'F1-score' : k}</div><div className="mt-1 text-2xl font-bold text-accent">{(m[k] * 100).toFixed(2)}%</div></Card>)}</div>
        <div className="text-xs text-slate-400">Test rows: {m.test_rows.toLocaleString()} · Train rows: {m.train_rows.toLocaleString()} · Isolation Forest (normal vs attack): precision {(m.isolation_forest.precision * 100).toFixed(1)}%, recall {(m.isolation_forest.recall * 100).toFixed(1)}%</div>
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Confusion matrix (rows = actual, columns = predicted)"><div className="overflow-x-auto"><table className="text-center"><thead><tr><th></th>{m.labels.map((l) => <th key={l} className="text-center">{l}</th>)}</tr></thead>
            <tbody>{m.confusion_matrix.map((row, i) => <tr key={i}><th>{m.labels[i]}</th>{row.map((v, j) => <td key={j} style={{ background: `rgba(34,211,238,${(v / max) * 0.7})` }} className={i !== j && v > 0 ? 'font-bold text-red-300' : ''}>{v}</td>)}</tr>)}</tbody></table></div></Card>
          <Card title="Top feature importances (explainability)"><ResponsiveContainer width="100%" height={260}><BarChart layout="vertical" data={Object.entries(m.feature_importance).slice(0, 10).map(([name, value]) => ({ name, value: +value.toFixed(4) }))}><CartesianGrid stroke="#1c2a45" strokeDasharray="3 3" /><XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} /><YAxis type="category" dataKey="name" width={120} tick={{ fill: '#94a3b8', fontSize: 10 }} /><Tooltip {...tooltipStyle} /><Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} /></BarChart></ResponsiveContainer></Card>
        </div>
        <Card title="Per-class results"><table className="w-full"><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead><tbody>{m.labels.map((l) => { const c = m.per_class[l]; return <tr key={l}><td>{l}</td><td>{(c.precision * 100).toFixed(1)}%</td><td>{(c.recall * 100).toFixed(1)}%</td><td>{(c['f1-score'] * 100).toFixed(1)}%</td><td>{c.support}</td></tr> })}</tbody></table></Card>
      </>)}
    </div>
  )
}
