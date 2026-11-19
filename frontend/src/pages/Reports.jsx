import { FileDown } from 'lucide-react'
import { reportUrl } from '../services/api'
import { Card } from '../components/ui'
const R = [['daily', 'Daily security report', 'Incidents by severity, top incidents and alert categories.'], ['weekly', 'Weekly threat summary', 'Same breakdown framed as a weekly summary of stored data.'],
  ['traffic', 'Network traffic analysis', 'Protocols, top talkers and most-used destination ports.'], ['classification', 'Attack classification report', 'Model predictions and average confidence per class.']]
export default function Reports() {
  return (<div className="space-y-4"><h1 className="text-xl font-bold">Reports & Analytics</h1>
    <div className="grid gap-4 md:grid-cols-2">{R.map(([k, t, d]) => <Card key={k} title={t}><p className="mb-3 text-sm text-slate-400">{d}</p><div className="flex gap-2"><a className="btn btn-primary" href={reportUrl(k, 'pdf')}><FileDown size={14} />PDF</a><a className="btn" href={reportUrl(k, 'csv')}><FileDown size={14} />CSV</a></div></Card>)}</div>
    <p className="text-xs text-slate-400">Incident investigation reports are downloaded from each incident's detail panel on the Incidents page. Reports use data currently in the database; with an empty database they will be mostly empty.</p></div>)
}
