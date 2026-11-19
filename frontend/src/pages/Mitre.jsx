import useApi from '../hooks/useApi'
import { Card, Loading, Empty, ErrorBox, Tag } from '../components/ui'
export default function Mitre() {
  const { data, error, loading } = useApi('/mitre')
  if (loading && !data) return <Loading />
  if (error) return <ErrorBox msg={error} />
  return (
    <div className="space-y-4"><h1 className="text-xl font-bold">MITRE ATT&CK Mapping</h1><p className="text-xs text-slate-400">Mappings are stored locally and applied to the attack category of each incident.</p>
      {!data.detected.length ? <Card><Empty text="No detected activity to map yet." /></Card> : <div className="grid gap-4 md:grid-cols-2">{data.detected.map((m) => (
        <Card key={m.id} title={<span><span className="font-mono text-accent">{m.id}</span> {m.name}</span>} right={<Tag>{m.tactic}</Tag>}>
          <p className="text-sm text-slate-300">{m.description}</p><p className="mt-2 text-xs text-slate-400">Related detection: <b>{m.category}</b> · {m.related_incidents} incident(s), e.g. INC-{String(m.example_incident).padStart(4, '0')}</p>
          <p className="mt-2 text-sm"><span className="font-semibold">Mitigation: </span>{m.mitigation}</p></Card>))}</div>}
      <Card title="Local technique reference"><table className="w-full"><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr></thead><tbody>{data.reference.map((m) => <tr key={m.id}><td className="font-mono text-accent">{m.id}</td><td>{m.name}</td><td>{m.tactic}</td></tr>)}</tbody></table></Card>
    </div>)
}
