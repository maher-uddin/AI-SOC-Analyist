import { Loader2, Inbox, AlertTriangle } from 'lucide-react'
export const SEV = { Critical: 'bg-red-500/15 text-red-400 border-red-500/40', High: 'bg-orange-500/15 text-orange-400 border-orange-500/40', Medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40', Low: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40' }
export const SEV_HEX = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22d3ee' }
export const Sev = ({ v }) => <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${SEV[v] || 'border-edge text-slate-400'}`}>{v || '-'}</span>
export const Card = ({ title, right, children, className = '' }) => (
  <section className={`rounded-xl border border-edge bg-panel/80 p-4 backdrop-blur ${className}`}>
    {(title || right) && <div className="mb-3 flex items-center justify-between gap-2"><h3 className="text-sm font-semibold text-slate-200">{title}</h3>{right}</div>}
    {children}
  </section>
)
export const Loading = ({ text = 'Loading…' }) => <div className="flex items-center gap-2 p-6 text-slate-400"><Loader2 className="animate-spin" size={16} />{text}</div>
export const Empty = ({ text, children }) => <div className="flex flex-col items-center gap-3 p-8 text-center text-slate-400"><Inbox size={28} /><p className="text-sm">{text}</p>{children}</div>
export const ErrorBox = ({ msg }) => msg ? <div className="mb-3 flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300"><AlertTriangle size={16} />{msg}</div> : null
export const Tag = ({ children, tone = 'cyan' }) => <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${tone === 'amber' ? 'border-amber-500/50 text-amber-300 bg-amber-500/10' : 'border-accent/40 text-accent bg-accent/10'}`}>{children}</span>
export const tooltipStyle = { contentStyle: { background: '#0e1628', border: '1px solid #1c2a45', borderRadius: 8, fontSize: 12 }, labelStyle: { color: '#94a3b8' } }
