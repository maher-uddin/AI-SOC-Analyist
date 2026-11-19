import { LayoutDashboard, Activity, BrainCircuit, Bot, ShieldAlert, Target, FileText, Settings, ShieldCheck } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
export const NAV = [
  ['dashboard', 'Dashboard', LayoutDashboard], ['network', 'Network Monitoring', Activity], ['detection', 'Threat Detection', BrainCircuit],
  ['analyst', 'AI SOC Analyst', Bot], ['incidents', 'Incidents', ShieldAlert], ['mitre', 'MITRE ATT&CK', Target], ['reports', 'Reports', FileText], ['settings', 'Settings', Settings],
]
export default function Layout({ page, setPage, children }) {
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-edge bg-panel/70 p-4 md:flex">
        <div className="mb-6 flex items-center gap-2"><ShieldCheck className="text-accent" /><div><div className="text-sm font-bold tracking-wide">SOC ANALYST</div><div className="text-[10px] text-slate-400">LOCAL · NO EXTERNAL APIs</div></div></div>
        <nav className="flex flex-col gap-1">
          {NAV.map(([k, label, Icon]) => (
            <button key={k} onClick={() => setPage(k)} className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition ${page === k ? 'bg-accent/10 text-accent' : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'}`}><Icon size={16} />{label}</button>
          ))}
        </nav>
      </aside>
      <main className="min-w-0 flex-1">
        <div className="flex gap-1 overflow-x-auto border-b border-edge p-2 md:hidden">{NAV.map(([k, l]) => <button key={k} onClick={() => setPage(k)} className={`btn shrink-0 ${page === k ? 'btn-primary' : ''}`}>{l}</button>)}</div>
        <AnimatePresence mode="wait"><motion.div key={page} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.18 }} className="p-4 md:p-6">{children}</motion.div></AnimatePresence>
      </main>
    </div>
  )
}
