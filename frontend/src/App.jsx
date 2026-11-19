import { useState } from 'react'
import Layout from './layouts/Layout'
import Dashboard from './pages/Dashboard'
import Network from './pages/Network'
import Detection from './pages/Detection'
import Analyst from './pages/Analyst'
import Incidents from './pages/Incidents'
import Mitre from './pages/Mitre'
import Reports from './pages/Reports'
import SettingsPage from './pages/Settings'
export default function App() {
  const [page, setPage] = useState('dashboard')
  const P = { dashboard: Dashboard, network: Network, detection: Detection, analyst: Analyst, incidents: Incidents, mitre: Mitre, reports: Reports, settings: SettingsPage }[page]
  return <Layout page={page} setPage={setPage}><P go={setPage} /></Layout>
}
