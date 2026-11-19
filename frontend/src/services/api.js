const B = '/api'
async function req(p, o) {
  let r
  try { r = await fetch(B + p, o) } catch { throw new Error('Cannot reach the backend. Is uvicorn running on port 8000?') }
  if (!r.ok) { let m = r.statusText; try { const j = await r.json(); m = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail) } catch {} throw new Error(m) }
  return r
}
export const get = (p) => req(p).then((r) => r.json())
export const post = (p, body) => req(p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then((r) => r.json())
export const patch = (p, body) => req(p, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json())
export const upload = (p, file) => {
  if (!file) return req(p, { method: 'POST' }).then((r) => r.json())
  const f = new FormData(); f.append('file', file)
  return req(p, { method: 'POST', body: f }).then((r) => r.json())
}
export const reportUrl = (kind, fmt, id) => `${B}/reports/${kind}.${fmt}${id ? `?incident_id=${id}` : ''}`
