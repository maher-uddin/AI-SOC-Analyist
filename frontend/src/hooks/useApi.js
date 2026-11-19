import { useCallback, useEffect, useState } from 'react'
import { get } from '../services/api'
export default function useApi(path) {
  const [data, setData] = useState(null), [error, setError] = useState(null), [loading, setLoading] = useState(true)
  const load = useCallback(() => { setLoading(true); return get(path).then((d) => { setData(d); setError(null) }).catch((e) => setError(e.message)).finally(() => setLoading(false)) }, [path])
  useEffect(() => { load() }, [load])
  return { data, error, loading, reload: load }
}
