import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/auth'

export function Login() {
  const { login } = useAuth()
  const nav = useNavigate()
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setErr(''); setBusy(true)
    try { await login(u, p); nav('/') }
    catch { setErr('Invalid credentials') }
    finally { setBusy(false) }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-sx-bg">
      <form onSubmit={submit} className="w-80 rounded-xl border border-sx-border bg-sx-surface p-6 shadow-lg">
        <h1 className="mb-1 text-xl font-bold tracking-wide text-sx-text"><span className="text-sx-primary">◆</span> Suricatoos</h1>
        <p className="mb-5 text-sm text-sx-muted">Sign in to continue</p>
        <input className="mb-3 w-full rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-2 text-sx-text outline-none focus:border-sx-primary"
          placeholder="Username" value={u} onChange={(e) => setU(e.target.value)} autoFocus />
        <input className="mb-4 w-full rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-2 text-sx-text outline-none focus:border-sx-primary"
          placeholder="Password" type="password" value={p} onChange={(e) => setP(e.target.value)} />
        {err && <p className="mb-3 text-sm text-sx-critical">{err}</p>}
        <button disabled={busy} className="w-full rounded-lg bg-sx-primary py-2 font-medium text-white hover:bg-sx-primary-600 disabled:opacity-60">
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
