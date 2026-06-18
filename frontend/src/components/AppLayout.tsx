import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/auth'
import { getTheme, toggleTheme, type Theme } from '../lib/theme'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/osint', label: 'OSINT', end: false },
]

export function AppLayout() {
  const { logout } = useAuth()
  const [open, setOpen] = useState(false)
  const [theme, setTheme] = useState<Theme>(getTheme())

  return (
    <div className="min-h-screen bg-sx-bg text-sx-text">
      <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-sx-border bg-sx-surface px-4 py-3">
        <button className="rounded-lg border border-sx-border px-2 py-1 md:hidden" onClick={() => setOpen(!open)} aria-label="Menu">☰</button>
        <span className="font-semibold">Suricatoos</span>
        <span className="text-xs text-sx-muted">SPA</span>
        <div className="ml-auto flex items-center gap-2">
          <button className="rounded-lg border border-sx-border px-2 py-1 text-sm hover:border-sx-primary"
            onClick={() => setTheme(toggleTheme())} title="Toggle theme">{theme === 'dark' ? '☀' : '☾'}</button>
          <button className="rounded-lg border border-sx-border px-3 py-1 text-sm hover:border-sx-primary" onClick={logout}>Logout</button>
        </div>
      </header>
      <div className="flex">
        <aside className={'fixed inset-y-0 left-0 z-10 mt-[57px] w-56 transform border-r border-sx-border bg-sx-surface p-3 transition-transform md:static md:mt-0 md:translate-x-0 ' + (open ? 'translate-x-0' : '-translate-x-full')}>
          <nav className="flex flex-col gap-1">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.end} onClick={() => setOpen(false)}
                className={({ isActive }) => 'rounded-lg px-3 py-2 text-sm ' + (isActive ? 'bg-sx-primary text-white' : 'text-sx-muted hover:bg-sx-surface-2')}>
                {n.label}
              </NavLink>
            ))}
          </nav>
        </aside>
        <main className="min-w-0 flex-1 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
