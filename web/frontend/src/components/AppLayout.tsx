import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Menu, Search, LogOut } from 'lucide-react'
import { useAuth } from '../auth/auth'
import { getTheme, applyTheme, THEMES, type Theme } from '../lib/theme'
import { useProject } from '../project/project'
import { Select } from './ui/Select'
import { NAV_ITEMS } from './nav'
import { CommandPalette } from './CommandPalette'

export function AppLayout() {
  const { logout } = useAuth()
  const { projects, currentSlug, setCurrentSlug } = useProject()
  const [open, setOpen] = useState(false)
  const [cmdOpen, setCmdOpen] = useState(false)
  const [theme, setTheme] = useState<Theme>(getTheme())

  return (
    <div className="min-h-screen bg-sx-bg text-sx-text">
      <CommandPalette open={cmdOpen} onOpenChange={setCmdOpen} />

      <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-sx-border bg-sx-surface/80 px-4 py-2.5 backdrop-blur">
        <button className="rounded-lg border border-sx-border p-1.5 text-sx-muted hover:text-sx-text md:hidden"
          onClick={() => setOpen(!open)} aria-label="Menu"><Menu size={18} /></button>
        <span className="flex items-center gap-2 font-bold tracking-wide">
          <span className="text-sx-primary">◆</span> Suricatoos
        </span>

        {/* ⌘K launcher — doubles as a visible search affordance */}
        <button onClick={() => setCmdOpen(true)}
          className="ml-2 hidden items-center gap-2 rounded-lg border border-sx-border bg-sx-bg/40 px-3 py-1.5 text-sm text-sx-muted transition-colors hover:border-sx-primary/40 hover:text-sx-text sm:flex">
          <Search size={14} />
          <span>Search…</span>
          <kbd className="ml-6 rounded border border-sx-border px-1.5 py-0.5 text-[10px]">⌘K</kbd>
        </button>

        <div className="ml-auto flex items-center gap-2">
          {projects.length > 0 && (
            <Select value={currentSlug} onValueChange={setCurrentSlug} title="Project" placeholder="Project"
              options={projects.map((p) => ({ value: p.slug, label: p.name }))} />
          )}
          <Select value={theme} onValueChange={(v) => { const t = v as Theme; setTheme(t); applyTheme(t) }} title="Theme"
            options={THEMES.map((t) => ({ value: t.id, label: t.label }))} />
          <button className="flex items-center gap-1.5 rounded-lg border border-sx-border px-3 py-1.5 text-sm text-sx-muted hover:border-sx-primary hover:text-sx-text"
            onClick={logout}><LogOut size={14} /><span className="hidden sm:inline">Logout</span></button>
        </div>
      </header>

      <div className="flex">
        <aside className={'fixed inset-y-0 left-0 z-20 mt-[49px] w-56 transform border-r border-sx-border bg-sx-surface p-3 transition-transform md:static md:mt-0 md:translate-x-0 ' + (open ? 'translate-x-0' : '-translate-x-full')}>
          <nav className="flex flex-col gap-1">
            {NAV_ITEMS.map((n) => {
              const Icon = n.icon
              return (
                <NavLink key={n.to} to={n.to} end={n.end} onClick={() => setOpen(false)}
                  className={({ isActive }) =>
                    'sx-uplabel flex items-center gap-2.5 rounded-lg border px-3 py-2 text-xs font-semibold transition-colors ' +
                    (isActive
                      ? 'border-sx-primary/40 bg-sx-primary/10 text-sx-primary'
                      : 'border-transparent text-sx-muted hover:bg-sx-surface-2 hover:text-sx-text')}>
                  <Icon size={16} />
                  {n.label}
                </NavLink>
              )
            })}
          </nav>
        </aside>
        <main className="min-w-0 flex-1 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
