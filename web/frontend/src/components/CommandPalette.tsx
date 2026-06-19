import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import * as Dialog from '@radix-ui/react-dialog'
import { Search, CornerDownLeft } from 'lucide-react'
import { NAV_ITEMS } from './nav'

// ⌘K / Ctrl-K command palette: fuzzy-ish filter over navigation destinations
// with full keyboard control. Controlled by AppLayout so the topbar search
// button and the global hotkey share one open state.
export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        onOpenChange(!open)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onOpenChange])

  // reset query/selection each time it opens
  useEffect(() => { if (open) { setQ(''); setActive(0) } }, [open])

  const results = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return NAV_ITEMS
    return NAV_ITEMS.filter((n) => n.label.toLowerCase().includes(needle))
  }, [q])

  const go = (to: string) => { onOpenChange(false); navigate(to) }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm data-[state=open]:animate-in data-[state=open]:fade-in" />
        <Dialog.Content
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)) }
            else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)) }
            else if (e.key === 'Enter') { e.preventDefault(); const r = results[active]; if (r) go(r.to) }
          }}
          className="fixed left-1/2 top-24 z-50 w-[min(92vw,560px)] -translate-x-1/2 overflow-hidden rounded-xl border border-sx-border bg-sx-surface shadow-2xl"
        >
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <div className="flex items-center gap-2 border-b border-sx-border px-4">
            <Search size={16} className="text-sx-muted" />
            <input
              autoFocus
              value={q}
              onChange={(e) => { setQ(e.target.value); setActive(0) }}
              placeholder="Jump to…"
              className="w-full bg-transparent py-3 text-sm text-sx-text outline-none placeholder:text-sx-muted"
            />
            <kbd className="rounded border border-sx-border px-1.5 py-0.5 text-[10px] text-sx-muted">ESC</kbd>
          </div>
          <ul className="max-h-72 overflow-y-auto p-2">
            {results.length === 0 && <li className="px-3 py-6 text-center text-sm text-sx-muted">No matches.</li>}
            {results.map((n, i) => {
              const Icon = n.icon
              return (
                <li key={n.to}>
                  <button
                    onMouseEnter={() => setActive(i)}
                    onClick={() => go(n.to)}
                    className={
                      'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm ' +
                      (i === active ? 'bg-sx-primary/10 text-sx-text' : 'text-sx-muted hover:bg-sx-surface-2')
                    }
                  >
                    <Icon size={16} className={i === active ? 'text-sx-primary' : ''} />
                    <span className="flex-1">{n.label}</span>
                    {i === active && <CornerDownLeft size={14} className="text-sx-muted" />}
                  </button>
                </li>
              )
            })}
          </ul>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
