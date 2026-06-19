import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

// Surface container. `accent` turns on the per-theme neon top-border (.sx-accent),
// which is how Cyber Grid / Terminal Noir get their signature look.
export function Card({ children, className, accent }: { children: ReactNode; className?: string; accent?: boolean }) {
  return (
    <div className={cn(accent && 'sx-accent', 'overflow-hidden rounded-xl border border-sx-border bg-sx-surface', className)}>
      {children}
    </div>
  )
}

// Header strip for a panel: small uppercase label + optional leading icon and
// trailing action (link/button).
export function SectionHeader({ title, icon, action }: { title: string; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex items-center gap-2 border-b border-sx-border px-4 py-3">
      {icon && <span className="text-sx-muted">{icon}</span>}
      <h2 className="sx-uplabel text-xs font-semibold text-sx-muted">{title}</h2>
      {action && <div className="ml-auto">{action}</div>}
    </div>
  )
}
