import type { ReactNode } from 'react'

// Standard page header: an optional framed icon, title + subtitle, and a
// right-aligned actions slot. Every top-level screen uses this so headers stay
// consistent across the app.
export function PageHeader({ title, subtitle, icon, actions }: {
  title: string
  subtitle?: string
  icon?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header className="mb-6 flex flex-wrap items-center gap-3">
      {icon && (
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-sx-border bg-sx-surface text-sx-primary">
          {icon}
        </span>
      )}
      <div className="min-w-0">
        <h1 className="sx-uplabel text-2xl font-bold leading-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-sx-muted">{subtitle}</p>}
      </div>
      {actions && <div className="ml-auto flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}
