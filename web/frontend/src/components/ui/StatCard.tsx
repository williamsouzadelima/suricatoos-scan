import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'
import { Card } from './Card'

// KPI tile: big token-styled number (mono+glow on Cyber Grid via .sx-num), an
// icon that lights up on hover, an uppercase label and an optional sub-line.
export function StatCard({ icon, label, value, sub, accentText }: {
  icon: ReactNode
  label: string
  value: ReactNode
  sub?: ReactNode
  accentText?: string
}) {
  return (
    <Card accent className="group p-4 transition-colors duration-200 hover:border-sx-primary/40">
      <div className="flex items-start justify-between gap-2">
        <div className={cn('sx-num text-3xl font-bold leading-none', accentText ?? 'text-sx-text')}>{value}</div>
        <span className="shrink-0 text-sx-muted transition-colors duration-200 group-hover:text-sx-primary">{icon}</span>
      </div>
      <div className="sx-uplabel mt-3 text-[11px] font-semibold text-sx-muted">{label}</div>
      {sub != null && <div className="mt-1 text-xs text-sx-muted">{sub}</div>}
    </Card>
  )
}
