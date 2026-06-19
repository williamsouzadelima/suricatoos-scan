import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

// Token-driven pill (per-theme radius/outline via .sx-badge). Pass the color via
// a Tailwind text-*/bg-* class, e.g. <Badge className="text-sx-success">.
export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn('sx-badge inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium', className)}>
      {children}
    </span>
  )
}
