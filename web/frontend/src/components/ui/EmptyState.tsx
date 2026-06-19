import type { ReactNode } from 'react'

// Consistent empty/zero-results state: muted icon, message and an optional hint
// (usually a call-to-action link).
export function EmptyState({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 px-4 py-14 text-center text-sx-muted">
      {icon && <span className="opacity-60">{icon}</span>}
      <p className="text-sm">{title}</p>
      {hint && <div className="text-sm">{hint}</div>}
    </div>
  )
}
