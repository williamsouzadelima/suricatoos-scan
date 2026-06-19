import { cn } from '../../lib/cn'

// Loading placeholder. Premium UIs show shaped skeletons, never raw "Loading…".
export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-md bg-sx-surface-2', className)} />
}
