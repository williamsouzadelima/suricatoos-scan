import * as RT from '@radix-ui/react-toast'
import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { cn } from '../../lib/cn'

type Variant = 'default' | 'success' | 'error'
type ToastItem = { id: number; title: string; description?: string; variant: Variant }
type ToastInput = { title: string; description?: string; variant?: Variant }

const Ctx = createContext<(t: ToastInput) => void>(() => {})
export function useToast() { return useContext(Ctx) }

const ACCENT: Record<Variant, string> = {
  default: 'border-l-sx-primary',
  success: 'border-l-sx-success',
  error: 'border-l-sx-critical',
}

let seq = 0

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const push = useCallback((t: ToastInput) => {
    seq += 1
    setToasts((prev) => [...prev, { id: seq, title: t.title, description: t.description, variant: t.variant ?? 'default' }])
  }, [])

  const remove = (id: number) => setToasts((prev) => prev.filter((t) => t.id !== id))

  return (
    <Ctx.Provider value={push}>
      <RT.Provider swipeDirection="right" duration={4000}>
        {children}
        {toasts.map((t) => (
          <RT.Root
            key={t.id}
            onOpenChange={(open) => { if (!open) remove(t.id) }}
            className={cn(
              'flex items-start gap-3 rounded-lg border border-l-4 border-sx-border bg-sx-surface px-4 py-3 shadow-xl',
              'data-[state=open]:animate-in data-[state=closed]:animate-out',
              ACCENT[t.variant],
            )}
          >
            <div className="min-w-0 flex-1">
              <RT.Title className="text-sm font-semibold text-sx-text">{t.title}</RT.Title>
              {t.description && <RT.Description className="mt-0.5 break-words text-xs text-sx-muted">{t.description}</RT.Description>}
            </div>
            <RT.Close className="text-sx-muted hover:text-sx-text" aria-label="Close">✕</RT.Close>
          </RT.Root>
        ))}
        <RT.Viewport className="fixed bottom-4 right-4 z-[60] flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2 outline-none" />
      </RT.Provider>
    </Ctx.Provider>
  )
}
