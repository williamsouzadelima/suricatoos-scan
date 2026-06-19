import * as RD from '@radix-ui/react-dialog'
import { type ReactNode } from 'react'

/** Themed Radix Dialog (controlled). Accessible modal: focus trap, Esc, overlay. */
export function Modal({ open, onOpenChange, title, description, children }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: string
  children: ReactNode
}) {
  return (
    <RD.Root open={open} onOpenChange={onOpenChange}>
      <RD.Portal>
        <RD.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-in" />
        <RD.Content className="fixed left-1/2 top-1/2 z-50 w-[420px] max-w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 rounded-xl border border-sx-border bg-sx-surface p-6 shadow-2xl outline-none">
          <div className="mb-1 flex items-center justify-between">
            <RD.Title className="sx-uplabel text-base font-bold text-sx-text">{title}</RD.Title>
            <RD.Close className="text-sx-muted hover:text-sx-text" aria-label="Close">✕</RD.Close>
          </div>
          {description && <RD.Description className="mb-4 text-sm text-sx-muted">{description}</RD.Description>}
          {children}
        </RD.Content>
      </RD.Portal>
    </RD.Root>
  )
}
