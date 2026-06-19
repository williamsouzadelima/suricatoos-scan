import * as RT from '@radix-ui/react-tooltip'
import { type ReactNode } from 'react'

/** Themed Radix Tooltip. Tooltip.Provider is mounted once in main.tsx. */
export function Tip({ content, children }: { content: ReactNode; children: ReactNode }) {
  return (
    <RT.Root>
      <RT.Trigger asChild>{children}</RT.Trigger>
      <RT.Portal>
        <RT.Content
          sideOffset={6}
          className="z-50 max-w-xs rounded-md border border-sx-border bg-sx-surface px-2.5 py-1.5 text-xs text-sx-text shadow-xl data-[state=delayed-open]:animate-in data-[state=delayed-open]:fade-in-0 data-[state=delayed-open]:zoom-in-95"
        >
          {content}
          <RT.Arrow className="fill-sx-surface" />
        </RT.Content>
      </RT.Portal>
    </RT.Root>
  )
}
