import * as RS from '@radix-ui/react-select'
import { cn } from '../../lib/cn'

export type SelectOption = { value: string; label: string }

/** Themed Radix Select — accessible value picker styled with our --sx-* tokens. */
export function Select({ value, onValueChange, options, placeholder, title, className }: {
  value: string
  onValueChange: (v: string) => void
  options: SelectOption[]
  placeholder?: string
  title?: string
  className?: string
}) {
  return (
    <RS.Root value={value} onValueChange={onValueChange}>
      <RS.Trigger
        title={title}
        className={cn(
          'inline-flex items-center gap-2 rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-1.5 text-sm text-sx-text outline-none',
          'hover:border-sx-primary focus:border-sx-primary data-[placeholder]:text-sx-muted',
          className,
        )}
      >
        <RS.Value placeholder={placeholder} />
        <RS.Icon className="text-sx-muted">▾</RS.Icon>
      </RS.Trigger>
      <RS.Portal>
        <RS.Content
          position="popper"
          sideOffset={6}
          className="z-50 min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-lg border border-sx-border bg-sx-surface shadow-xl"
        >
          <RS.Viewport className="p-1">
            {options.map((o) => (
              <RS.Item
                key={o.value}
                value={o.value}
                className={cn(
                  'relative flex cursor-pointer select-none items-center rounded-md px-7 py-1.5 text-sm text-sx-text outline-none',
                  'data-[highlighted]:bg-sx-surface-2 data-[state=checked]:text-sx-primary',
                )}
              >
                <RS.ItemIndicator className="absolute left-2 text-sx-primary">✓</RS.ItemIndicator>
                <RS.ItemText>{o.label}</RS.ItemText>
              </RS.Item>
            ))}
          </RS.Viewport>
        </RS.Content>
      </RS.Portal>
    </RS.Root>
  )
}
