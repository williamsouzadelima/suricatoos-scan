// Shared severity metadata so every screen (dashboard, vulns, scan detail)
// renders severities with the same colors/labels, all driven by the --sx-*
// theme tokens (so they recolor per identity theme).
export type SevKey = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEVERITY: { key: SevKey; label: string; cssVar: string; text: string }[] = [
  { key: 'critical', label: 'Critical', cssVar: 'var(--sx-critical)', text: 'text-sx-critical' },
  { key: 'high', label: 'High', cssVar: 'var(--sx-high)', text: 'text-sx-high' },
  { key: 'medium', label: 'Medium', cssVar: 'var(--sx-medium)', text: 'text-sx-medium' },
  { key: 'low', label: 'Low', cssVar: 'var(--sx-low)', text: 'text-sx-low' },
  { key: 'info', label: 'Info', cssVar: 'var(--sx-info)', text: 'text-sx-info' },
]
