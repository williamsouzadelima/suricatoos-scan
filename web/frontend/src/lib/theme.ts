// Identity themes: sets data-sx-theme on <html>; index.css holds each token set.
const KEY = 'sx_theme'

export type Theme = 'coral-mirage' | 'terminal-noir' | 'cyber-grid' | 'slate-pro'

export const THEMES: { id: Theme; label: string }[] = [
  { id: 'coral-mirage', label: 'Coral Mirage' },
  { id: 'terminal-noir', label: 'Terminal Noir' },
  { id: 'cyber-grid', label: 'Cyber Grid' },
  { id: 'slate-pro', label: 'Slate Pro' },
]

const DEFAULT: Theme = 'cyber-grid'
const IDS = THEMES.map((t) => t.id)

export function getTheme(): Theme {
  const t = localStorage.getItem(KEY) as Theme | null
  return t && IDS.includes(t) ? t : DEFAULT
}
export function applyTheme(t: Theme) {
  document.documentElement.setAttribute('data-sx-theme', t)
  localStorage.setItem(KEY, t)
}
// apply persisted theme on load
applyTheme(getTheme())
