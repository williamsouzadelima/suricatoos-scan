// Theme toggle: mirrors the Django app convention (data-sx-theme on <html>).
const KEY = 'sx_theme'
export type Theme = 'dark' | 'light'

export function getTheme(): Theme {
  return (localStorage.getItem(KEY) as Theme) || 'dark'
}
export function applyTheme(t: Theme) {
  document.documentElement.setAttribute('data-sx-theme', t)
  localStorage.setItem(KEY, t)
}
export function toggleTheme(): Theme {
  const next: Theme = getTheme() === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  return next
}
// apply persisted theme on load
applyTheme(getTheme())
