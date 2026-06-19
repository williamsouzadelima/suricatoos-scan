/** Tokens mirror web/static/custom/premium-theme.css (--sx-*), dark by default. */
import animate from 'tailwindcss-animate'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        'sx-bg': 'var(--sx-bg)',
        'sx-surface': 'var(--sx-surface)',
        'sx-surface-2': 'var(--sx-surface-2)',
        'sx-border': 'var(--sx-border)',
        'sx-text': 'var(--sx-text)',
        'sx-muted': 'var(--sx-muted)',
        'sx-primary': 'var(--sx-primary)',
        'sx-primary-600': 'var(--sx-primary-600)',
        'sx-critical': 'var(--sx-critical)',
        'sx-high': 'var(--sx-high)',
        'sx-medium': 'var(--sx-medium)',
        'sx-low': 'var(--sx-low)',
        'sx-info': 'var(--sx-info)',
        'sx-success': 'var(--sx-success)',
      },
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
    },
  },
  plugins: [animate],
}
