import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev: Vite serves on :5173 at base '/', proxying /api to Django.
// Prod: built into web/static/spa with base '/staticfiles/spa/' (served by
// nginx via collectstatic); the SPA is mounted at /app/ by a Django catch-all.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === 'production' ? '/staticfiles/spa/' : '/',
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true } },
  },
  build: {
    outDir: '../web/static/spa',
    emptyOutDir: true,
    sourcemap: false,
  },
}))
