import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev: Vite serves on :5173 at base '/', proxying /api to Django.
// Prod: built to ./dist (a Docker multi-stage builds it and copies dist -> the
// image's /opt/spa; collectstatic publishes it under /staticfiles/spa/, which
// nginx serves). The SPA is mounted at /app/ by a Django catch-all. The build is
// no longer committed — the image build produces it.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === 'production' ? '/staticfiles/spa/' : '/',
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true } },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
}))
