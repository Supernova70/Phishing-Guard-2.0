import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Local :8000 is the default; set VITE_DEV_API_TARGET to point at a
// container/remote backend while developing (e.g. http://172.18.0.3:8000).
const apiTarget = process.env.VITE_DEV_API_TARGET ?? 'http://localhost:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // Dev proxy: mirrors nginx (strip the /api prefix, keep SSE streaming)
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
      '/artifacts': apiTarget,
      '/health': apiTarget,
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
