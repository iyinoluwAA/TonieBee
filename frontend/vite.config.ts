import { fileURLToPath, URL } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Development: /api goes to the local API (backend/, port 8000), so the website and the
// API share one address — exactly as live, where the host passes /api on.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5175,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false },
    },
  },
  build: {
    sourcemap: false,
    rollupOptions: {
      output: {
        // Mantine and React in their own file: they change rarely, so browsers keep them.
        manualChunks: (id) =>
          id.includes('node_modules/@mantine') || id.includes('node_modules/react')
            ? 'vendor'
            : id.includes('node_modules/@tabler')
              ? 'icons'
              : undefined,
      },
    },
  },
})
