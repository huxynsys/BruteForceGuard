/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // Production build (Phase 9.3): emitted to dist/ and served by the
    // reverse proxy.  Source maps are not shipped to production clients.
    outDir: 'dist',
    sourcemap: false,
    // Split the largest third-party dependencies so the dashboard shell is
    // not one oversized chunk (Phase 8 flagged a single ~692 kB bundle).
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('node_modules/recharts')) return 'charts'
          if (id.includes('node_modules/d3')) return 'charts'
          if (
            id.includes('node_modules/react-dom') ||
            id.includes('node_modules/react-router') ||
            id.includes('node_modules/react/')
          ) {
            return 'react'
          }
          return undefined
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
    css: false,
  },
})

