import { fileURLToPath } from 'node:url'
import path from 'node:path'

import react from '@vitejs/plugin-react'
import UnoCSS from 'unocss/vite'
import { defineConfig } from 'vite'

const dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  base: '/',
  resolve: {
    alias: { '@': path.resolve(dirname, 'src') },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:2020',
      '/metrics': 'http://127.0.0.1:2020',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  css: {
    modules: { localsConvention: 'camelCase' },
    preprocessorOptions: {
      scss: { additionalData: '@use "@/styles/mixins" as *;' },
    },
  },
  plugins: [
    react(),
    UnoCSS(),
  ],
})
