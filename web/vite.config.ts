/// <reference types="vitest/config" />
import { tanstackRouter } from '@tanstack/router-plugin/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The backend (hallpass serve) listens on :8080 by default (internal/config/defaults.go).
const apiTarget = process.env.HALLPASS_DEV_API_URL ?? 'http://127.0.0.1:8080';

// Mirrors the production CSP in docs/PLAN.md §12.3 so `pnpm preview` exercises the built assets under it.
// The dev server cannot use it: Vite's HMR/React Refresh preamble needs inline scripts.
const productionCsp = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ');

export default defineConfig({
  plugins: [
    // Must run before the React plugin.
    tanstackRouter({
      target: 'react',
      autoCodeSplitting: true,
      routesDirectory: './src/routes',
      generatedRouteTree: './src/routeTree.gen.ts',
      quoteStyle: 'single',
    }),
    react(),
  ],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: apiTarget, changeOrigin: false },
      '/auth/oidc': { target: apiTarget, changeOrigin: false },
    },
  },
  preview: {
    headers: { 'Content-Security-Policy': productionCsp },
    proxy: {
      '/api': { target: apiTarget, changeOrigin: false },
      '/auth/oidc': { target: apiTarget, changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    modulePreload: { polyfill: false },
    // Never inline assets as data: URIs. The CSP allows data: only for images (img-src), so inlined
    // fonts would be blocked by `default-src 'self'`.
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1500,
  },
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    restoreMocks: true,
  },
});
