import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': `${import.meta.dirname}/src`,
    },
  },
  server: {
    port: 3000,
    proxy: {
      // -----------------------------------------------------------------------
      // Development proxy: routes /api, /health, /ready to FastAPI at port 8000
      //
      // AUTHENTICATION ARCHITECTURE:
      //   - The backend supports optional bearer token auth (API_ACCESS_TOKEN).
      //   - For LOCAL DEVELOPMENT: leave API_ACCESS_TOKEN empty in backend/.env
      //     (auth disabled by design when token is unset).
      //   - For a SECURED local demo: set API_ACCESS_TOKEN in backend/.env AND
      //     set CYBERQALQON_PROXY_TOKEN in the shell before starting the dev server.
      //     The proxy then injects the Authorization header server-side so the token
      //     NEVER appears in the browser bundle, browser network inspector cookies,
      //     or VITE_* environment variables.
      //   - This proxy pattern is DEVELOPMENT ONLY. For production, implement proper
      //     user authentication (OAuth2/OIDC) with server-side session management.
      //
      // SECURITY: Never use VITE_API_ACCESS_TOKEN or any VITE_ prefixed variable
      // to pass the backend token. VITE_ vars are embedded in the browser bundle.
      // -----------------------------------------------------------------------
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        headers: (() => {
          const token = process.env['CYBERQALQON_PROXY_TOKEN'] ?? '';
          return token ? { Authorization: `Bearer ${token}` } : {};
        })(),
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/ready': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('node_modules')) {
            if (id.includes('react') || id.includes('react-dom') || id.includes('react-router')) {
              return 'vendor';
            }
          }
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    alias: {
      '@': `${import.meta.dirname}/src`,
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      exclude: ['src/api/fixtures.ts', 'src/test/**', 'dist/**'],
    },
  },
});

