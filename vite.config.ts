import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

const apiProxyTarget = process.env.CPX_VITE_API_PROXY_TARGET || 'http://127.0.0.1:8000';
const frontendPort = Number(process.env.CPX_FRONTEND_PORT || '5173');

export default defineConfig({
  plugins: [react()],
  define: {
    __CPX_DEMO_MODE__: JSON.stringify(process.env.CPX_DEMO_MODE === '1'),
  },
  server: {
    host: '127.0.0.1',
    port: frontendPort,
    proxy: {
      '/api/v1': apiProxyTarget,
      '/health': apiProxyTarget,
    },
  },
  test: {
    include: ['src/ui/**/*.test.{ts,tsx}'],
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
  },
});
