import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      manifest: {
        name: '器材借还管理系统',
        short_name: '器材借还',
        description: '零知识加密的实验室与车间器材借还管理',
        start_url: '/',
        display: 'standalone',
        background_color: '#ffffff',
        theme_color: '#185FA5',
        lang: 'zh-CN',
        icons: [],
      },
      workbox: {
        navigateFallback: '/index.html',
        globPatterns: ['**/*.{js,css,html,svg,png}'],
      },
    }),
  ],
  server: { port: 5173 },
});
