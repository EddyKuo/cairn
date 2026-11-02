// Vite 設定
// - base './'：產物以相對路徑引用，供 CairnConsole.exe 從 RCDATA 以 https://cairn.local/ 供應。
//   路由採 HashRouter，因此任何畫面的 URL 路徑永遠是 /index.html，相對資源路徑不會解析錯位。
// - 單一 chunk、資產不 inline 成 data URI 以外的外部資源（氣隙可用：不得有任何網路相依，part3 U-09）。
// - dev：/api/v1 proxy 至 CairnConsole.exe --dev-http 5080（僅 Debug 組建提供）。
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    cssCodeSplit: false,
    rollupOptions: {
      output: { manualChunks: undefined, inlineDynamicImports: true },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api/v1': { target: 'http://127.0.0.1:5080', changeOrigin: false },
    },
  },
});
