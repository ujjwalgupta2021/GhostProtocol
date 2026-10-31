import { defineConfig } from 'vite';

export default defineConfig({
  base: './', // Universal relative base: works identically on Vercel, GitHub Pages, Netlify & local file previews
  server: {
    port: 5173,
    host: true,
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: true,
  },
  define: {
    // Polyfill for client-side libraries that reference process.env
    'process.env': {}
  }
});
