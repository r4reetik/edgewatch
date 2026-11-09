import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  root,
  base: "/",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: fileURLToPath(new URL("../dist/web", import.meta.url)),
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
  server: {
    port: 5173,
    // Keep the browser's Host header (Vite's string shorthand rewrites it to the target). The API's CSRF check
    // compares Origin with Host, so a rewritten Host blocks every POST in development.
    proxy: { "/api": { target: "http://127.0.0.1:4317", changeOrigin: false } },
  },
});
