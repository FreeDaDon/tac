import { defineConfig } from "vite";

// Node globals without pulling in @types/node (only vite + typescript are dependencies).
declare const process: { env: Record<string, string | undefined> };

const clientPort = Number(process.env.TAC_DASHBOARD_CLIENT_PORT ?? 5173);
const serverPort = Number(process.env.TAC_DASHBOARD_PORT ?? 8000);
const target = `http://127.0.0.1:${serverPort}`;

export default defineConfig({
  server: {
    host: "127.0.0.1",
    port: clientPort,
    strictPort: true,
    proxy: {
      "/api": { target, changeOrigin: false },
      "/ws": { target, ws: true, changeOrigin: false },
    },
  },
  preview: { host: "127.0.0.1", port: clientPort, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
