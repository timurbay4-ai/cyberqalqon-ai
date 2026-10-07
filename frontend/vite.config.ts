import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";
import { loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, ".", "CYBERQALQON_");
  const proxyTarget = environment.CYBERQALQON_DEV_PROXY_TARGET?.trim();
  const proxy = proxyTarget
    ? Object.fromEntries(
        ["/api", "/health", "/readiness"].map((path) => [path, { target: proxyTarget }]),
      )
    : undefined;

  return {
    plugins: [react()],
    server: {
      host: "localhost",
      port: 5173,
      strictPort: true,
      proxy,
    },
    preview: {
      host: "localhost",
      port: 4173,
    },
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      css: true,
    },
  };
});
