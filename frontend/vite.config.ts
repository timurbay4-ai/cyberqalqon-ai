import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";
import { loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, ".", "CYBERQALQON_");
  const proxyTarget = environment.CYBERQALQON_DEV_PROXY_TARGET?.trim() || "http://127.0.0.1:8000";
  const proxy = Object.fromEntries(
    ["/api", "/health", "/readiness"].map((path) => [path, { target: proxyTarget }]),
  );

  return {
    plugins: [react()],
    server: {
      // Bind the documented IPv4 loopback explicitly. On Windows, `localhost`
      // can resolve to ::1 only, which makes 127.0.0.1 health validation fail.
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      proxy,
    },
    preview: {
      host: "127.0.0.1",
      port: 4173,
    },
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      css: true,
      testTimeout: 20_000,
      // Keep the complete suite reproducible on the same low-resource laptops
      // that run the local SOC lab. Vitest's default fork fan-out can exhaust
      // available process startup capacity while WSL telemetry is active.
      maxWorkers: 1,
      fileParallelism: false,
    },
  };
});
