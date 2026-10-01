// `defineConfig` from vitest/config, not vite: it is the one that types the
// `test` key below. Importing from "vite" makes tsc reject the whole block.
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Local dev convenience: same-origin calls to /v1/* are forwarded to
      // the FastAPI backend (see docker-compose.yml / .env.example for the
      // VITE_API_BASE_URL alternative used in the built app).
      "/v1": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // Exclude the build output and dependencies; without this vitest tries to
    // collect tests from dist/ after a production build.
    exclude: ["node_modules", "dist"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/test/**", "src/main.tsx", "src/vite-env.d.ts"],
    },
  },
});
