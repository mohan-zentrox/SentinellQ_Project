import { defineConfig } from "vite";
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
});
