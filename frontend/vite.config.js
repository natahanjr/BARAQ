import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiTarget = env.VITE_API_TARGET || "http://127.0.0.1:8001";
  const secure = apiTarget.startsWith("https://");
  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: apiTarget,
          changeOrigin: true,
          secure,
        },
        // Report files live on the backend; the page route "/reports" itself
        // must fall through to the SPA, so only proxy actual filenames.
        [/^\/reports\/.+\.(pdf|html|json|csv)$/]: {
          target: apiTarget,
          changeOrigin: true,
          secure,
        },
      },
    },
  };
});
