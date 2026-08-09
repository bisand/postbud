import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

// Served by postbud-api at /admin, so every asset URL must carry that
// prefix. The dev server proxies /admin/api to a locally running
// `postbud serve` (override with POSTBUD_API_PROXY).
export default defineConfig({
  base: "/admin/",
  plugins: [svelte(), tailwindcss()],
  server: {
    proxy: {
      "/admin/api": process.env.POSTBUD_API_PROXY || "http://127.0.0.1:8080",
    },
  },
});
