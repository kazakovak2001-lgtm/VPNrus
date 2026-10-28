import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Dev only: /admin/* is proxied to the real pocvpn-api (see
// gateway/tools/admin_dev_server.py). Override with VPN_ADMIN_API.
const target = process.env.VPN_ADMIN_API ?? "http://127.0.0.1:8787";
// Optional local multi-gateway hub (gateway/tools/run_admin_hub.py).
const hubTarget = process.env.VPN_HUB_API ?? "http://127.0.0.1:8790";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5173, proxy: {
      "/admin": { target, changeOrigin: false },
      // The hub only accepts its own Host header, so rewrite it.
      "/hub": { target: hubTarget, changeOrigin: true },
    } },
});
