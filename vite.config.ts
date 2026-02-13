import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: "/peek-a-bin/",
  plugins: [react(), tailwindcss()],
  optimizeDeps: {
    exclude: ["capstone-wasm"],
  },
});
