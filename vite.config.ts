import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // Relative base so the build works under whatever subpath GitHub Pages serves
  // it from (e.g. /antisplit-web/) without hardcoding a case-sensitive repo name.
  base: "./",
  plugins: [react()],
  build: {
    target: "es2022"
  }
});
