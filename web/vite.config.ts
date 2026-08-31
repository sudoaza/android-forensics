import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// `base: "./"` keeps the build portable across GitHub Pages project pages,
// custom domains, and offline file-served copies without a rebuild.
export default defineConfig({
    base: "./",
    plugins: [react()],
    build: {
        target: "es2023",
        sourcemap: true,
        // Fingerprinted assets are immutable; index.html must not be cached.
        assetsDir: "assets",
    },
    worker: {
        format: "es",
    },
    server: {
        port: 5173,
        strictPort: true,
    },
    test: {
        environment: "node",
        include: ["src/**/*.test.ts"],
    },
});
