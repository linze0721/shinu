// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import icon from "astro-icon";

/**
 * Deploy domain is not yet confirmed. It only affects the canonical link and
 * OG urls, so it is overridable at build time:
 *   SITE_URL=https://real.domain bun run build
 */
const site = process.env.SITE_URL ?? "https://shinu.sylvonic.com";

export default defineConfig({
  site,
  integrations: [icon()],
  vite: { plugins: [tailwindcss()] },
});
