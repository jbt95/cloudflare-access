/**
 * Cloudflare Workers Example - Environment Bindings
 *
 * This is the recommended approach for production. Configuration is read
 * from environment bindings set in wrangler.toml or Cloudflare dashboard.
 */

import { Hono } from "hono";
import {
  createCloudflareAccessAuth,
  getCloudflareAccessConfigFromBindings,
  type CloudflareAccessUser,
} from "cloudflare-access/hono";

// Define your environment bindings type
interface Bindings {
  // Cloudflare Access configuration
  CF_ACCESS_TEAM_DOMAIN: string;
  CF_ACCESS_AUD: string;

  // Your other bindings
  ENVIRONMENT: string;
  DB?: D1Database;
  CACHE?: KVNamespace;
}

// Define variables type
interface Variables {
  user?: CloudflareAccessUser;
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Apply middleware using bindings
app.use(
  createCloudflareAccessAuth({
    accessConfig: getCloudflareAccessConfigFromBindings,
    skipInDev: true, // Skip auth on localhost in non-prod environments
  }),
);

// Protected API routes
app.get("/api/user", (c) => {
  const user = c.get("user");

  return c.json({
    email: user?.email,
    userId: user?.userId,
    country: user?.country,
  });
});

app.get("/api/admin", (c) => {
  const user = c.get("user");

  // You can access the authenticated user's email
  console.log(`Admin access by: ${user?.email}`);

  return c.json({
    message: "Admin panel",
    admin: user?.email,
  });
});

// Export for Cloudflare Workers
export default app;

/*
## wrangler.toml configuration:

name = "my-app"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[vars]
ENVIRONMENT = "prod"
CF_ACCESS_TEAM_DOMAIN = "https://myteam.cloudflareaccess.com"

# Secrets (set via wrangler secret put)
# CF_ACCESS_AUD = "your-audience-tag"

## To set secrets:
# wrangler secret put CF_ACCESS_AUD
*/
