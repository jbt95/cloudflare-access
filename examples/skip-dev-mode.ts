/**
 * Skip Dev Mode Example
 *
 * Skip authentication during local development while still
 * requiring it in production.
 */

import { Hono } from "hono";
import {
  createCloudflareAccessAuth,
  getCloudflareAccessConfigFromBindings,
  type CloudflareAccessUser,
} from "cloudflare-access/hono";

interface Bindings {
  CF_ACCESS_TEAM_DOMAIN: string;
  CF_ACCESS_AUD: string;
  ENVIRONMENT: "dev" | "staging" | "prod";
}

interface Variables {
  user?: CloudflareAccessUser;
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

app.use(
  createCloudflareAccessAuth({
    accessConfig: getCloudflareAccessConfigFromBindings,

    // When true, auth is skipped for localhost/127.0.0.1
    // when ENVIRONMENT is not "prod"
    skipInDev: true,

    // Also exclude specific paths from auth
    excludePaths: ["/api/public", "/health"],
  }),
);

// This route:
// - Requires auth in production
// - Skips auth on localhost in dev/staging
app.get("/api/private", (c) => {
  const user = c.get("user");
  const env = c.env.ENVIRONMENT;

  // In dev mode, user might be undefined since auth is skipped
  if (!user) {
    return c.json({
      message: "Development mode - auth skipped",
      environment: env,
      note: "In production, this would require authentication",
    });
  }

  return c.json({
    message: "Production mode - authenticated",
    environment: env,
    user: user?.email,
  });
});

// Always public
app.get("/health", (c) => {
  return c.json({ status: "ok" });
});

export default app;

/*
## Development workflow:

1. Local development (no auth required):
   ```bash
   ENVIRONMENT=dev bun run dev
   curl http://localhost:8787/api/private
   # Returns: { message: "Development mode..." }
   ```

2. Production (auth required):
   ```bash
   # Deployed to Cloudflare with ENVIRONMENT=prod
   curl https://api.example.com/api/private
   # Returns: 401 Unauthorized

   curl -H "CF-Access-JWT-Assertion: <token>" https://api.example.com/api/private
   # Returns: { message: "Production mode...", user: "..." }
   ```
*/
