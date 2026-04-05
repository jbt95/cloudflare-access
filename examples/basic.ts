/**
 * Basic Example - Static Configuration
 *
 * This example shows the simplest usage of the middleware with
 * hardcoded configuration. Not recommended for production use.
 */

import { Hono } from "hono";
import { createCloudflareAccessAuth, type CloudflareAccessHono } from "cloudflare-access/hono";

// Use the helper type for proper typing
const app: CloudflareAccessHono = new Hono();

// Apply middleware with static configuration
app.use(
  createCloudflareAccessAuth({
    accessConfig: {
      teamDomain: "https://myteam.cloudflareaccess.com",
      audTag: "my-application-audience-tag",
    },
  }),
);

// Protected route - user is properly typed
app.get("/api/protected", (c) => {
  const user = c.get("user");
  return c.json({
    message: "Hello from protected route",
    user: {
      email: user?.email,
      userId: user?.userId,
    },
  });
});

// Health check (no auth required if excluded in config)
app.get("/health", (c) => {
  return c.json({ status: "ok" });
});

export default app;

// For local testing with Bun
if (import.meta.main) {
  console.log("Basic example - Static configuration");
  console.log("This example requires valid Cloudflare Access credentials.");
  console.log("");
  console.log("To test with a real token:");
  console.log(
    '  curl -H "CF-Access-JWT-Assertion: <your-token>" http://localhost:8787/api/protected',
  );
}
