/**
 * Custom Error Handlers Example
 *
 * Customize the response when authentication fails or access is denied.
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
  ENVIRONMENT: string;
}

interface Variables {
  user?: CloudflareAccessUser;
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

app.use(
  createCloudflareAccessAuth({
    accessConfig: getCloudflareAccessConfigFromBindings,
    allowedEmails: ["admin@example.com"],

    // Custom unauthorized response
    onUnauthorized: (c, reason) => {
      return c.json(
        {
          error: "Authentication Required",
          message: "You must sign in to access this resource",
          reason,
          documentation: "https://docs.example.com/auth",
          support: "support@example.com",
        },
        401,
      );
    },

    // Custom forbidden response
    onForbidden: (c, email) => {
      return c.json(
        {
          error: "Access Denied",
          message: `Sorry ${email}, you don't have permission to access this resource`,
          requiredRole: "admin",
          currentUser: email,
          upgradeRequestUrl: "https://example.com/request-access",
        },
        403,
      );
    },

    // Skip auth for these paths
    excludePaths: ["/api/public", "/health", "/docs"],
  }),
);

// Public routes (no auth required)
app.get("/api/public", (c) => {
  return c.json({
    message: "This is public data",
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", (c) => {
  return c.json({ status: "healthy" });
});

// Protected routes
app.get("/api/private", (c) => {
  const user = c.get("user");
  return c.json({
    message: "Private data",
    accessedBy: user?.email,
  });
});

export default app;
