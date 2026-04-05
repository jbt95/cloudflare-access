/**
 * Hono Router Example
 *
 * Using the middleware with Hono's router pattern for modular APIs.
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
}

// Extend Hono's variables type
interface Variables {
  user?: CloudflareAccessUser;
}

// Create typed Hono app
const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// API v1 routes
const apiV1 = new Hono<{ Bindings: Bindings; Variables: Variables }>();

apiV1.use(
  createCloudflareAccessAuth({
    accessConfig: getCloudflareAccessConfigFromBindings,
  }),
);

apiV1.get("/users/me", (c) => {
  const user = c.get("user");
  return c.json({
    id: user?.userId,
    email: user?.email,
    country: user?.country,
  });
});

apiV1.get("/dashboard", (c) => {
  const user = c.get("user");
  return c.json({
    welcome: `Hello ${user?.email}`,
    lastLogin: new Date().toISOString(),
  });
});

// Public routes
const publicRouter = new Hono();

publicRouter.get("/status", (c) => {
  return c.json({
    status: "operational",
    version: "1.0.0",
  });
});

// Mount routers
app.route("/api/v1", apiV1);
app.route("/public", publicRouter);

export default app;

/*
Route structure:
- GET /api/v1/users/me     -> Protected (requires auth)
- GET /api/v1/dashboard    -> Protected (requires auth)
- GET /public/status       -> Public (no auth)
*/
