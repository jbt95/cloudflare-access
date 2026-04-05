/**
 * Email Allowlist Example
 *
 * Restrict access to specific email addresses. This provides an additional
 * layer of security beyond Cloudflare Access policies.
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

interface Variables {
  user?: CloudflareAccessUser;
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Only allow specific emails
const ALLOWED_EMAILS = ["admin@company.com", "ceo@company.com", "cto@company.com"];

app.use(
  createCloudflareAccessAuth({
    accessConfig: getCloudflareAccessConfigFromBindings,
    allowedEmails: ALLOWED_EMAILS,
  }),
);

// Only accessible to allowed emails
app.get("/api/sensitive-data", (c) => {
  const user = c.get("user");

  return c.json({
    message: "Access granted to sensitive data",
    user: user?.email,
    data: {
      revenue: 1000000,
      projections: "classified",
    },
  });
});

export default app;
