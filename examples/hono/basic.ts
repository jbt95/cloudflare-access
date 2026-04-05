import { Hono } from "hono";
import {
  createCloudflareAccessAuth,
  getCloudflareAccessConfigFromBindings,
  type CloudflareAccessVariables,
} from "cloudflare-access/hono";

const app = new Hono<{ Variables: CloudflareAccessVariables }>();

// Use with Cloudflare Access bindings
app.use(
  createCloudflareAccessAuth({
    accessConfig: getCloudflareAccessConfigFromBindings,
  }),
);

app.get("/protected", (c) => {
  const user = c.get("user");
  return c.json({
    message: `Hello ${user?.email}`,
    userId: user?.userId,
    country: user?.country,
  });
});

export default app;
