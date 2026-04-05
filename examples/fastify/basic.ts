import fastify from "fastify";
import { cloudflareAccessPlugin } from "cloudflare-access/fastify";

const app = fastify();

// Register Cloudflare Access plugin
app.register(cloudflareAccessPlugin, {
  accessConfig: {
    teamDomain: "https://yourteam.cloudflareaccess.com",
    audTag: "your-audience-tag",
  },
});

app.get("/protected", async (request, _reply) => {
  return {
    message: `Hello ${request.user?.email}`,
    userId: request.user?.userId,
    country: request.user?.country,
  };
});

app.listen({ port: 3000 }, () => {
  console.log("Server running on http://localhost:3000");
});
