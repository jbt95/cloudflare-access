import express from "express";
import { cloudflareAccessAuth } from "cloudflare-access/express";

const app = express();

// Use Cloudflare Access middleware
app.use(
  cloudflareAccessAuth({
    accessConfig: {
      teamDomain: "https://yourteam.cloudflareaccess.com",
      audTag: "your-audience-tag",
    },
  }),
);

app.get("/protected", (req, res) => {
  res.json({
    message: `Hello ${req.user?.email}`,
    userId: req.user?.userId,
    country: req.user?.country,
  });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
