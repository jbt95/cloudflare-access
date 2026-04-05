<div align="center">

# 🔐 cloudflare-access

**Zero-config authentication for Cloudflare Access across all major frameworks**

[![npm version](https://img.shields.io/npm/v/cloudflare-access.svg?style=for-the-badge&color=3178C6)](https://www.npmjs.com/package/cloudflare-access)
[![npm downloads](https://img.shields.io/npm/dm/cloudflare-access.svg?style=for-the-badge&color=42B883)](https://www.npmjs.com/package/cloudflare-access)
[![license](https://img.shields.io/npm/l/cloudflare-access.svg?style=for-the-badge&color=F7DF1E)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

</div>

Secure, JWT-validated authentication middleware for **[Hono](https://hono.dev)**, **[Express](https://expressjs.com)**, **[Fastify](https://fastify.io)**, **[NestJS](https://nestjs.com)**, and **[Effect-TS](https://effect.website)**. Built for Cloudflare Access with automatic JWKS key rotation, local development bypass, and rich error handling.

---

## ✨ Features

| Feature                  | Description                                                    |
| ------------------------ | -------------------------------------------------------------- |
| 🔐 **JWT Validation**    | Full RS256 signature verification with automatic JWKS fetching |
| 🏢 **Cloudflare Access** | Native support for Cloudflare Access tokens & team domains     |
| 🚀 **Multi-Framework**   | Hono, Express, Fastify, NestJS, Effect-TS adapters             |
| 🔄 **Auto Key Rotation** | Automatic JWKS key fetching with in-memory caching             |
| 🛠️ **Dev-Friendly**      | Skip validation in local development (localhost detection)     |
| 📧 **Email Allowlist**   | Restrict access by email patterns                              |
| 🎯 **Rich Errors**       | Actionable error messages with `why` and `fix` hints           |
| 📦 **Type-Safe**         | Full TypeScript support with generated types                   |
| 🌐 **Edge-Ready**        | Works on Cloudflare Workers, Vercel Edge, Deno Deploy          |

---

## 📦 Installation

```bash
# npm
npm install cloudflare-access

# yarn
yarn add cloudflare-access

# bun (recommended)
bun add cloudflare-access
```

### Framework-Specific Setup

```bash
# 🎯 Hono - Edge-first web framework
bun add cloudflare-access hono

# 🚂 Express - Classic Node.js framework
bun add cloudflare-access express

# ⚡ Fastify - High-performance framework
bun add cloudflare-access fastify

# 🦁 NestJS - Enterprise framework
bun add cloudflare-access @nestjs/common @nestjs/core

# 🎭 Effect-TS - Functional programming
bun add cloudflare-access effect
```

---

## 🚀 Quick Start

### 🎯 Hono

```typescript
import { Hono } from "hono";
import { createCloudflareAccessAuth } from "cloudflare-access/hono";

const app = new Hono();

// Apply middleware to all routes
app.use(
  createCloudflareAccessAuth({
    accessConfig: {
      teamDomain: process.env.CF_ACCESS_TEAM_DOMAIN!,
      audTag: process.env.CF_ACCESS_AUD!,
    },
  }),
);

app.get("/api/user", (c) => {
  const user = c.get("user");
  return c.json({ email: user?.email, id: user?.userId });
});
```

### 🚂 Express

```typescript
import express from "express";
import { cloudflareAccessAuth } from "cloudflare-access/express";

const app = express();

app.use(
  cloudflareAccessAuth({
    accessConfig: {
      teamDomain: "https://yourteam.cloudflareaccess.com",
      audTag: "your-audience-tag",
    },
  }),
);

app.get("/api/user", (req, res) => {
  res.json({ email: req.user?.email, id: req.user?.userId });
});
```

### ⚡ Fastify

```typescript
import fastify from "fastify";
import { cloudflareAccessPlugin } from "cloudflare-access/fastify";

const app = fastify();

await app.register(cloudflareAccessPlugin, {
  accessConfig: {
    teamDomain: "https://yourteam.cloudflareaccess.com",
    audTag: "your-audience-tag",
  },
});

app.get("/api/user", async (request) => {
  return { email: request.user?.email };
});
```

### 🦁 NestJS

```typescript
import { Module, Controller, Get, Req } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { CloudflareAccessGuard, Public } from "cloudflare-access/nestjs";
import type { Request } from "express";

@Controller("api")
class ApiController {
  @Get("profile")
  getProfile(@Req() req: Request) {
    return { email: req.user?.email };
  }

  @Public() // Skip auth for this route
  @Get("health")
  getHealth() {
    return { status: "ok" };
  }
}

@Module({
  controllers: [ApiController],
  providers: [
    {
      provide: APP_GUARD,
      useFactory: () =>
        new CloudflareAccessGuard({
          accessConfig: {
            teamDomain: "https://yourteam.cloudflareaccess.com",
            audTag: "your-audience-tag",
          },
        }),
    },
  ],
})
export class AppModule {}
```

### 🎭 Effect-TS

```typescript
import { Effect, pipe } from "effect";
import { authenticateRequest } from "cloudflare-access/effect";
import { HttpServerRequest } from "@effect/platform";

const program = pipe(
  authenticateRequest(request, {
    accessConfig: {
      teamDomain: "https://yourteam.cloudflareaccess.com",
      audTag: "your-audience-tag",
    },
  }),
  Effect.tap((user) => Effect.log(`Authenticated: ${user.email}`)),
  Effect.catchAll((error) => Effect.logError(`Auth failed: ${error.message}`)),
);

Effect.runPromise(program);
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# Required
CF_ACCESS_TEAM_DOMAIN=https://yourteam.cloudflareaccess.com
CF_ACCESS_AUD=your-audience-tag-from-cloudflare

# Optional
ENVIRONMENT=development  # Skips JWT validation on localhost
```

### Cloudflare Workers (wrangler.toml)

```toml
[vars]
CF_ACCESS_TEAM_DOMAIN = "https://yourteam.cloudflareaccess.com"
CF_ACCESS_AUD = "your-audience-tag"
```

Or use secrets for the audience tag:

```bash
wrangler secret put CF_ACCESS_AUD
```

### Options Reference

```typescript
interface CloudflareAccessAuthOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;

  /** Restrict access to specific emails */
  allowedEmails?: string[];

  /** Skip auth for these paths */
  excludePaths?: string[];

  /** Skip JWT validation in development */
  skipInDev?: boolean;

  /** Custom error handlers */
  onUnauthorized?: (reason: string) => Response | void;
  onForbidden?: (email: string) => Response | void;
}
```

---

## 🎨 User Data

After authentication, user information is attached to requests:

```typescript
interface CloudflareAccessUser {
  email: string; // User's email (e.g., "user@example.com")
  userId?: string; // Unique identifier
  country?: string; // Country code (e.g., "US")
}
```

---

## 🚨 Error Handling

Rich, actionable errors with context:

```typescript
import {
  isAuthRequiredError,
  isInvalidTokenError,
  isAccessDeniedError,
} from "cloudflare-access/core";

try {
  await validateCloudflareAccessToken(token, options, url);
} catch (error) {
  if (isAuthRequiredError(error)) {
    // { message: "Authentication required", context: { fix: "Sign in via Cloudflare Access" } }
    return new Response(error.message, { status: 401 });
  }

  if (isAccessDeniedError(error)) {
    // { message: "Access denied", email: "user@example.com" }
    return new Response(`Access denied for ${error.email}`, { status: 403 });
  }
}
```

### Error Codes

| Code                  | Description                                      |
| --------------------- | ------------------------------------------------ |
| `AUTH_REQUIRED`       | Missing authentication token                     |
| `INVALID_TOKEN`       | Token validation failed (expired, bad signature) |
| `ACCESS_DENIED`       | Email not in allowlist                           |
| `CONFIGURATION_ERROR` | Missing or invalid configuration                 |

---

## 📚 Package Structure

```typescript
// Core JWT validation
import { validateCloudflareAccessToken } from "cloudflare-access/core";

// Framework adapters
import { createCloudflareAccessAuth } from "cloudflare-access/hono";
import { cloudflareAccessAuth } from "cloudflare-access/express";
import { cloudflareAccessPlugin } from "cloudflare-access/fastify";
import { CloudflareAccessGuard } from "cloudflare-access/nestjs";
import { authenticateRequest } from "cloudflare-access/effect";
```

---

## 🔧 Advanced Usage

### Email Allowlist

```typescript
app.use(
  createCloudflareAccessAuth({
    accessConfig: { teamDomain, audTag },
    allowedEmails: ["admin@company.com", "dev@company.com"],
    onForbidden: (email) => {
      return new Response(`Access denied for ${email}`, { status: 403 });
    },
  }),
);
```

### Skip Specific Paths

```typescript
app.use(
  createCloudflareAccessAuth({
    accessConfig: { teamDomain, audTag },
    excludePaths: ["/health", "/api/public"],
  }),
);
```

### Development Mode

```typescript
app.use(
  createCloudflareAccessAuth({
    accessConfig: { teamDomain, audTag },
    skipInDev: true, // Skip JWT validation on localhost
    environment: process.env.ENVIRONMENT,
  }),
);
```

---

## 📖 Examples

Check out the `/examples` directory for complete working examples:

- `examples/hono/` - Cloudflare Workers, Bun, Node.js
- `examples/express/` - Traditional Express server
- `examples/fastify/` - Fastify with plugins
- `examples/nestjs/` - NestJS with guards
- `examples/effect/` - Functional Effect-TS patterns

---

## 🧪 Testing

```bash
# Run all tests
bun test

# With coverage
bun test --coverage
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

MIT © [jbt95](https://github.com/jbt95)

---

<div align="center">

**[📦 npm](https://www.npmjs.com/package/cloudflare-access) · [🐙 GitHub](https://github.com/jbt95/cloudflare-access)**

Built with ❤️ for the Cloudflare ecosystem

</div>
