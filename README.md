# cloudflare-access

Multi-framework authentication for Cloudflare Access with JWT validation.

Supports: **Hono**, **Express**, **Fastify**, **NestJS**, and **Effect-TS**.

## Installation

```bash
# npm
npm install cloudflare-access

# yarn
yarn add cloudflare-access

# bun
bun add cloudflare-access
```

## Framework-Specific Installation

### Hono

```bash
bun add cloudflare-access hono
```

### Express

```bash
bun add cloudflare-access express
```

### Fastify

```bash
bun add cloudflare-access fastify
```

### NestJS

```bash
bun add cloudflare-access @nestjs/common @nestjs/core
```

### Effect-TS

```bash
bun add cloudflare-access effect
```

## Quick Start

### Hono

```typescript
import { Hono } from "hono";
import { createCloudflareAccessAuth } from "cloudflare-access/hono";

const app = new Hono();

// Using static configuration (works with any deployment target)
app.use(
  createCloudflareAccessAuth({
    accessConfig: {
      teamDomain: process.env.CF_ACCESS_TEAM_DOMAIN!,
      audTag: process.env.CF_ACCESS_AUD!,
    },
  }),
);

// Or with Cloudflare Workers bindings
// import { getCloudflareAccessConfigFromBindings } from "cloudflare-access/hono";
// app.use(createCloudflareAccessAuth({
//   accessConfig: getCloudflareAccessConfigFromBindings,
// }));

app.get("/protected", (c) => {
  const user = c.get("user");
  return c.json({ email: user?.email });
});
```

### Express

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

app.get("/protected", (req, res) => {
  res.json({ email: req.user?.email });
});
```

### Fastify

```typescript
import fastify from "fastify";
import { cloudflareAccessPlugin } from "cloudflare-access/fastify";

const app = fastify();

app.register(cloudflareAccessPlugin, {
  accessConfig: {
    teamDomain: "https://yourteam.cloudflareaccess.com",
    audTag: "your-audience-tag",
  },
});

app.get("/protected", async (request, reply) => {
  return { email: request.user?.email };
});
```

### NestJS

```typescript
import { Controller, Get, Req, Module } from "@nestjs/common";
import { CloudflareAccessGuard, Public } from "cloudflare-access/nestjs";
import { APP_GUARD } from "@nestjs/core";
import type { Request } from "express";

@Controller("api")
export class ApiController {
  @Get("protected")
  getProtected(@Req() req: Request) {
    return { email: req.user?.email };
  }

  @Public()
  @Get("public")
  getPublic() {
    return { message: "This is public" };
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

### Effect-TS

```typescript
import { Effect, Either } from "effect";
import { HttpServerRequest } from "@effect/platform";
import { authenticateRequest } from "cloudflare-access/effect";

const request: HttpServerRequest.HttpServerRequest = {
  url: "https://example.com/api/protected",
  headers: {
    "cf-access-jwt-assertion": "jwt-token-here",
  },
  method: "GET",
};

const program = Effect.gen(function* () {
  const result = yield* Effect.either(
    authenticateRequest(request, {
      accessConfig: {
        teamDomain: "https://yourteam.cloudflareaccess.com",
        audTag: "your-audience-tag",
      },
    }),
  );

  return Either.match(result, {
    onLeft: (error) => {
      console.error(`Auth failed: ${error.message}`);
      return null;
    },
    onRight: (user) => {
      console.log(`Authenticated user: ${user.email}`);
      return user;
    },
  });
});

Effect.runPromise(program);
```

## Configuration

### Environment Variables

Configure your Cloudflare Access credentials via environment variables:

```bash
# .env
CF_ACCESS_TEAM_DOMAIN=https://yourteam.cloudflareaccess.com
CF_ACCESS_AUD=your-audience-tag
ENVIRONMENT=dev
```

Or set them directly in your environment:

```bash
export CF_ACCESS_TEAM_DOMAIN="https://yourteam.cloudflareaccess.com"
export CF_ACCESS_AUD="your-audience-tag"
```

For **Cloudflare Workers**, use `wrangler.toml`:

```toml
[vars]
CF_ACCESS_TEAM_DOMAIN = "https://yourteam.cloudflareaccess.com"
CF_ACCESS_AUD = "your-audience-tag"
```

Or with Wrangler secrets:

```bash
wrangler secret put CF_ACCESS_AUD
```

### Common Options

All framework adapters support these options:

```typescript
interface CloudflareAccessAuthOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;

  /** Optional email allowlist */
  allowedEmails?: string[];

  /** Custom unauthorized handler */
  onUnauthorized?: (reason: string) => Response | void | Promise<void>;

  /** Custom forbidden handler */
  onForbidden?: (email: string) => Response | void | Promise<void>;

  /** Paths to exclude from authentication */
  excludePaths?: string[];

  /** Skip JWT validation in development (localhost requests) */
  skipInDev?: boolean;

  /** Environment indicator */
  environment?: string;
}
```

## User Information

After successful authentication, user information is available:

```typescript
interface CloudflareAccessUser {
  email: string;
  userId?: string;
  country?: string;
}
```

## Rich Error Handling

The library provides rich, actionable errors with detailed context:

### Error Classes

```typescript
import {
  CloudflareAccessError,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  ConfigurationError,
  // Type guards
  isAuthRequiredError,
  isInvalidTokenError,
  isAccessDeniedError,
} from "cloudflare-access/core";

// All errors extend CloudflareAccessError
try {
  await validateCloudflareAccessToken(token, options, url);
} catch (error) {
  if (isAuthRequiredError(error)) {
    console.log("Auth required:", error.message);
    console.log("Fix:", error.context?.fix);
  }

  if (isInvalidTokenError(error)) {
    console.log("Invalid token:", error.reason);
    console.log("Token info:", error.context?.tokenInfo);
  }

  if (isAccessDeniedError(error)) {
    console.log("Access denied for:", error.email);
  }

  // All errors are serializable
  console.log("Full error:", error.toJSON());
}
```

### Error Codes

```typescript
import { CloudflareAccessErrorCode } from "cloudflare-access/core";

// Available error codes:
// - AUTH_REQUIRED: Missing or invalid authentication token
// - INVALID_TOKEN: Token validation failed (expired, wrong signature, etc.)
// - ACCESS_DENIED: User email not in allowlist
// - INVALID_TEAM_DOMAIN: Invalid team domain configuration
// - MISSING_AUDIENCE_TAG: Missing audience tag
// - MISSING_CONFIG: Missing environment configuration
```

### Effect-TS Error Handling

```typescript
import { Effect, Either } from "effect";
import {
  authenticateRequest,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
} from "cloudflare-access/effect";
import { HttpServerRequest } from "@effect/platform";

const request: HttpServerRequest.HttpServerRequest = {
  url: "https://example.com/api/protected",
  headers: { "cf-access-jwt-assertion": "token" },
  method: "GET",
};

const program = Effect.gen(function* () {
  const result = yield* Effect.either(
    authenticateRequest(request, {
      accessConfig: {
        teamDomain: "https://yourteam.cloudflareaccess.com",
        audTag: "your-audience-tag",
      },
    }),
  );

  return Either.match(result, {
    onLeft: (error) => {
      if (error instanceof AuthRequiredError) {
        console.log("Auth required:", error.message);
        return null;
      }
      if (error instanceof AccessDeniedError) {
        console.log("Access denied for:", error.email);
        return null;
      }
      throw error;
    },
    onRight: (user) => user,
  });
});
```

## Using the Core Module Directly

If you need lower-level access to the authentication logic:

```typescript
import {
  validateCloudflareAccessToken,
  getCloudflareAccessConfigFromEnv,
  type CloudflareAccessConfig,
} from "cloudflare-access/core";

const result = await validateCloudflareAccessToken(
  token,
  { accessConfig: { teamDomain, audTag } },
  requestUrl,
);

if (result.success) {
  console.log("User:", result.user);
} else {
  console.log("Auth failed:", result.error);
}
```

## Package Imports

The package uses subpath exports for each framework:

```typescript
// Core authentication logic
import { validateCloudflareAccessToken } from "cloudflare-access/core";

// Framework adapters
import { createCloudflareAccessAuth } from "cloudflare-access/hono";
import { cloudflareAccessAuth } from "cloudflare-access/express";
import { cloudflareAccessPlugin } from "cloudflare-access/fastify";
import { CloudflareAccessGuard } from "cloudflare-access/nestjs";
import { authenticateRequest } from "cloudflare-access/effect";

// Hono exports (from root)
import {
  createCloudflareAccessAuth,
  getCloudflareAccessConfigFromBindings,
} from "cloudflare-access";
```

## Examples

See the `/examples` directory for detailed examples:

- `examples/hono/` - Hono framework examples
- `examples/express/` - Express framework examples
- `examples/fastify/` - Fastify framework examples
- `examples/nestjs/` - NestJS framework examples
- `examples/effect/` - Effect-TS framework examples

## Testing

The library includes comprehensive test coverage for all adapters:

```bash
# Run all tests
bun test

# Run with coverage
bun test --coverage
```

## License

MIT
