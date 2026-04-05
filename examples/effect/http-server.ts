import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "@effect/platform";
import { NodeHttpServer, NodeRuntime } from "@effect/platform-node";
import { Effect, Layer, Schema } from "effect";
import { createServer } from "node:http";
import {
  CloudflareAccessAuth,
  makeCloudflareAccessLive,
  CurrentUser,
  Unauthorized,
  Forbidden,
} from "cloudflare-access/effect";

// ============================================================================
// 1. SCHEMAS
// ============================================================================

/**
 * Schema for authenticated user
 */
const User = Schema.Struct({
  email: Schema.String,
  userId: Schema.optional(Schema.String),
  country: Schema.optional(Schema.String),
});

/**
 * Schema for user profile response
 */
const UserProfile = Schema.Struct({
  email: Schema.String,
  userId: Schema.optional(Schema.String),
  country: Schema.optional(Schema.String),
  preferences: Schema.Struct({
    theme: Schema.String,
    notifications: Schema.Boolean,
  }),
  lastLogin: Schema.String,
});

/**
 * Schema for admin dashboard response
 */
const AdminStats = Schema.Struct({
  totalUsers: Schema.Number,
  activeSessions: Schema.Number,
  apiRequests: Schema.Number,
  recentActivity: Schema.Array(Schema.String),
});

// ============================================================================
// 2. API DEFINITION
// ============================================================================

/**
 * Users API Group - Protected endpoints
 */
const UsersGroup = HttpApiGroup.make("users")
  .add(
    HttpApiEndpoint.get("getProfile", "/users/me")
      .addSuccess(UserProfile)
      .addError(Unauthorized, { status: 401 })
      .addError(Forbidden, { status: 403 }),
  )
  .middleware(CloudflareAccessAuth);

/**
 * Admin API Group - Admin-only endpoints
 */
const AdminGroup = HttpApiGroup.make("admin")
  .add(
    HttpApiEndpoint.get("getStats", "/admin/stats")
      .addSuccess(AdminStats)
      .addError(Unauthorized, { status: 401 })
      .addError(Forbidden, { status: 403 }),
  )
  .add(
    HttpApiEndpoint.get("getUsers", "/admin/users")
      .addSuccess(Schema.Array(User))
      .addError(Unauthorized, { status: 401 })
      .addError(Forbidden, { status: 403 }),
  )
  .middleware(CloudflareAccessAuth);

/**
 * Public API Group - No authentication required
 */
const PublicGroup = HttpApiGroup.make("public").add(
  HttpApiEndpoint.get("health", "/health").addSuccess(Schema.Struct({ status: Schema.String })),
);

/**
 * Main API definition
 */
const Api = HttpApi.make("CloudflareAccessApi").add(PublicGroup).add(UsersGroup).add(AdminGroup);

// ============================================================================
// 3. IMPLEMENTATION
// ============================================================================

/**
 * Authentication layer - provides the middleware implementation
 */
const CloudflareAccessLive = makeCloudflareAccessLive({
  accessConfig: {
    teamDomain: "https://yourteam.cloudflareaccess.com",
    audTag: "your-audience-tag",
  },
  allowedEmails: ["admin@example.com", "user@example.com"],
  skipInDev: true,
  environment: "dev",
});

/**
 * Implement the Users group
 */
const UsersLive = HttpApiBuilder.group(Api, "users", (handlers) =>
  handlers.handle("getProfile", () =>
    Effect.gen(function* () {
      const user = yield* CurrentUser;
      return {
        email: user.email,
        userId: user.userId,
        country: user.country,
        preferences: {
          theme: "dark",
          notifications: true,
        },
        lastLogin: new Date().toISOString(),
      };
    }),
  ),
).pipe(Layer.provide(CloudflareAccessLive));

/**
 * Implement the Admin group with admin-only access
 */
const AdminLive = HttpApiBuilder.group(Api, "admin", (handlers) =>
  handlers
    .handle("getStats", () =>
      Effect.gen(function* () {
        const user = yield* CurrentUser;
        const allowedAdmins = ["admin@example.com"];

        if (!allowedAdmins.includes(user.email)) {
          return yield* Effect.fail(
            new Forbidden({
              message: "Admin access required",
              email: user.email,
            }),
          );
        }

        return {
          totalUsers: 1500,
          activeSessions: 342,
          apiRequests: 125000,
          recentActivity: ["User login", "Config update"],
        };
      }),
    )
    .handle("getUsers", () =>
      Effect.gen(function* () {
        const user = yield* CurrentUser;
        const allowedAdmins = ["admin@example.com"];

        if (!allowedAdmins.includes(user.email)) {
          return yield* Effect.fail(
            new Forbidden({
              message: "Admin access required",
              email: user.email,
            }),
          );
        }

        return [
          { email: "user1@example.com", userId: "1" },
          { email: "user2@example.com", userId: "2" },
        ];
      }),
    ),
).pipe(Layer.provide(CloudflareAccessLive));

/**
 * Implement the Public group (no auth required)
 */
const PublicLive = HttpApiBuilder.group(Api, "public", (handlers) =>
  handlers.handle("health", () => Effect.succeed({ status: "healthy" })),
);

// ============================================================================
// 4. SERVER SETUP
// ============================================================================

const ApiLive = HttpApiBuilder.api(Api).pipe(
  Layer.provide(UsersLive),
  Layer.provide(AdminLive),
  Layer.provide(PublicLive),
);

HttpApiBuilder.serve().pipe(
  Layer.provide(ApiLive),
  Layer.provide(NodeHttpServer.layer(createServer, { port: 3000 })),
  Layer.launch,
  NodeRuntime.runMain,
);
