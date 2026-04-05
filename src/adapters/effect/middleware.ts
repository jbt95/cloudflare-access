import { Effect, Layer, Redacted, Schema } from "effect";
import { HttpApiMiddleware, HttpApiSecurity, HttpServerRequest } from "@effect/platform";
import { validateCloudflareAccessToken, CloudflareAccessErrorCode } from "../../core/index";
import type { CloudflareAccessMiddlewareOptions } from "./types";
import { Unauthorized, Forbidden } from "./errors";
import { CurrentUser } from "./context";

/**
 * Cloudflare Access authentication middleware class.
 *
 * Use this class directly in your API middleware definitions.
 *
 * @example
 * ```typescript
 * import { HttpApi, HttpApiGroup, HttpApiEndpoint } from "@effect/platform";
 * import { Schema, Effect, Layer } from "effect";
 * import {
 *   CloudflareAccessAuth,
 *   CurrentUser,
 *   makeCloudflareAccessLive,
 *   Unauthorized,
 *   Forbidden
 * } from "cloudflare-access/effect";
 *
 * // Configure the middleware
 * const CloudflareAccessLive = makeCloudflareAccessLive({
 *   accessConfig: {
 *     teamDomain: "https://yourteam.cloudflareaccess.com",
 *     audTag: "your-audience-tag",
 *   },
 *   allowedEmails: ["admin@example.com"],
 *   skipInDev: true,
 *   environment: "dev",
 * });
 *
 * // Define API with protected endpoints
 * const User = Schema.Struct({ email: Schema.String });
 *
 * const api = HttpApi.make("api").add(
 *   HttpApiGroup.make("users").add(
 *     HttpApiEndpoint.get("profile", "/profile")
 *       .addSuccess(User)
 *       .middleware(CloudflareAccessAuth)
 *   )
 * );
 *
 * // Implement handlers with access to CurrentUser
 * const UsersLive = HttpApiBuilder.group(api, "users", (handlers) =>
 *   Effect.gen(function* () {
 *     const user = yield* CurrentUser;
 *     return handlers.handle("profile", () =>
 *       Effect.succeed({ email: user.email })
 *     );
 *   })
 * ).pipe(Layer.provide(CloudflareAccessLive));
 * ```
 */
export class CloudflareAccessAuth extends HttpApiMiddleware.Tag<CloudflareAccessAuth>()(
  "CloudflareAccessAuth",
  {
    provides: CurrentUser,
    failure: Schema.Union(Unauthorized, Forbidden),
    security: {
      bearer: HttpApiSecurity.bearer,
    },
  },
) {}

/**
 * Create a Layer that implements Cloudflare Access authentication.
 *
 * This layer validates the Cloudflare Access JWT token from the request
 * and provides the authenticated user via the CurrentUser context.
 *
 * @param options Configuration for Cloudflare Access
 * @returns Layer that provides authentication
 */
export const makeCloudflareAccessLive = (options: CloudflareAccessMiddlewareOptions) => {
  return Layer.succeed(
    CloudflareAccessAuth,
    CloudflareAccessAuth.of({
      bearer: (bearerToken) =>
        Effect.gen(function* () {
          const request = yield* HttpServerRequest.HttpServerRequest;
          const token = Redacted.value(bearerToken);

          // Wrap the async validation in an Effect
          const result = yield* Effect.promise(() =>
            validateCloudflareAccessToken(
              token,
              {
                accessConfig: options.accessConfig,
                allowedEmails: options.allowedEmails,
                skipInDev: options.skipInDev,
                environment: options.environment,
              },
              request.url,
            ),
          );

          // Handle validation result
          if (!result.success) {
            const errorCode = result.error?.code ?? CloudflareAccessErrorCode.INVALID_TOKEN;
            const errorMessage = result.error?.message ?? "Authentication failed";

            if (errorCode === CloudflareAccessErrorCode.AUTH_REQUIRED) {
              return yield* Effect.fail(
                new Unauthorized({ message: errorMessage, code: "AUTH_REQUIRED" }),
              );
            }

            if (errorCode === CloudflareAccessErrorCode.ACCESS_DENIED) {
              return yield* Effect.fail(
                new Forbidden({
                  message: errorMessage,
                  email: result.user?.email ?? "unknown",
                }),
              );
            }

            return yield* Effect.fail(new Unauthorized({ message: errorMessage, code: errorCode }));
          }

          // Dev mode skip case (result.user can be null when skipped)
          if (!result.user) {
            return {
              email: "dev@example.com",
              userId: "dev-user",
              country: "dev",
            };
          }

          return result.user;
        }),
    }),
  );
};
