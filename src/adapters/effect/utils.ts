import { Effect, Option } from "effect";
import { HttpServerRequest } from "@effect/platform";
import {
  validateCloudflareAccessToken,
  CloudflareAccessError,
  CloudflareAccessErrorCode,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  isCloudflareAccessError,
  type CloudflareAccessUser,
} from "../../core/index";
import type { CloudflareAccessMiddlewareOptions } from "./types";

/**
 * Extract Cloudflare Access token from request headers.
 * Looks for CF-Access-JWT-Assertion header.
 *
 * @param request HTTP server request
 * @returns Option with token if present
 */
export const extractToken = (
  request: HttpServerRequest.HttpServerRequest,
): Option.Option<string> => {
  const token = request.headers["cf-access-jwt-assertion"];
  return Option.fromNullable(token);
};

/**
 * Authenticate using the CF-Access-JWT-Assertion header directly.
 * This bypasses the HttpApiSecurity bearer token pattern.
 *
 * @param request HTTP server request
 * @param options Authentication options
 * @returns Effect with authenticated user or error
 */
export const authenticateRequest = (
  request: HttpServerRequest.HttpServerRequest,
  options: CloudflareAccessMiddlewareOptions,
): Effect.Effect<CloudflareAccessUser, CloudflareAccessError, never> => {
  return Effect.gen(function* () {
    const token = extractToken(request);

    const result = yield* Effect.tryPromise({
      try: async () => {
        return await validateCloudflareAccessToken(
          Option.getOrUndefined(token),
          {
            accessConfig: options.accessConfig,
            allowedEmails: options.allowedEmails,
            skipInDev: options.skipInDev,
            environment: options.environment,
          },
          request.url,
        );
      },
      catch: (error) => {
        if (isCloudflareAccessError(error)) {
          return error;
        }
        return new CloudflareAccessError(
          CloudflareAccessErrorCode.INVALID_TOKEN,
          error instanceof Error ? error.message : "Unknown error",
          { context: { requestUrl: request.url } },
        );
      },
    });

    // Handle case where catch block returned a CloudflareAccessError directly
    if (result instanceof CloudflareAccessError) {
      return yield* Effect.fail(result);
    }

    if (!result.success) {
      const errorCode = result.error?.code ?? CloudflareAccessErrorCode.INVALID_TOKEN;
      const errorMessage = result.error?.message ?? "Authentication failed";

      switch (errorCode) {
        case CloudflareAccessErrorCode.AUTH_REQUIRED:
          return yield* Effect.fail(
            new AuthRequiredError({
              context: { requestUrl: request.url, ...result.error.context },
            }),
          );
        case CloudflareAccessErrorCode.ACCESS_DENIED:
          return yield* Effect.fail(
            new AccessDeniedError(result.user?.email ?? "unknown", {
              requestUrl: request.url,
              allowedEmails: options.allowedEmails,
            }),
          );
        case CloudflareAccessErrorCode.INVALID_TOKEN:
          return yield* Effect.fail(
            new InvalidTokenError(errorMessage, {
              requestUrl: request.url,
            }),
          );
        default:
          return yield* Effect.fail(
            new CloudflareAccessError(errorCode, errorMessage, {
              context: { requestUrl: request.url, ...result.error.context },
            }),
          );
      }
    }

    // Dev mode skip case
    if (!result.user) {
      return {
        email: "dev@example.com",
        userId: "dev-user",
        country: "dev",
      };
    }

    return result.user;
  });
};

/**
 * Get user as Option (returns None on auth failure)
 */
export const getUser = (
  request: HttpServerRequest.HttpServerRequest,
  options: CloudflareAccessMiddlewareOptions,
): Effect.Effect<Option.Option<CloudflareAccessUser>, never, never> => {
  return authenticateRequest(request, options).pipe(
    Effect.map((user) => Option.some(user)),
    Effect.catchAll(() => Effect.succeed(Option.none<CloudflareAccessUser>())),
  );
};

/**
 * Authenticate and return Either (for explicit error handling)
 */
export const authenticateEither = (
  request: HttpServerRequest.HttpServerRequest,
  options: CloudflareAccessMiddlewareOptions,
) => {
  return Effect.either(authenticateRequest(request, options));
};
