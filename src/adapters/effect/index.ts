import { Effect, Either, Option, pipe } from "effect";
import {
  type CloudflareAccessConfig,
  type CloudflareAccessMiddlewareEnv,
  type CloudflareAccessUser,
  validateCloudflareAccessToken,
  getCloudflareAccessConfigFromEnv as _getCloudflareAccessConfigFromEnv,
  __clearJwksCache,
  type AuthResult,
  // Error classes and utilities
  CloudflareAccessError,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  ConfigurationError,
  CloudflareAccessErrorCode,
  isCloudflareAccessError,
  isAuthRequiredError,
  isInvalidTokenError,
  isAccessDeniedError,
  isConfigurationError,
  toAuthError,
} from "../../core/auth";

export {
  type CloudflareAccessConfig,
  type CloudflareAccessUser,
  type CloudflareAccessPayload,
  type CloudflareAccessMiddlewareEnv,
  // Error classes
  CloudflareAccessError,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  ConfigurationError,
  // Error codes
  CloudflareAccessErrorCode,
  // Type guards
  isCloudflareAccessError,
  isAuthRequiredError,
  isInvalidTokenError,
  isAccessDeniedError,
  isConfigurationError,
  toAuthError,
  __clearJwksCache,
} from "../../core/auth";

/**
 * Get Cloudflare Access configuration from environment variables
 */
export function getCloudflareAccessConfigFromEnv(
  env: CloudflareAccessMiddlewareEnv,
): CloudflareAccessConfig {
  return _getCloudflareAccessConfigFromEnv(env);
}

/**
 * Options for Cloudflare Access authentication in Effect
 */
export interface CloudflareAccessAuthOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;

  /** Optional email allowlist. Access policy should still be configured at Cloudflare. */
  allowedEmails?: string[];

  /** Whether to skip JWT validation outside production */
  skipInDev?: boolean;

  /** Environment indicator */
  environment?: string;
}

/**
 * Context for authentication (input data)
 */
export interface CloudflareAccessContext {
  readonly token: Option.Option<string>;
  readonly requestUrl: string;
}

/**
 * Successful authentication result (may be partial in dev mode)
 */
export interface AuthenticationSuccess {
  readonly user?: CloudflareAccessUser;
  readonly skipped?: boolean;
}

/**
 * Convert a CloudflareAccessError to an Effect failure
 */
function errorToEffectFailure(error: unknown): Effect.Effect<never, CloudflareAccessError, never> {
  if (isCloudflareAccessError(error)) {
    return Effect.fail(error);
  }

  if (error instanceof Error) {
    return Effect.fail(
      new CloudflareAccessError(
        CloudflareAccessErrorCode.INVALID_TOKEN,
        error.message,
        { cause: error },
      ),
    );
  }

  return Effect.fail(
    new CloudflareAccessError(
      CloudflareAccessErrorCode.INVALID_TOKEN,
      "Unknown authentication error",
    ),
  );
}

/**
 * Authenticate a request using Cloudflare Access.
 * Returns an Effect that can fail with CloudflareAccessError or succeed with AuthenticationSuccess.
 *
 * @example
 * ```typescript
 * import { Effect } from 'effect';
 * import { authenticate, CloudflareAccessContext, isAuthRequiredError } from 'cloudflare-access/effect';
 *
 * const program = Effect.gen(function* () {
 *   const context: CloudflareAccessContext = {
 *     token: Option.some(token),
 *     requestUrl: 'https://example.com/api',
 *   };
 *
 *   const result = yield* authenticate(context, {
 *     accessConfig: {
 *       teamDomain: 'https://yourteam.cloudflareaccess.com',
 *       audTag: 'your-audience-tag',
 *     },
 *   }).pipe(
 *     Effect.catchTag("CloudflareAccessError", (error) => {
 *       if (isAuthRequiredError(error)) {
 *         console.log("Auth required:", error.message);
 *       }
 *       return Effect.fail(error);
 *     })
 *   );
 *
 *   if (result.user) {
 *     console.log('Authenticated user:', result.user.email);
 *   }
 *   return result;
 * });
 * ```
 */
export const authenticate = (
  context: CloudflareAccessContext,
  options: CloudflareAccessAuthOptions,
): Effect.Effect<AuthenticationSuccess, CloudflareAccessError, never> => {
  return Effect.tryPromise({
    try: async () => {
      const token = Option.getOrUndefined(context.token);

      const result = await validateCloudflareAccessToken(token, {
        accessConfig: options.accessConfig,
        allowedEmails: options.allowedEmails,
        skipInDev: options.skipInDev,
        environment: options.environment,
      }, context.requestUrl);

      if (!result.success) {
        // Convert AuthResult error to rich error
        const errorCode = result.error?.code ?? CloudflareAccessErrorCode.INVALID_TOKEN;
        const errorMessage = result.error?.message ?? "Authentication failed";
        const errorContext = result.error?.context;

        switch (errorCode) {
          case CloudflareAccessErrorCode.AUTH_REQUIRED:
            throw new AuthRequiredError({
              requestUrl: context.requestUrl,
              context: errorContext,
            });
          case CloudflareAccessErrorCode.ACCESS_DENIED:
            throw new AccessDeniedError(
              result.user?.email ?? "unknown",
              {
                requestUrl: context.requestUrl,
                allowedEmails: options.allowedEmails,
              },
            );
          case CloudflareAccessErrorCode.INVALID_TOKEN:
            throw new InvalidTokenError(errorMessage, {
              requestUrl: context.requestUrl,
            });
          default:
            throw new CloudflareAccessError(errorCode, errorMessage, {
              requestUrl: context.requestUrl,
              context: errorContext,
            });
        }
      }

      // Handle dev mode skip (success but no user)
      if (!result.user) {
        return { skipped: true };
      }

      return { user: result.user };
    },
    catch: (error) => {
      if (isCloudflareAccessError(error)) {
        return error;
      }

      if (error instanceof Error) {
        return new CloudflareAccessError(
          CloudflareAccessErrorCode.INVALID_TOKEN,
          error.message,
          { cause: error },
        );
      }

      return new CloudflareAccessError(
        CloudflareAccessErrorCode.INVALID_TOKEN,
        "Unknown authentication error",
      );
    },
  });
};

/**
 * Authenticate and return Either (for when you want to handle errors as values).
 *
 * @example
 * ```typescript
 * import { Effect, Either, isAccessDeniedError } from 'effect';
 * import { authenticateEither } from 'cloudflare-access/effect';
 *
 * const result = await Effect.runPromise(authenticateEither(context, options));
 *
 * if (Either.isRight(result)) {
 *   console.log('User:', result.right.user?.email);
 * } else {
 *   const error = result.left;
 *   if (isAccessDeniedError(error)) {
 *     console.log('Access denied for:', error.email);
 *   }
 * }
 * ```
 */
export const authenticateEither = (
  context: CloudflareAccessContext,
  options: CloudflareAccessAuthOptions,
): Effect.Effect<Either.Either<AuthenticationSuccess, CloudflareAccessError>, never, never> => {
  return Effect.either(authenticate(context, options));
};

/**
 * Middleware function that validates Cloudflare Access token and returns user or null.
 * This is a more traditional approach for Effect users.
 *
 * @example
 * ```typescript
 * import { Effect, Option } from 'effect';
 * import { getUser, CloudflareAccessContext } from 'cloudflare-access/effect';
 *
 * const context: CloudflareAccessContext = {
 *   token: Option.some(token),
 *   requestUrl: 'https://example.com/api',
 * };
 *
 * const program = Effect.gen(function* () {
 *   const user = yield* getUser(context, options);
 *
 *   if (Option.isSome(user)) {
 *     console.log('User:', user.value.email);
 *   } else {
 *     console.log('Not authenticated');
 *   }
 * });
 * ```
 */
export const getUser = (
  context: CloudflareAccessContext,
  options: CloudflareAccessAuthOptions,
): Effect.Effect<Option.Option<CloudflareAccessUser>, never, never> => {
  return pipe(
    authenticate(context, options),
    Effect.map((success: AuthenticationSuccess) =>
      success.user ? Option.some(success.user) : Option.none<CloudflareAccessUser>()
    ),
    Effect.catchAll(() => Effect.succeed(Option.none<CloudflareAccessUser>())),
  );
};

/**
 * Layer for providing Cloudflare Access authentication as a service.
 * This is useful for dependency injection patterns in Effect.
 */
export const CloudflareAccessLive = (options: CloudflareAccessAuthOptions) => ({
  authenticate: (context: CloudflareAccessContext) => authenticate(context, options),
  getUser: (context: CloudflareAccessContext) => getUser(context, options),
});

/**
 * Type for the Cloudflare Access service
 */
export type CloudflareAccessService = ReturnType<typeof CloudflareAccessLive>;

// Also export as default for convenience
export default authenticate;
