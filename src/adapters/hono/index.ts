import type { Context, MiddlewareHandler } from "hono";
import {
  type CloudflareAccessConfig,
  type CloudflareAccessMiddlewareEnv,
  type CloudflareAccessUser,
  validateCloudflareAccessToken,
  getCloudflareAccessConfigFromEnv,
  __clearJwksCache,
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
 * Extended Hono variables type
 */
export interface CloudflareAccessVariables {
  /** Authenticated user from Cloudflare Access */
  user?: CloudflareAccessUser;
}

/**
 * Helper type to create a typed Hono app with Cloudflare Access variables
 */
export type CloudflareAccessHono = import("hono").Hono<{
  Variables: CloudflareAccessVariables;
}>;

/**
 * Configuration resolver type - can be static config or a function
 */
export type CloudflareAccessConfigResolver =
  | CloudflareAccessConfig
  | ((c: Context) => CloudflareAccessConfig);

/**
 * Get Cloudflare Access configuration from Hono context bindings
 */
export function getCloudflareAccessConfigFromBindings(
  c: Context<{ Bindings: CloudflareAccessMiddlewareEnv }>,
): CloudflareAccessConfig {
  return getCloudflareAccessConfigFromEnv(c.env ?? {});
}

/**
 * Options for creating Cloudflare Access authentication middleware for Hono
 */
export interface CloudflareAccessAuthOptions {
  /**
   * Exact Cloudflare Access config or a resolver that reads it from bindings.
   * Both `teamDomain` and `audTag` are required for secure validation.
   */
  accessConfig: CloudflareAccessConfigResolver;

  /** Optional email allowlist. Access policy should still be configured at Cloudflare. */
  allowedEmails?: string[];

  /** Custom unauthorized handler */
  onUnauthorized?: (c: Context, reason: string) => Response | Promise<Response>;

  /** Custom forbidden handler */
  onForbidden?: (c: Context, email: string) => Response | Promise<Response>;

  /** Paths to exclude from auth check */
  excludePaths?: string[];

  /** Whether to skip JWT validation outside production */
  skipInDev?: boolean;
}

/**
 * Generate unauthorized response
 */
function unauthorizedResponse(c: Context, reason: string): Response {
  return c.json(
    {
      success: false,
      error: {
        code: "INVALID_TOKEN",
        message: "Invalid authentication token",
        why: reason,
        fix: "Please sign in again via Cloudflare Access",
      },
    },
    401,
  );
}

/**
 * Generate auth required response
 */
function authRequiredResponse(c: Context): Response {
  return c.json(
    {
      success: false,
      error: {
        code: "AUTH_REQUIRED",
        message: "Unauthorized",
        why: "Authentication required via Cloudflare Access",
        fix: "Sign in via Cloudflare Access",
      },
    },
    401,
  );
}

/**
 * Generate forbidden response
 */
function forbiddenResponse(c: Context): Response {
  return c.json(
    {
      success: false,
      error: {
        code: "ACCESS_DENIED",
        message: "Forbidden",
        why: "Your email is not authorized to access this resource",
        fix: "Contact an administrator if you need access",
      },
    },
    403,
  );
}

/**
 * Get access configuration from resolver
 */
function resolveConfig(
  resolver: CloudflareAccessConfigResolver,
  c: Context,
): CloudflareAccessConfig {
  return typeof resolver === "function" ? resolver(c) : resolver;
}

/**
 * Creates secure Cloudflare Access authentication middleware for Hono.
 *
 * @param options - Configuration options
 * @returns Hono middleware handler
 *
 * @example
 * ```typescript
 * import { Hono } from 'hono';
 * import { createCloudflareAccessAuth, getCloudflareAccessConfigFromBindings } from 'cloudflare-access/adapters/hono';
 *
 * const app = new Hono();
 *
 * app.use(createCloudflareAccessAuth({
 *   accessConfig: getCloudflareAccessConfigFromBindings,
 * }));
 *
 * app.get('/protected', (c) => {
 *   const user = c.get('user');
 *   return c.json({ email: user?.email });
 * });
 * ```
 */
export function createCloudflareAccessAuth(
  options: CloudflareAccessAuthOptions,
): MiddlewareHandler {
  const allowedEmails = options.allowedEmails ?? null;

  return async (c, next) => {
    const path = c.req.path;
    const method = c.req.method;
    const env = c.env as CloudflareAccessMiddlewareEnv | undefined;

    // Skip OPTIONS requests and excluded paths
    if (options.excludePaths?.includes(path) || method === "OPTIONS") {
      return next();
    }

    const config = resolveConfig(options.accessConfig, c);
    const token = c.req.header("CF-Access-JWT-Assertion");

    const result = await validateCloudflareAccessToken(
      token,
      {
        accessConfig: config,
        allowedEmails: allowedEmails ?? undefined,
        skipInDev: options.skipInDev,
        environment: env?.ENVIRONMENT,
      },
      c.req.url,
    );

    if (!result.success) {
      if (result.error?.code === "AUTH_REQUIRED") {
        const response = options.onUnauthorized
          ? await options.onUnauthorized(c, result.error.why)
          : authRequiredResponse(c);
        return response;
      }

      if (result.error?.code === "ACCESS_DENIED") {
        const email = result.user?.email ?? "unknown";
        const response = options.onForbidden
          ? await options.onForbidden(c, email)
          : forbiddenResponse(c);
        return response;
      }

      const response = options.onUnauthorized
        ? await options.onUnauthorized(c, result.error?.why ?? "Unknown error")
        : unauthorizedResponse(c, result.error?.why ?? "Unknown error");
      return response;
    }

    // Set user in context
    if (result.user) {
      c.set("user", result.user);
    }

    return next();
  };
}
