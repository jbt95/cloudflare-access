import type { MiddlewareHandler } from "hono";
import { type CloudflareAccessMiddlewareEnv, validateCloudflareAccessToken } from "../../core";
import type { CloudflareAccessAuthOptions } from "./types";
import { resolveConfig } from "./config";
import { unauthorizedResponse, authRequiredResponse, forbiddenResponse } from "./responses";

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
