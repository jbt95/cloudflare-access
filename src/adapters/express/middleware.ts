import type { Request, Response, NextFunction } from "express";
import { validateCloudflareAccessToken } from "../../core";
import type { CloudflareAccessAuthOptions } from "./types";
import { unauthorizedResponse, authRequiredResponse, forbiddenResponse } from "./responses";

/**
 * Creates secure Cloudflare Access authentication middleware for Express.
 *
 * @param options - Configuration options
 * @returns Express middleware handler
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { cloudflareAccessAuth } from 'cloudflare-access/adapters/express';
 *
 * const app = express();
 *
 * app.use(cloudflareAccessAuth({
 *   accessConfig: {
 *     teamDomain: 'https://yourteam.cloudflareaccess.com',
 *     audTag: 'your-audience-tag',
 *   },
 * }));
 *
 * app.get('/protected', (req, res) => {
 *   res.json({ email: req.user?.email });
 * });
 * ```
 */
export function cloudflareAccessAuth(
  options: CloudflareAccessAuthOptions,
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  const allowedEmails = options.allowedEmails ?? null;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const path = req.path;
    const method = req.method;

    // Skip OPTIONS requests and excluded paths
    if (options.excludePaths?.includes(path) || method === "OPTIONS") {
      next();
      return;
    }

    const token = req.headers["cf-access-jwt-assertion"] as string | undefined;
    const protocol = req.headers["x-forwarded-proto"] || req.protocol;
    const host = req.headers.host;
    const url = `${protocol}://${host}${req.originalUrl}`;

    const result = await validateCloudflareAccessToken(
      token,
      {
        accessConfig: options.accessConfig,
        allowedEmails: allowedEmails ?? undefined,
        skipInDev: options.skipInDev,
        environment: options.environment,
      },
      url,
    );

    if (!result.success) {
      if (result.error?.code === "AUTH_REQUIRED") {
        if (options.onUnauthorized) {
          await options.onUnauthorized(req, res, result.error.why);
        } else {
          authRequiredResponse(res);
        }
        return;
      }

      if (result.error?.code === "ACCESS_DENIED") {
        const email = result.user?.email ?? "unknown";
        if (options.onForbidden) {
          await options.onForbidden(req, res, email);
        } else {
          forbiddenResponse(res);
        }
        return;
      }

      if (options.onUnauthorized) {
        await options.onUnauthorized(req, res, result.error?.why ?? "Unknown error");
      } else {
        unauthorizedResponse(res, result.error?.why ?? "Unknown error");
      }
      return;
    }

    // Set user in request
    if (result.user) {
      req.user = result.user;
    }

    next();
  };
}

// Also export as default for convenience
export default cloudflareAccessAuth;
