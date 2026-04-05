import type { Request, Response, NextFunction } from "express";
import {
  type CloudflareAccessConfig,
  type CloudflareAccessMiddlewareEnv,
  type CloudflareAccessUser,
  validateCloudflareAccessToken,
  getCloudflareAccessConfigFromEnv as _getCloudflareAccessConfigFromEnv,
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

declare global {
  namespace Express {
    interface Request {
      /** Authenticated user from Cloudflare Access */
      user?: CloudflareAccessUser;
    }
  }
}

/**
 * Get Cloudflare Access configuration from environment variables
 */
export function getCloudflareAccessConfigFromEnv(
  env: CloudflareAccessMiddlewareEnv,
): CloudflareAccessConfig {
  return _getCloudflareAccessConfigFromEnv(env);
}

/**
 * Options for creating Cloudflare Access authentication middleware for Express
 */
export interface CloudflareAccessAuthOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;

  /** Optional email allowlist. Access policy should still be configured at Cloudflare. */
  allowedEmails?: string[];

  /** Custom unauthorized handler */
  onUnauthorized?: (req: Request, res: Response, reason: string) => void | Promise<void>;

  /** Custom forbidden handler */
  onForbidden?: (req: Request, res: Response, email: string) => void | Promise<void>;

  /** Paths to exclude from auth check */
  excludePaths?: string[];

  /** Whether to skip JWT validation outside production */
  skipInDev?: boolean;

  /** Environment indicator */
  environment?: string;
}

/**
 * Generate unauthorized response
 */
function unauthorizedResponse(res: Response, reason: string): void {
  res.status(401).json({
    success: false,
    error: {
      code: "INVALID_TOKEN",
      message: "Invalid authentication token",
      why: reason,
      fix: "Please sign in again via Cloudflare Access",
    },
  });
}

/**
 * Generate auth required response
 */
function authRequiredResponse(res: Response): void {
  res.status(401).json({
    success: false,
    error: {
      code: "AUTH_REQUIRED",
      message: "Unauthorized",
      why: "Authentication required via Cloudflare Access",
      fix: "Sign in via Cloudflare Access",
    },
  });
}

/**
 * Generate forbidden response
 */
function forbiddenResponse(res: Response): void {
  res.status(403).json({
    success: false,
    error: {
      code: "ACCESS_DENIED",
      message: "Forbidden",
      why: "Your email is not authorized to access this resource",
      fix: "Contact an administrator if you need access",
    },
  });
}

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
