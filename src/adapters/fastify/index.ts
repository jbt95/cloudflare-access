import type {
  FastifyRequest,
  FastifyReply,
  FastifyInstance,
  FastifyPluginAsync,
  preHandlerHookHandler,
} from "fastify";
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

declare module "fastify" {
  interface FastifyRequest {
    /** Authenticated user from Cloudflare Access */
    user?: CloudflareAccessUser;
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
 * Options for creating Cloudflare Access authentication for Fastify
 */
export interface CloudflareAccessAuthOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;

  /** Optional email allowlist. Access policy should still be configured at Cloudflare. */
  allowedEmails?: string[];

  /** Custom unauthorized handler */
  onUnauthorized?: (
    request: FastifyRequest,
    reply: FastifyReply,
    reason: string,
  ) => void | Promise<void>;

  /** Custom forbidden handler */
  onForbidden?: (
    request: FastifyRequest,
    reply: FastifyReply,
    email: string,
  ) => void | Promise<void>;

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
function unauthorizedResponse(reply: FastifyReply, reason: string): void {
  reply.code(401).send({
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
function authRequiredResponse(reply: FastifyReply): void {
  reply.code(401).send({
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
function forbiddenResponse(reply: FastifyReply): void {
  reply.code(403).send({
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
 * Creates a preHandler hook for Cloudflare Access authentication.
 *
 * @param options - Configuration options
 * @returns Fastify preHandler hook
 *
 * @example
 * ```typescript
 * import fastify from 'fastify';
 * import { cloudflareAccessPreHandler } from 'cloudflare-access/adapters/fastify';
 *
 * const app = fastify();
 *
 * app.addHook('preHandler', cloudflareAccessPreHandler({
 *   accessConfig: {
 *     teamDomain: 'https://yourteam.cloudflareaccess.com',
 *     audTag: 'your-audience-tag',
 *   },
 * }));
 *
 * app.get('/protected', async (request, reply) => {
 *   return { email: request.user?.email };
 * });
 * ```
 */
export function cloudflareAccessPreHandler(
  options: CloudflareAccessAuthOptions,
): preHandlerHookHandler {
  const allowedEmails = options.allowedEmails ?? null;

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const path = request.url;
    const method = request.method;

    // Skip OPTIONS requests and excluded paths
    if (options.excludePaths?.includes(path) || method === "OPTIONS") {
      return;
    }

    const token = request.headers["cf-access-jwt-assertion"] as string | undefined;
    const protocol = request.protocol;
    const host = request.hostname;
    const url = `${protocol}://${host}${request.url}`;

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
          await options.onUnauthorized(request, reply, result.error.why);
        } else {
          authRequiredResponse(reply);
        }
        return;
      }

      if (result.error?.code === "ACCESS_DENIED") {
        const email = result.user?.email ?? "unknown";
        if (options.onForbidden) {
          await options.onForbidden(request, reply, email);
        } else {
          forbiddenResponse(reply);
        }
        return;
      }

      if (options.onUnauthorized) {
        await options.onUnauthorized(request, reply, result.error?.why ?? "Unknown error");
      } else {
        unauthorizedResponse(reply, result.error?.why ?? "Unknown error");
      }
      return;
    }

    // Set user in request
    if (result.user) {
      request.user = result.user;
    }
  };
}

/**
 * Creates a Fastify plugin for Cloudflare Access authentication.
 *
 * @param options - Configuration options
 * @returns Fastify plugin
 *
 * @example
 * ```typescript
 * import fastify from 'fastify';
 * import { cloudflareAccessPlugin } from 'cloudflare-access/adapters/fastify';
 *
 * const app = fastify();
 *
 * app.register(cloudflareAccessPlugin, {
 *   accessConfig: {
 *     teamDomain: 'https://yourteam.cloudflareaccess.com',
 *     audTag: 'your-audience-tag',
 *   },
 * });
 *
 * app.get('/protected', async (request, reply) => {
 *   return { email: request.user?.email };
 * });
 * ```
 */
export const cloudflareAccessPlugin: FastifyPluginAsync<CloudflareAccessAuthOptions> = async (
  fastify: FastifyInstance,
  options: CloudflareAccessAuthOptions,
) => {
  fastify.addHook("preHandler", cloudflareAccessPreHandler(options));
};

// Also export as default for convenience
export default cloudflareAccessPlugin;
