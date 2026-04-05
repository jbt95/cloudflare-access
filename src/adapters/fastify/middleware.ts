import type { FastifyRequest, FastifyReply, FastifyInstance, preHandlerHookHandler } from "fastify";
import { validateCloudflareAccessToken } from "../../core";
import type { CloudflareAccessAuthOptions } from "./types";
import { unauthorizedResponse, authRequiredResponse, forbiddenResponse } from "./responses";

declare module "fastify" {
  interface FastifyRequest {
    /** Authenticated user from Cloudflare Access */
    user?: import("../../core").CloudflareAccessUser;
  }
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
export async function cloudflareAccessPlugin(
  fastify: FastifyInstance,
  options: CloudflareAccessAuthOptions,
): Promise<void> {
  fastify.addHook("preHandler", cloudflareAccessPreHandler(options));
}
