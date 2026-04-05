import type { CloudflareAccessConfig, CloudflareAccessMiddlewareEnv } from "../../core";
import { getCloudflareAccessConfigFromEnv as _getCloudflareAccessConfigFromEnv } from "../../core";

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
    request: import("fastify").FastifyRequest,
    reply: import("fastify").FastifyReply,
    reason: string,
  ) => void | Promise<void>;

  /** Custom forbidden handler */
  onForbidden?: (
    request: import("fastify").FastifyRequest,
    reply: import("fastify").FastifyReply,
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
 * Get Cloudflare Access configuration from environment variables
 */
export function getCloudflareAccessConfigFromEnv(
  env: CloudflareAccessMiddlewareEnv,
): CloudflareAccessConfig {
  return _getCloudflareAccessConfigFromEnv(env);
}
