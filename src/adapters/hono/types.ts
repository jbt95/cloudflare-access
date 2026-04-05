import type { Context } from "hono";
import type { CloudflareAccessConfig, CloudflareAccessUser } from "../../core";

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
