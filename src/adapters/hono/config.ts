import type { Context } from "hono";
import {
  type CloudflareAccessConfig,
  type CloudflareAccessMiddlewareEnv,
  getCloudflareAccessConfigFromEnv,
} from "../../core";

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
 * Get access configuration from resolver
 */
export function resolveConfig(
  resolver: CloudflareAccessConfigResolver,
  c: Context,
): CloudflareAccessConfig {
  return typeof resolver === "function" ? resolver(c) : resolver;
}
