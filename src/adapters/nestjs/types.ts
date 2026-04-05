import type { CloudflareAccessConfig, CloudflareAccessMiddlewareEnv } from "../../core";
import { getCloudflareAccessConfigFromEnv as _getCloudflareAccessConfigFromEnv } from "../../core";

/**
 * Options for Cloudflare Access Guard
 */
export interface CloudflareAccessGuardOptions {
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
 * Get Cloudflare Access configuration from environment variables
 */
export function getCloudflareAccessConfigFromEnv(
  env: CloudflareAccessMiddlewareEnv,
): CloudflareAccessConfig {
  return _getCloudflareAccessConfigFromEnv(env);
}
