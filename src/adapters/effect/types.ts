import type { CloudflareAccessConfig } from "../../core/index";

/**
 * Options for creating Cloudflare Access middleware
 */
export interface CloudflareAccessMiddlewareOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;
  /** Optional email allowlist */
  allowedEmails?: string[];
  /** Skip validation in development */
  skipInDev?: boolean;
  /** Environment identifier */
  environment?: string;
}
