import type { Request, Response } from "express";
import type { CloudflareAccessConfig, CloudflareAccessUser } from "../../core";

declare global {
  namespace Express {
    interface Request {
      /** Authenticated user from Cloudflare Access */
      user?: CloudflareAccessUser;
    }
  }
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
