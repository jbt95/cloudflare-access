import type { Response } from "express";

/**
 * Generate unauthorized response
 */
export function unauthorizedResponse(res: Response, reason: string): void {
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
export function authRequiredResponse(res: Response): void {
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
export function forbiddenResponse(res: Response): void {
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
