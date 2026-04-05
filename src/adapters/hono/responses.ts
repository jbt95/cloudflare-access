import type { Context } from "hono";

/**
 * Generate unauthorized response
 */
export function unauthorizedResponse(c: Context, reason: string): Response {
  return c.json(
    {
      success: false,
      error: {
        code: "INVALID_TOKEN",
        message: "Invalid authentication token",
        why: reason,
        fix: "Please sign in again via Cloudflare Access",
      },
    },
    401,
  );
}

/**
 * Generate auth required response
 */
export function authRequiredResponse(c: Context): Response {
  return c.json(
    {
      success: false,
      error: {
        code: "AUTH_REQUIRED",
        message: "Unauthorized",
        why: "Authentication required via Cloudflare Access",
        fix: "Sign in via Cloudflare Access",
      },
    },
    401,
  );
}

/**
 * Generate forbidden response
 */
export function forbiddenResponse(c: Context): Response {
  return c.json(
    {
      success: false,
      error: {
        code: "ACCESS_DENIED",
        message: "Forbidden",
        why: "Your email is not authorized to access this resource",
        fix: "Contact an administrator if you need access",
      },
    },
    403,
  );
}
