import type { FastifyReply } from "fastify";

/**
 * Generate unauthorized response
 */
export function unauthorizedResponse(reply: FastifyReply, reason: string): void {
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
export function authRequiredResponse(reply: FastifyReply): void {
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
export function forbiddenResponse(reply: FastifyReply): void {
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
