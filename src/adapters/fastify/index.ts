// Core exports
export {
  type CloudflareAccessConfig,
  type CloudflareAccessUser,
  type CloudflareAccessPayload,
  type CloudflareAccessMiddlewareEnv,
  // Error classes
  CloudflareAccessError,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  ConfigurationError,
  // Error codes
  CloudflareAccessErrorCode,
  // Type guards
  isCloudflareAccessError,
  isAuthRequiredError,
  isInvalidTokenError,
  isAccessDeniedError,
  isConfigurationError,
  toAuthError,
  __clearJwksCache,
} from "../../core";

// Fastify-specific exports
export type { CloudflareAccessAuthOptions } from "./types";
export { getCloudflareAccessConfigFromEnv } from "./types";
export { unauthorizedResponse, authRequiredResponse, forbiddenResponse } from "./responses";
export { cloudflareAccessPreHandler } from "./middleware";
export { cloudflareAccessPlugin, default } from "./plugin";

// Type augmentation for Fastify
declare module "fastify" {
  interface FastifyRequest {
    /** Authenticated user from Cloudflare Access */
    user?: import("../../core").CloudflareAccessUser;
  }
}
