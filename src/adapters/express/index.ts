/**
 * Cloudflare Access - Express Adapter
 *
 * Provides Express middleware for Cloudflare Access JWT authentication.
 */

// Re-export everything from core
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

// Export types
export type { CloudflareAccessAuthOptions } from "./types";

// Export responses
export { unauthorizedResponse, authRequiredResponse, forbiddenResponse } from "./responses";

// Export main middleware
export { cloudflareAccessAuth, default } from "./middleware";
