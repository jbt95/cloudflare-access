/**
 * Cloudflare Access - Hono Adapter
 *
 * Provides Hono middleware for Cloudflare Access JWT authentication.
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
export type {
  CloudflareAccessVariables,
  CloudflareAccessHono,
  CloudflareAccessConfigResolver,
  CloudflareAccessAuthOptions,
} from "./types";

// Export config utilities
export { getCloudflareAccessConfigFromBindings, resolveConfig } from "./config";

// Export responses
export { unauthorizedResponse, authRequiredResponse, forbiddenResponse } from "./responses";

// Export main middleware
export { createCloudflareAccessAuth } from "./middleware";
