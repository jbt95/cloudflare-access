/**
 * Cloudflare Access - Effect-TS Adapter
 *
 * Provides Effect-TS integration with HttpApiMiddleware.Tag pattern
 * for Cloudflare Access JWT authentication.
 */

// Re-export everything from core
export {
  type CloudflareAccessConfig,
  type CloudflareAccessUser,
  type CloudflareAccessPayload,
  type CloudflareAccessMiddlewareEnv,
  type AuthResult,
  CloudflareAccessError,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  ConfigurationError,
  CloudflareAccessErrorCode,
  isCloudflareAccessError,
  isAuthRequiredError,
  isInvalidTokenError,
  isAccessDeniedError,
  isConfigurationError,
  toAuthError,
  __clearJwksCache,
  getCloudflareAccessConfigFromEnv,
} from "../../core";

// Export types
export type { CloudflareAccessMiddlewareOptions } from "./types";

// Export errors
export { Unauthorized, Forbidden } from "./errors";

// Export context
export { CurrentUser } from "./context";

// Export middleware
export { CloudflareAccessAuth, makeCloudflareAccessLive } from "./middleware";

// Export utilities
export { extractToken, authenticateRequest, getUser, authenticateEither } from "./utils";
