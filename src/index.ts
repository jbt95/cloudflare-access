// Re-export everything from the Hono adapter for convenience
// This allows importing directly from the package root for Hono users

export {
  createCloudflareAccessAuth,
  getCloudflareAccessConfigFromBindings,
  type CloudflareAccessConfigResolver,
  type CloudflareAccessAuthOptions,
  type CloudflareAccessVariables,
  type CloudflareAccessHono,
} from "./adapters/hono";

// Export error classes and utilities from core
export {
  // Error classes
  CloudflareAccessError,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  ConfigurationError,
  // Error codes (both const and type)
  CloudflareAccessErrorCode,
  // Type guards
  isCloudflareAccessError,
  isAuthRequiredError,
  isInvalidTokenError,
  isAccessDeniedError,
  isConfigurationError,
  toAuthError,
  // Types
  type CloudflareAccessConfig,
  type CloudflareAccessUser,
  type CloudflareAccessPayload,
  type CloudflareAccessMiddlewareEnv,
  type AuthError,
  type AuthResult,
  // Functions
  getCloudflareAccessConfigFromEnv,
  validateCloudflareAccessToken,
  __clearJwksCache,
} from "./core/auth";
