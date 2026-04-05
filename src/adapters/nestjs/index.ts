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

// NestJS-specific exports
export type { CloudflareAccessGuardOptions } from "./types";
export { getCloudflareAccessConfigFromEnv } from "./types";
export { CloudflareAccessGuard } from "./guard";
export {
  IS_PUBLIC_KEY,
  Public,
  CloudflareAccess,
  type CloudflareAccessModuleAsyncOptions,
} from "./decorators";

// Type augmentation for Express (used by NestJS)
declare module "express" {
  interface Request {
    /** Authenticated user from Cloudflare Access */
    user?: import("../../core").CloudflareAccessUser;
  }
}
