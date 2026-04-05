import { CloudflareAccessErrorCode } from "./types";

/**
 * Base error class for Cloudflare Access authentication errors
 */
export class CloudflareAccessError extends Error {
  readonly code: CloudflareAccessErrorCode;
  readonly context?: Record<string, unknown>;
  readonly requestUrl?: string;
  readonly timestamp: string;

  constructor(
    code: CloudflareAccessErrorCode,
    message: string,
    options?: {
      cause?: Error;
      context?: Record<string, unknown>;
      requestUrl?: string;
    },
  ) {
    super(message, { cause: options?.cause });
    this.name = "CloudflareAccessError";
    this.code = code;
    this.context = options?.context;
    this.requestUrl = options?.requestUrl;
    this.timestamp = new Date().toISOString();
  }

  /**
   * Get a user-friendly error message with fix instructions
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      timestamp: this.timestamp,
      context: this.context,
      fix: this.getFixInstructions(),
    };
  }

  /**
   * Get fix instructions based on error code
   */
  private getFixInstructions(): string {
    switch (this.code) {
      case CloudflareAccessErrorCode.AUTH_REQUIRED:
        return "Ensure you're accessing through Cloudflare Access or provide a valid CF-Access-JWT-Assertion token";
      case CloudflareAccessErrorCode.INVALID_TOKEN:
        return "Your session may have expired. Please re-authenticate through Cloudflare Access";
      case CloudflareAccessErrorCode.ACCESS_DENIED:
        return "Contact your administrator to request access";
      case CloudflareAccessErrorCode.MISSING_CONFIG:
        return "Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD environment variables";
      case CloudflareAccessErrorCode.INVALID_TEAM_DOMAIN:
        return "Verify your team domain URL format (should be https://yourteam.cloudflareaccess.com)";
      case CloudflareAccessErrorCode.MISSING_AUDIENCE_TAG:
        return "Set CF_ACCESS_AUD to your application's audience tag";
      case CloudflareAccessErrorCode.JWKS_FETCH_ERROR:
        return "Unable to fetch signing keys. Check network connectivity and team domain";
      default:
        return "Check Cloudflare Access configuration and try again";
    }
  }
}

/**
 * Error thrown when authentication is required but missing/invalid
 */
export class AuthRequiredError extends CloudflareAccessError {
  constructor(options?: { requestUrl?: string; context?: Record<string, unknown> }) {
    super(
      CloudflareAccessErrorCode.AUTH_REQUIRED,
      "Authentication required via Cloudflare Access",
      { requestUrl: options?.requestUrl, context: options?.context },
    );
    this.name = "AuthRequiredError";
  }
}

/**
 * Error thrown when token validation fails
 */
export class InvalidTokenError extends CloudflareAccessError {
  readonly reason: string;

  constructor(reason: string, options?: { requestUrl?: string }) {
    super(CloudflareAccessErrorCode.INVALID_TOKEN, `Invalid authentication token: ${reason}`, {
      requestUrl: options?.requestUrl,
    });
    this.name = "InvalidTokenError";
    this.reason = reason;
  }
}

/**
 * Error thrown when user is not in email allowlist
 */
export class AccessDeniedError extends CloudflareAccessError {
  readonly email: string;

  constructor(email: string, options?: { requestUrl?: string; allowedEmails?: string[] }) {
    super(CloudflareAccessErrorCode.ACCESS_DENIED, `Access denied for ${email}`, {
      requestUrl: options?.requestUrl,
      context: { email, allowedEmails: options?.allowedEmails },
    });
    this.name = "AccessDeniedError";
    this.email = email;
  }
}

/**
 * Error thrown when configuration is invalid or missing
 */
export class ConfigurationError extends CloudflareAccessError {
  constructor(message: string, options?: { cause?: Error; context?: Record<string, unknown> }) {
    super(CloudflareAccessErrorCode.MISSING_CONFIG, message, options);
    this.name = "ConfigurationError";
  }
}

/**
 * Type guard to check if error is a CloudflareAccessError
 */
export function isCloudflareAccessError(error: unknown): error is CloudflareAccessError {
  return error instanceof CloudflareAccessError;
}

/**
 * Type guard for specific error types
 */
export function isAuthRequiredError(error: unknown): error is AuthRequiredError {
  return error instanceof AuthRequiredError;
}

export function isInvalidTokenError(error: unknown): error is InvalidTokenError {
  return error instanceof InvalidTokenError;
}

export function isAccessDeniedError(error: unknown): error is AccessDeniedError {
  return error instanceof AccessDeniedError;
}

export function isConfigurationError(error: unknown): error is ConfigurationError {
  return error instanceof ConfigurationError;
}

/**
 * Convert unknown error to CloudflareAccessError
 */
export function toAuthError(error: unknown): CloudflareAccessError {
  if (isCloudflareAccessError(error)) {
    return error;
  }

  if (error instanceof Error) {
    return new CloudflareAccessError(CloudflareAccessErrorCode.INVALID_TOKEN, error.message, {
      cause: error,
    });
  }

  return new CloudflareAccessError(
    CloudflareAccessErrorCode.INVALID_TOKEN,
    "Unknown authentication error",
    { context: { error } },
  );
}
