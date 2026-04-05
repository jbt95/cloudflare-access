import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

/**
 * Cloudflare Access JWT payload with additional claims
 */
export interface CloudflareAccessPayload extends JWTPayload {
  /** User's email address */
  email?: string;
  /** Token type */
  type?: string;
  /** Identity nonce for additional verification */
  identity_nonce?: string;
  /** User's country */
  country?: string;
}

/**
 * Cloudflare Access configuration
 */
export interface CloudflareAccessConfig {
  /** Exact Cloudflare Access issuer domain, e.g. https://myteam.cloudflareaccess.com */
  teamDomain: string;
  /** Exact Access application audience tag */
  audTag: string;
}

/**
 * User information extracted from Cloudflare Access token
 */
export interface CloudflareAccessUser {
  email: string;
  userId?: string;
  country?: string;
}

/**
 * Expected environment bindings for Cloudflare Access
 */
export interface CloudflareAccessMiddlewareEnv {
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  ENVIRONMENT?: string;
}

/**
 * Error codes for Cloudflare Access authentication
 */
export const CloudflareAccessErrorCode = {
  /** Missing or invalid authentication token */
  AUTH_REQUIRED: "AUTH_REQUIRED",
  /** Token validation failed (expired, wrong signature, etc.) */
  INVALID_TOKEN: "INVALID_TOKEN",
  /** User email not in allowlist */
  ACCESS_DENIED: "ACCESS_DENIED",
  /** Invalid team domain configuration */
  INVALID_TEAM_DOMAIN: "INVALID_TEAM_DOMAIN",
  /** Missing audience tag configuration */
  MISSING_AUDIENCE_TAG: "MISSING_AUDIENCE_TAG",
  /** Missing environment configuration */
  MISSING_CONFIG: "MISSING_CONFIG",
  /** JWKS fetch failed */
  JWKS_FETCH_ERROR: "JWKS_FETCH_ERROR",
} as const;

export type CloudflareAccessErrorCode =
  typeof CloudflareAccessErrorCode[keyof typeof CloudflareAccessErrorCode];

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
      context: this.context,
      requestUrl: this.requestUrl,
      timestamp: this.timestamp,
      cause: this.cause instanceof Error
        ? { message: this.cause.message, name: this.cause.name }
        : undefined,
    };
  }
}

/**
 * Error thrown when authentication is required but token is missing
 */
export class AuthRequiredError extends CloudflareAccessError {
  constructor(options?: {
    requestUrl?: string;
    context?: Record<string, unknown>;
  }) {
    super(
      CloudflareAccessErrorCode.AUTH_REQUIRED,
      "Authentication required via Cloudflare Access",
      {
        ...options,
        context: {
          ...options?.context,
          fix: "Sign in via Cloudflare Access and include the CF-Access-JWT-Assertion header",
          documentation: "https://developers.cloudflare.com/cloudflare-one/identity/",
        },
      },
    );
    this.name = "AuthRequiredError";
  }
}

/**
 * Error thrown when token validation fails
 */
export class InvalidTokenError extends CloudflareAccessError {
  readonly reason: string;

  constructor(reason: string, options?: {
    cause?: Error;
    requestUrl?: string;
    tokenInfo?: { issuer?: string; audience?: string; exp?: number };
  }) {
    const message = `Invalid authentication token: ${reason}`;
    super(
      CloudflareAccessErrorCode.INVALID_TOKEN,
      message,
      {
        cause: options?.cause,
        requestUrl: options?.requestUrl,
        context: {
          reason,
          tokenInfo: options?.tokenInfo,
          fix: "Please sign in again via Cloudflare Access to obtain a new token",
          commonCauses: [
            "Token has expired",
            "Token was issued by wrong team domain",
            "Token audience doesn't match application",
            "Token signature is invalid",
          ],
        },
      },
    );
    this.name = "InvalidTokenError";
    this.reason = reason;
  }
}

/**
 * Error thrown when user is not authorized to access resource
 */
export class AccessDeniedError extends CloudflareAccessError {
  readonly email: string;

  constructor(email: string, options?: {
    requestUrl?: string;
    allowedEmails?: string[];
  }) {
    const message = `Access denied for ${email}`;
    super(
      CloudflareAccessErrorCode.ACCESS_DENIED,
      message,
      {
        ...options,
        context: {
          email,
          allowedEmails: options?.allowedEmails,
          fix: "Contact an administrator if you need access to this resource",
          note: "Your email must be in the allowedEmails list or the Cloudflare Access policy must allow your email",
        },
      },
    );
    this.name = "AccessDeniedError";
    this.email = email;
  }
}

/**
 * Error thrown when configuration is invalid
 */
export class ConfigurationError extends CloudflareAccessError {
  readonly configKey: string;

  constructor(
    code: Exclude<
      CloudflareAccessErrorCode,
      "AUTH_REQUIRED" | "INVALID_TOKEN" | "ACCESS_DENIED"
    >,
    configKey: string,
    message: string,
    options?: {
      requestUrl?: string;
      expectedFormat?: string;
    },
  ) {
    super(
      code,
      message,
      {
        ...options,
        context: {
          configKey,
          expectedFormat: options?.expectedFormat,
          fix: `Check your Cloudflare Access configuration for ${configKey}`,
        },
      },
    );
    this.name = "ConfigurationError";
    this.configKey = configKey;
  }
}

/** JWK Set cache by team domain */
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

/**
 * Clear the JWKS cache. Useful for testing.
 * @internal
 */
export function __clearJwksCache(): void {
  jwksCache.clear();
}

/**
 * Remove trailing slashes from team domain
 */
function normalizeTeamDomain(teamDomain: string): string {
  return teamDomain.replace(/\/+$/, "");
}

/**
 * Validate and normalize access configuration
 */
export function validateAccessConfig(
  config: CloudflareAccessConfig,
  requestUrl?: string,
): CloudflareAccessConfig {
  const teamDomain = normalizeTeamDomain(config.teamDomain);

  if (!teamDomain.startsWith("https://") || !teamDomain.endsWith(".cloudflareaccess.com")) {
    throw new ConfigurationError(
      CloudflareAccessErrorCode.INVALID_TEAM_DOMAIN,
      "teamDomain",
      `Invalid Cloudflare Access team domain: ${config.teamDomain}`,
      {
        requestUrl,
        expectedFormat: "https://<team>.cloudflareaccess.com",
      },
    );
  }

  if (!config.audTag) {
    throw new ConfigurationError(
      CloudflareAccessErrorCode.MISSING_AUDIENCE_TAG,
      "audTag",
      "Missing Cloudflare Access audience tag",
      {
        requestUrl,
        expectedFormat: "Application AUD tag from Cloudflare Access dashboard",
      },
    );
  }

  return { teamDomain, audTag: config.audTag };
}

/**
 * Get or create cached JWKS for a team domain
 */
export function getRemoteJwks(teamDomain: string): ReturnType<typeof createRemoteJWKSet> {
  const cached = jwksCache.get(teamDomain);
  if (cached) {
    return cached;
  }

  const jwks = createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`));
  jwksCache.set(teamDomain, jwks);
  return jwks;
}

/**
 * Check if request is from local development
 */
export function isLocalDevelopmentRequest(url: string): boolean {
  try {
    const hostname = new URL(url).hostname;
    return (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "[::1]" ||
      hostname.endsWith(".localhost")
    );
  } catch {
    return false;
  }
}

/**
 * Options for creating Cloudflare Access authentication
 */
export interface CloudflareAccessAuthOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;

  /** Optional email allowlist. Access policy should still be configured at Cloudflare. */
  allowedEmails?: string[];

  /** Whether to skip JWT validation outside production */
  skipInDev?: boolean;

  /** Environment indicator */
  environment?: string;
}

/**
 * Rich authentication error with actionable information
 */
export interface AuthError {
  code: CloudflareAccessErrorCode;
  message: string;
  why: string;
  fix: string;
  context?: Record<string, unknown>;
}

/**
 * Authentication result
 */
export interface AuthResult {
  success: boolean;
  user?: CloudflareAccessUser;
  error?: AuthError;
}

/**
 * Type guard to check if error is a CloudflareAccessError
 */
export function isCloudflareAccessError(error: unknown): error is CloudflareAccessError {
  return error instanceof CloudflareAccessError;
}

/**
 * Type guard to check if error is an AuthRequiredError
 */
export function isAuthRequiredError(error: unknown): error is AuthRequiredError {
  return error instanceof AuthRequiredError;
}

/**
 * Type guard to check if error is an InvalidTokenError
 */
export function isInvalidTokenError(error: unknown): error is InvalidTokenError {
  return error instanceof InvalidTokenError;
}

/**
 * Type guard to check if error is an AccessDeniedError
 */
export function isAccessDeniedError(error: unknown): error is AccessDeniedError {
  return error instanceof AccessDeniedError;
}

/**
 * Type guard to check if error is a ConfigurationError
 */
export function isConfigurationError(error: unknown): error is ConfigurationError {
  return error instanceof ConfigurationError;
}

/**
 * Convert any error to a rich AuthError
 */
export function toAuthError(
  error: unknown,
  requestUrl?: string,
): AuthError {
  if (isCloudflareAccessError(error)) {
    return {
      code: error.code,
      message: error.message,
      why: error.message,
      fix: (error.context?.fix as string) || "Please try again",
      context: error.context,
    };
  }

  if (error instanceof Error) {
    return {
      code: CloudflareAccessErrorCode.INVALID_TOKEN,
      message: error.message,
      why: error.message,
      fix: "Please sign in again via Cloudflare Access",
      context: { requestUrl },
    };
  }

  return {
    code: CloudflareAccessErrorCode.INVALID_TOKEN,
    message: "Unknown authentication error",
    why: "An unexpected error occurred",
    fix: "Please try again or contact support",
    context: { requestUrl },
  };
}

/**
 * Validate Cloudflare Access JWT token
 */
export async function validateCloudflareAccessToken(
  token: string | undefined,
  options: CloudflareAccessAuthOptions,
  requestUrl: string,
): Promise<AuthResult> {
  const { accessConfig, allowedEmails, skipInDev, environment } = options;
  const isDev = environment !== "prod";

  // Skip OPTIONS requests
  if (!token) {
    // Check if we should skip auth in dev
    if (isDev && skipInDev && isLocalDevelopmentRequest(requestUrl)) {
      return { success: true };
    }

    return {
      success: false,
      error: {
        code: CloudflareAccessErrorCode.AUTH_REQUIRED,
        message: "Unauthorized",
        why: "Missing CF-Access-JWT-Assertion header",
        fix: "Sign in via Cloudflare Access",
        context: { requestUrl },
      },
    };
  }

  try {
    const { teamDomain, audTag } = validateAccessConfig(accessConfig, requestUrl);
    const jwks = getRemoteJwks(teamDomain);

    // Verify the JWT token
    const { payload } = await jwtVerify(token, jwks, {
      issuer: teamDomain,
      audience: audTag,
      algorithms: ["RS256"],
    });

    const accessPayload = payload as CloudflareAccessPayload;
    const email = accessPayload.email;

    if (!email) {
      throw new InvalidTokenError(
        "Email not found in validated Cloudflare Access token",
        {
          requestUrl,
          tokenInfo: {
            issuer: payload.iss,
            audience: Array.isArray(payload.aud) ? payload.aud[0] : payload.aud,
            exp: payload.exp,
          },
        },
      );
    }

    // Check email allowlist if configured
    if (allowedEmails && !allowedEmails.includes(email)) {
      return {
        success: false,
        user: {
          email,
          userId: typeof accessPayload.sub === "string" ? accessPayload.sub : undefined,
          country: accessPayload.country,
        },
        error: {
          code: CloudflareAccessErrorCode.ACCESS_DENIED,
          message: "Forbidden",
          why: "Your email is not authorized to access this resource",
          fix: "Contact an administrator if you need access",
          context: {
            email,
            allowedEmails,
            requestUrl,
          },
        },
      };
    }

    return {
      success: true,
      user: {
        email,
        userId: typeof accessPayload.sub === "string" ? accessPayload.sub : undefined,
        country: accessPayload.country,
      },
    };
  } catch (error) {
    if (error instanceof CloudflareAccessError) {
      return {
        success: false,
        error: {
          code: error.code,
          message: error.message,
          why: error.message,
          fix: (error.context?.fix as string) || "Please sign in again via Cloudflare Access",
          context: error.context,
        },
      };
    }

    const reason = error instanceof Error ? error.message : "Token validation failed";
    return {
      success: false,
      error: {
        code: CloudflareAccessErrorCode.INVALID_TOKEN,
        message: "Invalid authentication token",
        why: reason,
        fix: "Please sign in again via Cloudflare Access",
        context: { requestUrl, originalError: reason },
      },
    };
  }
}

/**
 * Get Cloudflare Access configuration from environment variables/bindings
 */
export function getCloudflareAccessConfigFromEnv(
  env: CloudflareAccessMiddlewareEnv,
): CloudflareAccessConfig {
  const teamDomain = env.CF_ACCESS_TEAM_DOMAIN;
  const audTag = env.CF_ACCESS_AUD;

  if (!teamDomain || !audTag) {
    const missing = [!teamDomain && "CF_ACCESS_TEAM_DOMAIN", !audTag && "CF_ACCESS_AUD"]
      .filter(Boolean)
      .join(" and ");

    throw new ConfigurationError(
      CloudflareAccessErrorCode.MISSING_CONFIG,
      missing,
      `Missing Cloudflare Access bindings: ${missing}`,
      {
        expectedFormat: "CF_ACCESS_TEAM_DOMAIN=https://<team>.cloudflareaccess.com, CF_ACCESS_AUD=<audience-tag>",
      },
    );
  }

  return { teamDomain, audTag };
}
