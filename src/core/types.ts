import type { JWTPayload } from "jose";

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
  (typeof CloudflareAccessErrorCode)[keyof typeof CloudflareAccessErrorCode];

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
export type AuthResult =
  | { success: true; user: CloudflareAccessUser | null; error?: never }
  | { success: false; user?: CloudflareAccessUser | null; error: AuthError };
