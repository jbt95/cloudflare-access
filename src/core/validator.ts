import { jwtVerify } from "jose";
import {
  CloudflareAccessErrorCode,
  type CloudflareAccessConfig,
  type CloudflareAccessPayload,
  type AuthResult,
} from "./types";
import { validateAccessConfig } from "./config";
import { getRemoteJwks, isLocalDevelopmentRequest } from "./jwks";
import { InvalidTokenError, CloudflareAccessError } from "./errors";

/**
 * Options for token validation
 */
export interface ValidateTokenOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;
  /** Optional email allowlist */
  allowedEmails?: string[];
  /** Whether to skip JWT validation outside production */
  skipInDev?: boolean;
  /** Environment indicator */
  environment?: string;
}

/**
 * Validate Cloudflare Access JWT token
 */
export async function validateCloudflareAccessToken(
  token: string | undefined,
  options: ValidateTokenOptions,
  requestUrl: string,
): Promise<AuthResult> {
  const { accessConfig, allowedEmails, skipInDev, environment } = options;
  const isDev = environment !== "prod";

  // Skip OPTIONS requests
  if (!token) {
    // Check if we should skip auth in dev
    if (isDev && skipInDev && isLocalDevelopmentRequest(requestUrl)) {
      return { success: true, user: null };
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
      throw new InvalidTokenError("Email not found in validated Cloudflare Access token", {
        requestUrl,
      });
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
