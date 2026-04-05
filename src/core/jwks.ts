import { createRemoteJWKSet } from "jose";

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
