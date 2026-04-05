import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import {
  validateCloudflareAccessToken,
  validateAccessConfig,
  getRemoteJwks,
  isLocalDevelopmentRequest,
  getCloudflareAccessConfigFromEnv,
  __clearJwksCache,
  type CloudflareAccessConfig,
} from "cloudflare-access/core";
import { SignJWT, generateKeyPair, exportJWK, type JWK, type KeyLike } from "jose";

describe("core/auth", () => {
  let mockJWK: JWK;
  let mockPrivateKey: KeyLike;
  const teamDomain = "https://testteam.cloudflareaccess.com";
  const audTag = "test-audience-tag";

  // Store original fetch
  const originalFetch = globalThis.fetch;

  beforeEach(async () => {
    // Clear JWKS cache between tests
    __clearJwksCache();

    // Generate a mock key pair for signing JWTs
    const { privateKey, publicKey } = await generateKeyPair("RS256", {
      extractable: true,
      modulusLength: 2048,
    });
    mockPrivateKey = privateKey;
    mockJWK = await exportJWK(publicKey);
    mockJWK.kid = "test-key-id";
    mockJWK.kty = "RSA";
    mockJWK.alg = "RS256";
    mockJWK.use = "sig";

    // Ensure all required RSA fields are present
    if (!mockJWK.n || !mockJWK.e) {
      throw new Error("Missing required RSA JWK fields");
    }

    // Mock fetch to return the JWKS
    (globalThis as any).fetch = async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes("/cdn-cgi/access/certs")) {
        return new Response(
          JSON.stringify({
            keys: [mockJWK],
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      }
      return originalFetch(input);
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    __clearJwksCache();
  });

  // Helper to create a valid JWT
  async function createValidJWT(payload: Record<string, unknown> = {}): Promise<string> {
    return new SignJWT({
      email: "test@example.com",
      sub: "user-123",
      country: "US",
      ...payload,
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .setIssuer(teamDomain)
      .setAudience(audTag)
      .sign(mockPrivateKey);
  }

  describe("validateAccessConfig", () => {
    it("should validate correct config", () => {
      const config: CloudflareAccessConfig = {
        teamDomain: "https://testteam.cloudflareaccess.com",
        audTag: "test-audience",
      };
      const result = validateAccessConfig(config);
      expect(result.teamDomain).toBe("https://testteam.cloudflareaccess.com");
      expect(result.audTag).toBe("test-audience");
    });

    it("should normalize team domain with trailing slashes", () => {
      const config: CloudflareAccessConfig = {
        teamDomain: "https://testteam.cloudflareaccess.com///",
        audTag: "test-audience",
      };
      const result = validateAccessConfig(config);
      expect(result.teamDomain).toBe("https://testteam.cloudflareaccess.com");
    });

    it("should throw for invalid team domain", () => {
      const config: CloudflareAccessConfig = {
        teamDomain: "https://invalid.com",
        audTag: "test-audience",
      };
      expect(() => validateAccessConfig(config)).toThrow("Invalid Cloudflare Access team domain");
    });

    it("should throw for missing aud tag", () => {
      const config: CloudflareAccessConfig = {
        teamDomain: "https://testteam.cloudflareaccess.com",
        audTag: "",
      };
      expect(() => validateAccessConfig(config)).toThrow("Missing Cloudflare Access audience tag");
    });
  });

  describe("isLocalDevelopmentRequest", () => {
    it("should return true for localhost", () => {
      expect(isLocalDevelopmentRequest("http://localhost:3000/test")).toBe(true);
    });

    it("should return true for 127.0.0.1", () => {
      expect(isLocalDevelopmentRequest("http://127.0.0.1:3000/test")).toBe(true);
    });

    it("should return true for ::1", () => {
      expect(isLocalDevelopmentRequest("http://[::1]:3000/test")).toBe(true);
    });

    it("should return true for .localhost domains", () => {
      expect(isLocalDevelopmentRequest("http://app.localhost:3000/test")).toBe(true);
    });

    it("should return false for production domains", () => {
      expect(isLocalDevelopmentRequest("https://example.com/test")).toBe(false);
    });
  });

  describe("getRemoteJwks", () => {
    it("should cache JWKS for same team domain", () => {
      const jwks1 = getRemoteJwks(teamDomain);
      const jwks2 = getRemoteJwks(teamDomain);
      expect(jwks1).toBe(jwks2);
    });

    it("should create different JWKS for different domains", () => {
      const jwks1 = getRemoteJwks("https://team1.cloudflareaccess.com");
      const jwks2 = getRemoteJwks("https://team2.cloudflareaccess.com");
      expect(jwks1).not.toBe(jwks2);
    });
  });

  describe("getCloudflareAccessConfigFromEnv", () => {
    it("should return config from env", () => {
      const env = {
        CF_ACCESS_TEAM_DOMAIN: "https://myteam.cloudflareaccess.com",
        CF_ACCESS_AUD: "my-audience-tag",
      };
      const result = getCloudflareAccessConfigFromEnv(env);
      expect(result.teamDomain).toBe("https://myteam.cloudflareaccess.com");
      expect(result.audTag).toBe("my-audience-tag");
    });

    it("should throw for missing team domain", () => {
      const env = {
        CF_ACCESS_AUD: "my-audience-tag",
      };
      expect(() => getCloudflareAccessConfigFromEnv(env)).toThrow("CF_ACCESS_TEAM_DOMAIN");
    });

    it("should throw for missing aud tag", () => {
      const env = {
        CF_ACCESS_TEAM_DOMAIN: "https://myteam.cloudflareaccess.com",
      };
      expect(() => getCloudflareAccessConfigFromEnv(env)).toThrow("CF_ACCESS_AUD");
    });
  });

  describe("validateCloudflareAccessToken", () => {
    it("should validate valid token", async () => {
      const token = await createValidJWT();
      const result = await validateCloudflareAccessToken(
        token,
        {
          accessConfig: { teamDomain, audTag },
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(true);
      expect(result.user?.email).toBe("test@example.com");
      expect(result.user?.userId).toBe("user-123");
      expect(result.user?.country).toBe("US");
    });

    it("should reject missing token", async () => {
      const result = await validateCloudflareAccessToken(
        undefined,
        {
          accessConfig: { teamDomain, audTag },
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("AUTH_REQUIRED");
    });

    it("should reject invalid token", async () => {
      const result = await validateCloudflareAccessToken(
        "invalid-token",
        {
          accessConfig: { teamDomain, audTag },
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("INVALID_TOKEN");
    });

    it("should reject token with wrong issuer", async () => {
      const wrongToken = await new SignJWT({
        email: "test@example.com",
        sub: "user-123",
      })
        .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .setIssuer("https://wrongteam.cloudflareaccess.com")
        .setAudience(audTag)
        .sign(mockPrivateKey);

      const result = await validateCloudflareAccessToken(
        wrongToken,
        {
          accessConfig: { teamDomain, audTag },
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("INVALID_TOKEN");
    });

    it("should reject token with wrong audience", async () => {
      const wrongToken = await new SignJWT({
        email: "test@example.com",
        sub: "user-123",
      })
        .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .setIssuer(teamDomain)
        .setAudience("wrong-audience")
        .sign(mockPrivateKey);

      const result = await validateCloudflareAccessToken(
        wrongToken,
        {
          accessConfig: { teamDomain, audTag },
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("INVALID_TOKEN");
    });

    it("should reject expired token", async () => {
      const expiredToken = await new SignJWT({
        email: "test@example.com",
        sub: "user-123",
      })
        .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
        .setIssuedAt()
        .setExpirationTime("-1h")
        .setIssuer(teamDomain)
        .setAudience(audTag)
        .sign(mockPrivateKey);

      const result = await validateCloudflareAccessToken(
        expiredToken,
        {
          accessConfig: { teamDomain, audTag },
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("INVALID_TOKEN");
    });

    it("should reject token without email", async () => {
      const noEmailToken = await new SignJWT({
        sub: "user-123",
      })
        .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .setIssuer(teamDomain)
        .setAudience(audTag)
        .sign(mockPrivateKey);

      const result = await validateCloudflareAccessToken(
        noEmailToken,
        {
          accessConfig: { teamDomain, audTag },
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("INVALID_TOKEN");
    });

    it("should check email allowlist", async () => {
      const token = await createValidJWT({ email: "test@example.com" });
      const result = await validateCloudflareAccessToken(
        token,
        {
          accessConfig: { teamDomain, audTag },
          allowedEmails: ["admin@example.com"],
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("ACCESS_DENIED");
    });

    it("should allow email in allowlist", async () => {
      const token = await createValidJWT({ email: "admin@example.com" });
      const result = await validateCloudflareAccessToken(
        token,
        {
          accessConfig: { teamDomain, audTag },
          allowedEmails: ["admin@example.com"],
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(true);
      expect(result.user?.email).toBe("admin@example.com");
    });

    it("should skip auth in dev when skipInDev is true", async () => {
      const result = await validateCloudflareAccessToken(
        undefined,
        {
          accessConfig: { teamDomain, audTag },
          skipInDev: true,
          environment: "dev",
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(true);
    });

    it("should require auth in production even with skipInDev", async () => {
      const result = await validateCloudflareAccessToken(
        undefined,
        {
          accessConfig: { teamDomain, audTag },
          skipInDev: true,
          environment: "prod",
        },
        "http://localhost/test",
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("AUTH_REQUIRED");
    });
  });
});
