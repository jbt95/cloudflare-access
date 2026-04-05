import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { CloudflareAccessGuard, IS_PUBLIC_KEY } from "cloudflare-access/nestjs";
import { __clearJwksCache } from "cloudflare-access/core";
import { SignJWT, generateKeyPair, exportJWK, type JWK, type KeyLike } from "jose";
import type { ExecutionContext } from "@nestjs/common";
import "reflect-metadata";

describe("NestJS adapter - CloudflareAccessGuard", () => {
  let mockJWK: JWK;
  let mockPrivateKey: KeyLike;
  const teamDomain = "https://testteam.cloudflareaccess.com";
  const audTag = "test-audience-tag";

  const originalFetch = globalThis.fetch;

  beforeEach(async () => {
    __clearJwksCache();

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

    if (!mockJWK.n || !mockJWK.e) {
      throw new Error("Missing required RSA JWK fields");
    }

    (globalThis as any).fetch = async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes("/cdn-cgi/access/certs")) {
        return new Response(JSON.stringify({ keys: [mockJWK] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return originalFetch(input);
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    __clearJwksCache();
  });

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

  function createMockExecutionContext(
    headers: Record<string, string>,
    url: string = "/protected",
    method: string = "GET",
  ): ExecutionContext {
    const req = {
      headers,
      url,
      method,
      originalUrl: url,
      user: undefined,
    };

    return {
      switchToHttp: () => ({
        getRequest: () => req,
      }),
      getHandler: () => ({}),
      getClass: () => ({}),
    } as unknown as ExecutionContext;
  }

  describe("basic authentication", () => {
    it("should allow access with valid JWT token", async () => {
      const token = await createValidJWT();
      const context = createMockExecutionContext({
        "cf-access-jwt-assertion": token,
      });

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      const request = context.switchToHttp().getRequest();
      expect(request.user?.email).toBe("test@example.com");
      expect(request.user?.userId).toBe("user-123");
    });

    it("should reject request without JWT token", async () => {
      const context = createMockExecutionContext({});

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      try {
        await guard.canActivate(context);
        expect(false).toBe(true); // Should not reach here
      } catch (error: any) {
        expect(error.status).toBe(401);
      }
    });

    it("should reject request with invalid JWT token", async () => {
      const context = createMockExecutionContext({
        "cf-access-jwt-assertion": "invalid-token",
      });

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      try {
        await guard.canActivate(context);
        expect(false).toBe(true); // Should not reach here
      } catch (error: any) {
        expect(error.status).toBe(401);
      }
    });
  });

  describe("email allowlist", () => {
    it("should allow access for email in allowlist", async () => {
      const token = await createValidJWT({ email: "admin@example.com" });
      const context = createMockExecutionContext({
        "cf-access-jwt-assertion": token,
      });

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
      });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it("should reject access for email not in allowlist", async () => {
      const token = await createValidJWT({ email: "test@example.com" });
      const context = createMockExecutionContext({
        "cf-access-jwt-assertion": token,
      });

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
      });

      try {
        await guard.canActivate(context);
        expect(false).toBe(true); // Should not reach here
      } catch (error: any) {
        expect(error.status).toBe(403);
      }
    });
  });

  describe("OPTIONS requests", () => {
    it("should skip auth for OPTIONS requests", async () => {
      const context = createMockExecutionContext({}, "/protected", "OPTIONS");

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });

  describe("Public decorator", () => {
    it("should skip auth for routes marked with @Public()", async () => {
      // Create a handler function and mark it as public
      const handler = () => {};
      Reflect.defineMetadata(IS_PUBLIC_KEY, true, handler);

      const req = {
        headers: {},
        url: "/protected",
        method: "GET",
        originalUrl: "/protected",
        user: undefined,
      };

      const context = {
        switchToHttp: () => ({
          getRequest: () => req,
        }),
        getHandler: () => handler,
        getClass: () => ({}),
      } as unknown as ExecutionContext;

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it("should require auth for non-public routes", async () => {
      // Handler without public metadata
      const handler = () => {};

      const req = {
        headers: {},
        url: "/protected",
        method: "GET",
        originalUrl: "/protected",
        user: undefined,
      };

      const context = {
        switchToHttp: () => ({
          getRequest: () => req,
        }),
        getHandler: () => handler,
        getClass: () => ({}),
      } as unknown as ExecutionContext;

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      try {
        await guard.canActivate(context);
        expect(false).toBe(true); // Should not reach here
      } catch (error: any) {
        expect(error.status).toBe(401);
      }
    });
  });

  describe("token validation", () => {
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

      const context = createMockExecutionContext({
        "cf-access-jwt-assertion": wrongToken,
      });

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      try {
        await guard.canActivate(context);
        expect(false).toBe(true); // Should not reach here
      } catch (error: any) {
        expect(error.status).toBe(401);
      }
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

      const context = createMockExecutionContext({
        "cf-access-jwt-assertion": wrongToken,
      });

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      try {
        await guard.canActivate(context);
        expect(false).toBe(true); // Should not reach here
      } catch (error: any) {
        expect(error.status).toBe(401);
      }
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

      const context = createMockExecutionContext({
        "cf-access-jwt-assertion": expiredToken,
      });

      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      try {
        await guard.canActivate(context);
        expect(false).toBe(true); // Should not reach here
      } catch (error: any) {
        expect(error.status).toBe(401);
      }
    });
  });
});
