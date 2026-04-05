import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import type { Request, Response } from "express";
import {
  cloudflareAccessAuth,
  __clearJwksCache,
  type CloudflareAccessConfig,
} from "cloudflare-access/express";
import { SignJWT, generateKeyPair, exportJWK, type JWK, type KeyLike } from "jose";

describe("Express adapter - cloudflareAccessAuth", () => {
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

  function createMockRequest(token?: string): Request {
    return {
      path: "/protected",
      method: "GET",
      headers: {
        "cf-access-jwt-assertion": token,
        host: "localhost",
      },
      protocol: "http",
      originalUrl: "/protected",
    } as unknown as Request;
  }

  function createMockResponse(): Response {
    return {
      statusCode: 200,
      jsonBody: null,
      status(code: number) {
        (this as any).statusCode = code;
        return this;
      },
      json(body: any) {
        (this as any).jsonBody = body;
        return this;
      },
    } as unknown as Response;
  }

  describe("basic authentication", () => {
    it("should allow access with valid JWT token", async () => {
      const token = await createValidJWT();
      const req = createMockRequest(token);
      const res = createMockResponse();

      const middleware = cloudflareAccessAuth({ accessConfig: { teamDomain, audTag } });

      let nextCalled = false;
      const next = () => {
        nextCalled = true;
      };

      await middleware(req, res, next);

      expect(nextCalled).toBe(true);
      expect((req as any).user?.email).toBe("test@example.com");
      expect((req as any).user?.userId).toBe("user-123");
      expect((req as any).user?.country).toBe("US");
    });

    it("should reject request without JWT token", async () => {
      const req = createMockRequest(undefined);
      const res = createMockResponse();

      const middleware = cloudflareAccessAuth({ accessConfig: { teamDomain, audTag } });
      await middleware(req, res, () => {});

      expect((res as any).statusCode).toBe(401);
      expect((res as any).jsonBody?.error?.code).toBe("AUTH_REQUIRED");
    });

    it("should reject request with invalid JWT token", async () => {
      const req = createMockRequest("invalid-token");
      const res = createMockResponse();

      const middleware = cloudflareAccessAuth({ accessConfig: { teamDomain, audTag } });
      await middleware(req, res, () => {});

      expect((res as any).statusCode).toBe(401);
      expect((res as any).jsonBody?.error?.code).toBe("INVALID_TOKEN");
    });
  });

  describe("email allowlist", () => {
    it("should allow access for email in allowlist", async () => {
      const token = await createValidJWT({ email: "admin@example.com" });
      const req = createMockRequest(token);
      const res = createMockResponse();

      const middleware = cloudflareAccessAuth({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
      });

      let nextCalled = false;
      const next = () => {
        nextCalled = true;
      };

      await middleware(req, res, next);

      expect(nextCalled).toBe(true);
      expect((req as any).user?.email).toBe("admin@example.com");
    });

    it("should reject access for email not in allowlist", async () => {
      const token = await createValidJWT({ email: "test@example.com" });
      const req = createMockRequest(token);
      const res = createMockResponse();

      const middleware = cloudflareAccessAuth({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
      });

      await middleware(req, res, () => {});

      expect((res as any).statusCode).toBe(403);
      expect((res as any).jsonBody?.error?.code).toBe("ACCESS_DENIED");
    });
  });

  describe("excluded paths", () => {
    it("should skip auth for excluded paths", async () => {
      const req = {
        path: "/health",
        method: "GET",
        headers: { host: "localhost" },
        protocol: "http",
        originalUrl: "/health",
      } as unknown as Request;

      const res = createMockResponse();

      let nextCalled = false;

      const middleware = cloudflareAccessAuth({
        accessConfig: { teamDomain, audTag },
        excludePaths: ["/health", "/public"],
      });

      const next = () => {
        nextCalled = true;
      };

      await middleware(req, res, next);

      expect(nextCalled).toBe(true);
    });
  });

  describe("OPTIONS requests", () => {
    it("should skip auth for OPTIONS requests", async () => {
      const req = {
        path: "/protected",
        method: "OPTIONS",
        headers: { host: "localhost" },
        protocol: "http",
        originalUrl: "/protected",
      } as unknown as Request;

      const res = createMockResponse();

      let nextCalled = false;

      const middleware = cloudflareAccessAuth({
        accessConfig: { teamDomain, audTag },
      });

      const next = () => {
        nextCalled = true;
      };

      await middleware(req, res, next);

      expect(nextCalled).toBe(true);
    });
  });

  describe("custom handlers", () => {
    it("should use custom unauthorized handler", async () => {
      const req = createMockRequest(undefined);
      const res = createMockResponse();

      let handlerCalled = false;
      let receivedReason = "";

      const middleware = cloudflareAccessAuth({
        accessConfig: { teamDomain, audTag },
        onUnauthorized: (_req, _res, reason) => {
          handlerCalled = true;
          receivedReason = reason;
          _res.status(401).json({ custom: "unauthorized", reason });
        },
      });

      await middleware(req, res, () => {});

      expect(handlerCalled).toBe(true);
      expect(receivedReason).toContain("Missing");
      expect((res as any).jsonBody?.custom).toBe("unauthorized");
    });

    it("should use custom forbidden handler", async () => {
      const token = await createValidJWT({ email: "test@example.com" });
      const req = createMockRequest(token);
      const res = createMockResponse();

      let handlerCalled = false;
      let receivedEmail = "";

      const middleware = cloudflareAccessAuth({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
        onForbidden: (_req, _res, email) => {
          handlerCalled = true;
          receivedEmail = email;
          _res.status(403).json({ custom: "forbidden", email });
        },
      });

      await middleware(req, res, () => {});

      expect(handlerCalled).toBe(true);
      expect(receivedEmail).toBe("test@example.com");
      expect((res as any).jsonBody?.custom).toBe("forbidden");
    });
  });
});
