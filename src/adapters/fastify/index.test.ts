import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import type { FastifyRequest, FastifyReply } from "fastify";
import { cloudflareAccessPreHandler, __clearJwksCache } from "cloudflare-access/fastify";
import { SignJWT, generateKeyPair, exportJWK, type JWK, type KeyLike } from "jose";

describe("Fastify adapter - cloudflareAccessPlugin", () => {
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

  function createMockRequest(token?: string): FastifyRequest {
    return {
      url: "/protected",
      method: "GET",
      protocol: "http",
      hostname: "localhost",
      headers: {
        "cf-access-jwt-assertion": token,
      },
    } as unknown as FastifyRequest;
  }

  function createMockReply(): FastifyReply {
    const reply: any = {
      statusCode: 200,
      sentBody: null,
    };
    reply.code = function (code: number) {
      this.statusCode = code;
      return this;
    };
    reply.send = function (body: any) {
      this.sentBody = body;
      return this;
    };
    return reply as FastifyReply;
  }

  describe("cloudflareAccessPreHandler", () => {
    it("should allow access with valid JWT token", async () => {
      const token = await createValidJWT();
      const mockRequest = createMockRequest(token);
      const mockReply = createMockReply();

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      // Check if user was set on the request
      expect((mockRequest as any).user?.email).toBe("test@example.com");
    });

    it("should reject request without JWT token", async () => {
      const mockRequest = createMockRequest(undefined);
      const mockReply = createMockReply();

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      expect(mockReply.statusCode).toBe(401);
      expect((mockReply as any).sentBody?.error?.code).toBe("AUTH_REQUIRED");
    });

    it("should reject request with invalid JWT token", async () => {
      const mockRequest = createMockRequest("invalid-token");
      const mockReply = createMockReply();

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      expect(mockReply.statusCode).toBe(401);
      expect((mockReply as any).sentBody?.error?.code).toBe("INVALID_TOKEN");
    });
  });

  describe("email allowlist", () => {
    it("should allow access for email in allowlist", async () => {
      const token = await createValidJWT({ email: "admin@example.com" });
      const mockRequest = createMockRequest(token);
      const mockReply = createMockReply();

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      expect((mockRequest as any).user?.email).toBe("admin@example.com");
    });

    it("should reject access for email not in allowlist", async () => {
      const token = await createValidJWT({ email: "test@example.com" });
      const mockRequest = createMockRequest(token);
      const mockReply = createMockReply();

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      expect(mockReply.statusCode).toBe(403);
      expect((mockReply as any).sentBody?.error?.code).toBe("ACCESS_DENIED");
    });
  });

  describe("excluded paths", () => {
    it("should skip auth for excluded paths", async () => {
      const mockRequest = {
        url: "/health",
        method: "GET",
        protocol: "http",
        hostname: "localhost",
        headers: {},
      } as unknown as FastifyRequest;

      const mockReply = createMockReply();

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
        excludePaths: ["/health", "/public"],
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      // Status should still be 200 (unchanged) because auth was skipped
      expect(mockReply.statusCode).toBe(200);
    });
  });

  describe("OPTIONS requests", () => {
    it("should skip auth for OPTIONS requests", async () => {
      const mockRequest = {
        url: "/protected",
        method: "OPTIONS",
        protocol: "http",
        hostname: "localhost",
        headers: {},
      } as unknown as FastifyRequest;

      const mockReply = createMockReply();

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      // Status should still be 200 (unchanged) because auth was skipped
      expect(mockReply.statusCode).toBe(200);
    });
  });

  describe("custom handlers", () => {
    it("should use custom unauthorized handler", async () => {
      const mockRequest = createMockRequest(undefined);
      const mockReply = createMockReply();

      let handlerCalled = false;
      let receivedReason = "";

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
        onUnauthorized: async (_request, _reply, reason) => {
          handlerCalled = true;
          receivedReason = reason;
          _reply.code(401).send({ custom: "unauthorized", reason });
        },
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      expect(handlerCalled).toBe(true);
      expect(receivedReason).toContain("Missing");
      expect((mockReply as any).sentBody?.custom).toBe("unauthorized");
    });

    it("should use custom forbidden handler", async () => {
      const token = await createValidJWT({ email: "test@example.com" });
      const mockRequest = createMockRequest(token);
      const mockReply = createMockReply();

      let handlerCalled = false;
      let receivedEmail = "";

      const preHandler = cloudflareAccessPreHandler({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
        onForbidden: async (_request, _reply, email) => {
          handlerCalled = true;
          receivedEmail = email;
          _reply.code(403).send({ custom: "forbidden", email });
        },
      });

      await preHandler.call({ user: undefined }, mockRequest, mockReply);

      expect(handlerCalled).toBe(true);
      expect(receivedEmail).toBe("test@example.com");
      expect((mockReply as any).sentBody?.custom).toBe("forbidden");
    });
  });
});
