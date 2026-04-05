import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Effect, Either, Option } from "effect";
import {
  authenticate,
  authenticateEither,
  getUser,
  CloudflareAccessError,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  type CloudflareAccessContext,
  type AuthenticationSuccess,
} from "cloudflare-access/effect";
import { __clearJwksCache } from "cloudflare-access/core";
import { SignJWT, generateKeyPair, exportJWK, type JWK, type KeyLike } from "jose";

describe("Effect adapter", () => {
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

  describe("authenticate", () => {
    it("should authenticate with valid JWT token", async () => {
      const token = await createValidJWT();
      const context: CloudflareAccessContext = {
        token: Option.some(token),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        authenticate(context, {
          accessConfig: { teamDomain, audTag },
        }),
      );

      expect(result.user?.email).toBe("test@example.com");
      expect(result.user?.userId).toBe("user-123");
      expect(result.user?.country).toBe("US");
    });

    it("should fail with AuthRequired when token is missing", async () => {
      const context: CloudflareAccessContext = {
        token: Option.none(),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        Effect.either(
          authenticate(context, {
            accessConfig: { teamDomain, audTag },
          }),
        ),
      );

      expect(Either.isLeft(result)).toBe(true);
      if (Either.isLeft(result)) {
        expect(result.left.code).toBe("AUTH_REQUIRED");
        expect(result.left).toBeInstanceOf(AuthRequiredError);
      }
    });

    it("should fail with InvalidToken for invalid token", async () => {
      const context: CloudflareAccessContext = {
        token: Option.some("invalid-token"),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        Effect.either(
          authenticate(context, {
            accessConfig: { teamDomain, audTag },
          }),
        ),
      );

      expect(Either.isLeft(result)).toBe(true);
      if (Either.isLeft(result)) {
        expect(result.left.code).toBe("INVALID_TOKEN");
        expect(result.left).toBeInstanceOf(InvalidTokenError);
      }
    });

    it("should fail with AccessDenied for unauthorized email", async () => {
      const token = await createValidJWT({ email: "test@example.com" });
      const context: CloudflareAccessContext = {
        token: Option.some(token),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        Effect.either(
          authenticate(context, {
            accessConfig: { teamDomain, audTag },
            allowedEmails: ["admin@example.com"],
          }),
        ),
      );

      expect(Either.isLeft(result)).toBe(true);
      if (Either.isLeft(result)) {
        expect(result.left.code).toBe("ACCESS_DENIED");
        expect(result.left).toBeInstanceOf(AccessDeniedError);
      }
    });
  });

  describe("authenticateEither", () => {
    it("should return Right for successful authentication", async () => {
      const token = await createValidJWT();
      const context: CloudflareAccessContext = {
        token: Option.some(token),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        authenticateEither(context, {
          accessConfig: { teamDomain, audTag },
        }),
      );

      expect(Either.isRight(result)).toBe(true);
      if (Either.isRight(result)) {
        expect(result.right.user?.email).toBe("test@example.com");
      }
    });

    it("should return Left for failed authentication", async () => {
      const context: CloudflareAccessContext = {
        token: Option.none(),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        authenticateEither(context, {
          accessConfig: { teamDomain, audTag },
        }),
      );

      expect(Either.isLeft(result)).toBe(true);
      if (Either.isLeft(result)) {
        expect(result.left.code).toBe("AUTH_REQUIRED");
        expect(result.left).toBeInstanceOf(AuthRequiredError);
      }
    });
  });

  describe("getUser", () => {
    it("should return Some for valid token", async () => {
      const token = await createValidJWT();
      const context: CloudflareAccessContext = {
        token: Option.some(token),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        getUser(context, {
          accessConfig: { teamDomain, audTag },
        }),
      );

      expect(Option.isSome(result)).toBe(true);
      if (Option.isSome(result)) {
        expect(result.value.email).toBe("test@example.com");
      }
    });

    it("should return None for invalid token", async () => {
      const context: CloudflareAccessContext = {
        token: Option.none(),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        getUser(context, {
          accessConfig: { teamDomain, audTag },
        }),
      );

      expect(Option.isNone(result)).toBe(true);
    });

    it("should return None for unauthorized email", async () => {
      const token = await createValidJWT({ email: "test@example.com" });
      const context: CloudflareAccessContext = {
        token: Option.some(token),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        getUser(context, {
          accessConfig: { teamDomain, audTag },
          allowedEmails: ["admin@example.com"],
        }),
      );

      expect(Option.isNone(result)).toBe(true);
    });
  });

  describe("error constructors", () => {
    it("AuthRequiredError should create correct error", () => {
      const error = new AuthRequiredError({ context: { reason: "Missing token" } });
      expect(error.code).toBe("AUTH_REQUIRED");
      expect(error.message).toBe("Authentication required via Cloudflare Access");
      expect(error.name).toBe("AuthRequiredError");
    });

    it("AccessDeniedError should create correct error", () => {
      const error = new AccessDeniedError("user@example.com");
      expect(error.code).toBe("ACCESS_DENIED");
      expect(error.message).toBe("Access denied for user@example.com");
      expect(error.name).toBe("AccessDeniedError");
      expect(error.email).toBe("user@example.com");
    });

    it("InvalidTokenError should create correct error", () => {
      const error = new InvalidTokenError("Invalid signature");
      expect(error.code).toBe("INVALID_TOKEN");
      expect(error.message).toBe("Invalid authentication token: Invalid signature");
      expect(error.name).toBe("InvalidTokenError");
      expect(error.reason).toBe("Invalid signature");
    });
  });

  describe("token validation edge cases", () => {
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

      const context: CloudflareAccessContext = {
        token: Option.some(wrongToken),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        Effect.either(
          authenticate(context, {
            accessConfig: { teamDomain, audTag },
          }),
        ),
      );

      expect(Either.isLeft(result)).toBe(true);
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

      const context: CloudflareAccessContext = {
        token: Option.some(wrongToken),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        Effect.either(
          authenticate(context, {
            accessConfig: { teamDomain, audTag },
          }),
        ),
      );

      expect(Either.isLeft(result)).toBe(true);
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

      const context: CloudflareAccessContext = {
        token: Option.some(expiredToken),
        requestUrl: "https://example.com/protected",
      };

      const result = await Effect.runPromise(
        Effect.either(
          authenticate(context, {
            accessConfig: { teamDomain, audTag },
          }),
        ),
      );

      expect(Either.isLeft(result)).toBe(true);
    });
  });

  describe("skipInDev", () => {
    it("should skip auth in dev when skipInDev is true", async () => {
      const context: CloudflareAccessContext = {
        token: Option.none(),
        requestUrl: "http://localhost:3000/protected",
      };

      const result = await Effect.runPromise(
        Effect.either(
          authenticate(context, {
            accessConfig: { teamDomain, audTag },
            skipInDev: true,
            environment: "dev",
          }),
        ),
      );

      // Should succeed but with skipped flag
      expect(Either.isRight(result)).toBe(true);
      if (Either.isRight(result)) {
        expect(result.right.skipped).toBe(true);
      }
    });

    it("should require auth in production even with skipInDev", async () => {
      const context: CloudflareAccessContext = {
        token: Option.none(),
        requestUrl: "http://localhost:3000/protected",
      };

      const result = await Effect.runPromise(
        Effect.either(
          authenticate(context, {
            accessConfig: { teamDomain, audTag },
            skipInDev: true,
            environment: "prod",
          }),
        ),
      );

      // Should fail without token in prod
      expect(Either.isLeft(result)).toBe(true);
    });
  });
});
