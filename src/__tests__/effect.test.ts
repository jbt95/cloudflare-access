import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Effect, Either, Option } from "effect";
import { HttpServerRequest } from "@effect/platform";
import {
  authenticateRequest,
  authenticateEither,
  getUser,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
} from "cloudflare-access/effect";
import { __clearJwksCache } from "cloudflare-access/core";

describe("Effect adapter", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    __clearJwksCache();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    __clearJwksCache();
  });

  function createMockRequest(headers: Record<string, string>): HttpServerRequest.HttpServerRequest {
    return {
      url: "https://example.com/protected",
      headers,
      method: "GET",
    } as unknown as HttpServerRequest.HttpServerRequest;
  }

  describe("authenticateRequest", () => {
    it("should fail with AuthRequired when token is missing", async () => {
      const request = createMockRequest({});

      const result = await Effect.runPromise(
        Effect.either(
          authenticateRequest(request, {
            accessConfig: {
              teamDomain: "https://testteam.cloudflareaccess.com",
              audTag: "test-audience-tag",
            },
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
      const request = createMockRequest({ "cf-access-jwt-assertion": "invalid-token" });

      const result = await Effect.runPromise(
        Effect.either(
          authenticateRequest(request, {
            accessConfig: {
              teamDomain: "https://testteam.cloudflareaccess.com",
              audTag: "test-audience-tag",
            },
          }),
        ),
      );

      expect(Either.isLeft(result)).toBe(true);
      if (Either.isLeft(result)) {
        expect(result.left.code).toBe("INVALID_TOKEN");
        expect(result.left).toBeInstanceOf(InvalidTokenError);
      }
    });
  });

  describe("authenticateEither", () => {
    it("should return Left for failed authentication", async () => {
      const request = createMockRequest({});

      const result = await Effect.runPromise(
        authenticateEither(request, {
          accessConfig: {
            teamDomain: "https://testteam.cloudflareaccess.com",
            audTag: "test-audience-tag",
          },
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
    it("should return None for missing token", async () => {
      const request = createMockRequest({});

      const result = await Effect.runPromise(
        getUser(request, {
          accessConfig: {
            teamDomain: "https://testteam.cloudflareaccess.com",
            audTag: "test-audience-tag",
          },
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

  describe("skipInDev", () => {
    it("should skip auth in dev when skipInDev is true", async () => {
      const request = {
        url: "http://localhost:3000/protected",
        headers: {},
        method: "GET",
      } as unknown as HttpServerRequest.HttpServerRequest;

      const result = await Effect.runPromise(
        Effect.either(
          authenticateRequest(request, {
            accessConfig: {
              teamDomain: "https://testteam.cloudflareaccess.com",
              audTag: "test-audience-tag",
            },
            skipInDev: true,
            environment: "dev",
          }),
        ),
      );

      expect(Either.isRight(result)).toBe(true);
      if (Either.isRight(result)) {
        expect(result.right.email).toBe("dev@example.com");
      }
    });

    it("should require auth in production even with skipInDev", async () => {
      const request = createMockRequest({});

      const result = await Effect.runPromise(
        Effect.either(
          authenticateRequest(request, {
            accessConfig: {
              teamDomain: "https://testteam.cloudflareaccess.com",
              audTag: "test-audience-tag",
            },
            skipInDev: true,
            environment: "prod",
          }),
        ),
      );

      expect(Either.isLeft(result)).toBe(true);
    });
  });
});
