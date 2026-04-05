import { describe, it, expect } from "bun:test";
import { CloudflareAccessGuard, IS_PUBLIC_KEY } from "cloudflare-access/nestjs";
import type { ExecutionContext } from "@nestjs/common";
import "reflect-metadata";

describe("NestJS adapter - CloudflareAccessGuard", () => {
  const teamDomain = "https://testteam.cloudflareaccess.com";
  const audTag = "test-audience-tag";

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

  describe("basic guard structure", () => {
    it("should create guard with config", () => {
      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
      });

      expect(guard).toBeDefined();
    });

    it("should create guard with email allowlist", () => {
      const guard = new CloudflareAccessGuard({
        accessConfig: { teamDomain, audTag },
        allowedEmails: ["admin@example.com"],
      });

      expect(guard).toBeDefined();
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

    it("should check auth for non-public routes (missing token)", async () => {
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
        // Should throw 401 for missing token
        expect(error.status).toBe(401);
      }
    });
  });

  describe("request without token", () => {
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

    it("should reject request with invalid JWT token format", async () => {
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
});
