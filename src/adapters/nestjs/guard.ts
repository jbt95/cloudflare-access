import type { CanActivate, ExecutionContext } from "@nestjs/common";
import { Injectable, UnauthorizedException, ForbiddenException } from "@nestjs/common";
import type { Request } from "express";
import { validateCloudflareAccessToken } from "../../core";
import type { CloudflareAccessGuardOptions } from "./types";
import { IS_PUBLIC_KEY } from "./constants";

declare module "express" {
  interface Request {
    user?: import("../../core").CloudflareAccessUser;
  }
}

/**
 * NestJS Guard for Cloudflare Access authentication.
 *
 * @example
 * ```typescript
 * import { Module } from '@nestjs/common';
 * import { APP_GUARD } from '@nestjs/core';
 * import { CloudflareAccessGuard } from 'cloudflare-access/adapters/nestjs';
 *
 * @Module({
 *   providers: [
 *     {
 *       provide: APP_GUARD,
 *       useFactory: () => new CloudflareAccessGuard({
 *         accessConfig: {
 *           teamDomain: 'https://yourteam.cloudflareaccess.com',
 *           audTag: 'your-audience-tag',
 *         },
 *       }),
 *     },
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
@Injectable()
export class CloudflareAccessGuard implements CanActivate {
  private readonly allowedEmails: string[] | null;

  constructor(private readonly options: CloudflareAccessGuardOptions) {
    this.allowedEmails = options.allowedEmails ?? null;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.isPublicRoute(context);
    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const method = request.method;

    // Skip OPTIONS requests
    if (method === "OPTIONS") {
      return true;
    }

    const protocol = request.headers["x-forwarded-proto"] || "http";
    const host = request.headers.host;
    const url = `${protocol}://${host}${request.originalUrl}`;

    const token = request.headers["cf-access-jwt-assertion"] as string | undefined;

    const result = await validateCloudflareAccessToken(
      token,
      {
        accessConfig: this.options.accessConfig,
        allowedEmails: this.allowedEmails ?? undefined,
        skipInDev: this.options.skipInDev,
        environment: this.options.environment,
      },
      url,
    );

    if (!result.success) {
      if (result.error?.code === "ACCESS_DENIED") {
        throw new ForbiddenException(result.error.message);
      }
      throw new UnauthorizedException(result.error?.message ?? "Authentication required");
    }

    if (result.user) {
      request.user = result.user;
    }

    return true;
  }

  private isPublicRoute(context: ExecutionContext): boolean {
    const isPublic = Reflect.getMetadata(IS_PUBLIC_KEY, context.getHandler());
    if (isPublic) {
      return true;
    }
    const isClassPublic = Reflect.getMetadata(IS_PUBLIC_KEY, context.getClass());
    return isClassPublic ?? false;
  }
}
