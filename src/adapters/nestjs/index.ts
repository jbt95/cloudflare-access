import {
  type CanActivate,
  type ExecutionContext,
  type ModuleMetadata,
  type Type,
  Injectable,
  SetMetadata,
  UnauthorizedException,
  ForbiddenException,
  applyDecorators,
  UseGuards,
} from "@nestjs/common";
import type { Request } from "express";
import {
  type CloudflareAccessConfig,
  type CloudflareAccessMiddlewareEnv,
  type CloudflareAccessUser,
  validateCloudflareAccessToken,
  getCloudflareAccessConfigFromEnv as _getCloudflareAccessConfigFromEnv,
  __clearJwksCache,
} from "../../core/auth";

export {
  type CloudflareAccessConfig,
  type CloudflareAccessUser,
  type CloudflareAccessPayload,
  type CloudflareAccessMiddlewareEnv,
  // Error classes
  CloudflareAccessError,
  AuthRequiredError,
  InvalidTokenError,
  AccessDeniedError,
  ConfigurationError,
  // Error codes
  CloudflareAccessErrorCode,
  // Type guards
  isCloudflareAccessError,
  isAuthRequiredError,
  isInvalidTokenError,
  isAccessDeniedError,
  isConfigurationError,
  toAuthError,
  __clearJwksCache,
} from "../../core/auth";

declare module "express" {
  interface Request {
    user?: CloudflareAccessUser;
  }
}

/**
 * Get Cloudflare Access configuration from environment variables
 */
export function getCloudflareAccessConfigFromEnv(
  env: CloudflareAccessMiddlewareEnv,
): CloudflareAccessConfig {
  return _getCloudflareAccessConfigFromEnv(env);
}

/**
 * Metadata key for public routes
 */
export const IS_PUBLIC_KEY = "cfAccessPublic";

/**
 * Decorator to mark a route as public (skip auth)
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

/**
 * Options for Cloudflare Access Guard
 */
export interface CloudflareAccessGuardOptions {
  /** Cloudflare Access configuration */
  accessConfig: CloudflareAccessConfig;

  /** Optional email allowlist. Access policy should still be configured at Cloudflare. */
  allowedEmails?: string[];

  /** Whether to skip JWT validation outside production */
  skipInDev?: boolean;

  /** Environment indicator */
  environment?: string;
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
    const path = request.url;

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

/**
 * Decorator to apply Cloudflare Access authentication to a route or controller.
 *
 * @example
 * ```typescript
 * import { Controller, Get } from '@nestjs/common';
 * import { CloudflareAccess, Public } from 'cloudflare-access/adapters/nestjs';
 *
 * @Controller('api')
 * @CloudflareAccess({
 *   accessConfig: {
 *     teamDomain: 'https://yourteam.cloudflareaccess.com',
 *     audTag: 'your-audience-tag',
 *   },
 * })
 * export class ApiController {
 *   @Get('protected')
 *   getProtected(@Req() req: Request) {
 *     return { email: req.user?.email };
 *   }
 *
 *   @Public()
 *   @Get('public')
 *   getPublic() {
 *     return { message: 'This is public' };
 *   }
 * }
 * ```
 */
export function CloudflareAccess(options: CloudflareAccessGuardOptions) {
  return applyDecorators(UseGuards(new CloudflareAccessGuard(options)));
}

/**
 * Interface for async options for Cloudflare Access module
 */
export interface CloudflareAccessModuleAsyncOptions extends Pick<ModuleMetadata, "imports"> {
  useExisting?: Type<{
    createCloudflareAccessOptions():
      | Promise<CloudflareAccessGuardOptions>
      | CloudflareAccessGuardOptions;
  }>;
  useClass?: Type<{
    createCloudflareAccessOptions():
      | Promise<CloudflareAccessGuardOptions>
      | CloudflareAccessGuardOptions;
  }>;
  useFactory?: (
    ...args: any[]
  ) => Promise<CloudflareAccessGuardOptions> | CloudflareAccessGuardOptions;
  inject?: any[];
}
