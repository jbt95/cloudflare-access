import {
  SetMetadata,
  type ModuleMetadata,
  type Type,
  applyDecorators,
  UseGuards,
} from "@nestjs/common";
import { CloudflareAccessGuard } from "./guard";
import type { CloudflareAccessGuardOptions } from "./types";
import { IS_PUBLIC_KEY } from "./constants";
export { IS_PUBLIC_KEY } from "./constants";

/**
 * Decorator to mark a route as public (skip auth)
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

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
