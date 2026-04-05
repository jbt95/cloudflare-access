import type { FastifyPluginAsync } from "fastify";
import type { CloudflareAccessAuthOptions } from "./types";
import { cloudflareAccessPreHandler } from "./middleware";

/**
 * Creates a Fastify plugin for Cloudflare Access authentication.
 *
 * @param options - Configuration options
 * @returns Fastify plugin
 *
 * @example
 * ```typescript
 * import fastify from 'fastify';
 * import { cloudflareAccessPlugin } from 'cloudflare-access/adapters/fastify';
 *
 * const app = fastify();
 *
 * app.register(cloudflareAccessPlugin, {
 *   accessConfig: {
 *     teamDomain: 'https://yourteam.cloudflareaccess.com',
 *     audTag: 'your-audience-tag',
 *   },
 * });
 *
 * app.get('/protected', async (request, reply) => {
 *   return { email: request.user?.email };
 * });
 * ```
 */
export const cloudflareAccessPlugin: FastifyPluginAsync<CloudflareAccessAuthOptions> = async (
  fastify,
  options,
) => {
  fastify.addHook("preHandler", cloudflareAccessPreHandler(options));
};

// Also export as default for convenience
export default cloudflareAccessPlugin;
