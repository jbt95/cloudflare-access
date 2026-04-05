import { Context } from "effect";
import type { CloudflareAccessUser } from "../../core/index";

/**
 * Context Tag for the authenticated user.
 * Use this to access the current user in your handlers.
 *
 * @example
 * ```typescript
 * import { Effect } from "effect";
 * import { CurrentUser } from "cloudflare-access/effect";
 *
 * const handler = Effect.gen(function* () {
 *   const user = yield* CurrentUser;
 *   console.log(`Hello ${user.email}`);
 *   return user;
 * });
 * ```
 */
export class CurrentUser extends Context.Tag("cloudflare-access/CurrentUser")<
  CurrentUser,
  CloudflareAccessUser
>() {}
