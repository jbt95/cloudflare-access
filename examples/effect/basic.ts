import { Effect, Option, Console, pipe } from "effect";
import {
  authenticate,
  getUser,
  type CloudflareAccessContext,
  isAuthRequiredError,
  isAccessDeniedError,
  isInvalidTokenError,
  CloudflareAccessError,
} from "cloudflare-access/effect";

// Example: Authenticate a request
const program = Effect.gen(function* () {
  // Simulate request context
  const context: CloudflareAccessContext = {
    token: Option.some("cf-jwt-token-here"),
    requestUrl: "https://example.com/api",
  };

  // Authenticate
  const result = yield* authenticate(context, {
    accessConfig: {
      teamDomain: "https://yourteam.cloudflareaccess.com",
      audTag: "your-audience-tag",
    },
  });

  yield* Console.log(`Authenticated user: ${result.user?.email}`);
  return result.user;
});

// Example: Get user or null (safe version)
const _safeProgram = Effect.gen(function* () {
  const context: CloudflareAccessContext = {
    token: Option.some("cf-jwt-token-here"),
    requestUrl: "https://example.com/api",
  };

  const user = yield* getUser(context, {
    accessConfig: {
      teamDomain: "https://yourteam.cloudflareaccess.com",
      audTag: "your-audience-tag",
    },
  });

  if (Option.isSome(user)) {
    yield* Console.log(`User: ${user.value.email}`);
  } else {
    yield* Console.log("No authenticated user");
  }

  return user;
});

// Example: Handling errors
const errorHandlingProgram = pipe(
  program,
  Effect.catchAll((error: CloudflareAccessError) =>
    Effect.gen(function* () {
      if (isAuthRequiredError(error)) {
        yield* Console.error(`Auth required: ${error.message}`);
      } else if (isAccessDeniedError(error)) {
        yield* Console.error(`Access denied for ${error.email}`);
      } else if (isInvalidTokenError(error)) {
        yield* Console.error(`Invalid token: ${error.reason}`);
      } else {
        yield* Console.error(`Unknown error: ${error.message}`);
      }
      return null;
    }),
  ),
);

// Run the program
Effect.runPromise(errorHandlingProgram).then(
  (result) => console.log("Result:", result),
  (error) => console.error("Error:", error),
);
