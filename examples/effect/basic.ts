import { Effect, Option, Console, pipe } from "effect";
import { authenticate, getUser, type CloudflareAccessContext } from "cloudflare-access/effect";

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
const safeProgram = Effect.gen(function* () {
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
  Effect.catchTag("AuthRequired", (error) =>
    Effect.gen(function* () {
      yield* Console.error(`Auth required: ${error.why}`);
      return null;
    }),
  ),
  Effect.catchTag("AccessDenied", (error) =>
    Effect.gen(function* () {
      yield* Console.error(`Access denied for ${error.email}`);
      return null;
    }),
  ),
  Effect.catchTag("InvalidToken", (error) =>
    Effect.gen(function* () {
      yield* Console.error(`Invalid token: ${error.why}`);
      return null;
    }),
  ),
);

// Run the program
Effect.runPromise(errorHandlingProgram).then(
  (result) => console.log("Result:", result),
  (error) => console.error("Error:", error),
);
