import { Schema } from "effect";
import { HttpApiSchema } from "@effect/platform";

/**
 * Unauthorized error schema for Effect Platform
 */
export class Unauthorized extends Schema.TaggedError<Unauthorized>()(
  "Unauthorized",
  {
    message: Schema.String,
    code: Schema.String,
  },
  HttpApiSchema.annotations({ status: 401 }),
) {}

/**
 * Forbidden error schema for Effect Platform
 */
export class Forbidden extends Schema.TaggedError<Forbidden>()(
  "Forbidden",
  {
    message: Schema.String,
    email: Schema.String,
  },
  HttpApiSchema.annotations({ status: 403 }),
) {}
