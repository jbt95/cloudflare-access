import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "adapters/hono/index": "src/adapters/hono/index.ts",
    "adapters/express/index": "src/adapters/express/index.ts",
    "adapters/fastify/index": "src/adapters/fastify/index.ts",
    "adapters/nestjs/index": "src/adapters/nestjs/index.ts",
    "adapters/effect/index": "src/adapters/effect/index.ts",
    "core/index": "src/core/index.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  splitting: true,
  sourcemap: true,
  minify: false,
  external: ["hono", "express", "@types/express", "fastify", "@nestjs/common", "effect", "jose"],
  noExternal: [],
});
