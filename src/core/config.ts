import { type CloudflareAccessConfig, type CloudflareAccessMiddlewareEnv } from "./types";
import { ConfigurationError } from "./errors";

/**
 * Remove trailing slashes from team domain
 */
function normalizeTeamDomain(teamDomain: string): string {
  return teamDomain.replace(/\/+$/, "");
}

/**
 * Validate and normalize access configuration
 */
export function validateAccessConfig(
  config: CloudflareAccessConfig,
  requestUrl?: string,
): CloudflareAccessConfig {
  const teamDomain = normalizeTeamDomain(config.teamDomain);

  if (!teamDomain.startsWith("https://") || !teamDomain.endsWith(".cloudflareaccess.com")) {
    throw new ConfigurationError(`Invalid Cloudflare Access team domain: ${config.teamDomain}`, {
      context: { requestUrl, expectedFormat: "https://<team>.cloudflareaccess.com" },
    });
  }

  if (!config.audTag) {
    throw new ConfigurationError("Missing Cloudflare Access audience tag", {
      context: {
        requestUrl,
        expectedFormat: "Application AUD tag from Cloudflare Access dashboard",
      },
    });
  }

  return { teamDomain, audTag: config.audTag };
}

/**
 * Get Cloudflare Access configuration from environment variables/bindings
 */
export function getCloudflareAccessConfigFromEnv(
  env: CloudflareAccessMiddlewareEnv,
): CloudflareAccessConfig {
  const teamDomain = env.CF_ACCESS_TEAM_DOMAIN;
  const audTag = env.CF_ACCESS_AUD;

  if (!teamDomain || !audTag) {
    const missing = [!teamDomain && "CF_ACCESS_TEAM_DOMAIN", !audTag && "CF_ACCESS_AUD"]
      .filter(Boolean)
      .join(" and ");

    throw new ConfigurationError(`Missing Cloudflare Access bindings: ${missing}`, {
      context: {
        expectedFormat:
          "CF_ACCESS_TEAM_DOMAIN=https://<team>.cloudflareaccess.com, CF_ACCESS_AUD=<audience-tag>",
      },
    });
  }

  return { teamDomain, audTag };
}
