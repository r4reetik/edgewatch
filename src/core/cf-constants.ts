// Cloudflare identifiers and name patterns used across checks and views.

/** Ruleset IDs of the managed rulesets Cloudflare publishes. */
export const RULESET = {
  cloudflareManaged: "efb7b8c949ac4650a09736fc376e9aee",
  owasp: "4814384a9e5d4991b9815dcfc25d2f1f",
  leakedCredentials: "c2e184081120413c86c3ab7e14069605",
} as const;

export const rulesetName = (id: string | undefined): string =>
  id === RULESET.owasp ? "OWASP Core Ruleset" : id === RULESET.cloudflareManaged ? "Cloudflare Managed Ruleset" : "Managed ruleset";

/** A CNAME to a Cloudflare Tunnel: <tunnel id>.cfargotunnel.com (trailing dot allowed). */
export const TUNNEL_CNAME = /^([0-9a-f-]{36})\.cfargotunnel\.com\.?$/i;

/** Security levels that let practically everything through. */
export const WEAK_SECURITY_LEVELS = ["off", "essentially_off", "low"];
/** TLS versions below 1.2. */
export const OLD_TLS = ["1.0", "1.1"];
