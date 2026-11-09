// The platforms Edgewatch scans. Every account belongs to exactly one provider, and
// an entity can hold accounts from several. Adding a provider starts here; see
// "Adding a provider" in CONTRIBUTING.md for the rest.

export const PROVIDERS = ["cloudflare", "vercel"] as const;
export type ProviderId = (typeof PROVIDERS)[number];

export interface ProviderInfo {
  id: ProviderId;
  label: string;
  /** What the provider calls an account, singular and plural ("account", "team"). */
  account: string;
  accounts: string;
  /** What one scanned resource is called in the provider's inventory page. */
  resource: string;
}

export const PROVIDER_INFO: Record<ProviderId, ProviderInfo> = {
  cloudflare: { id: "cloudflare", label: "Cloudflare", account: "account", accounts: "accounts", resource: "zone" },
  vercel: { id: "vercel", label: "Vercel", account: "team", accounts: "teams", resource: "project" },
};

export const isProvider = (v: unknown): v is ProviderId => typeof v === "string" && (PROVIDERS as readonly string[]).includes(v);

/** Account IDs as each provider issues them: Cloudflare's are 32 hex characters, Vercel's are team or user IDs. */
export const ACCOUNT_ID_PATTERN: Record<ProviderId, RegExp> = {
  cloudflare: /^[0-9a-f]{32}$/,
  vercel: /^(team_)?[A-Za-z0-9]{8,40}$/,
};

/** The provider an account ID can belong to, judged by its shape. */
export const providerForId = (id: string): ProviderId | null => PROVIDERS.find((p) => ACCOUNT_ID_PATTERN[p].test(id)) ?? null;
