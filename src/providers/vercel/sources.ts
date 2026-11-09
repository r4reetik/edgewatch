// Every Vercel data source a scan reads. Like Cloudflare's registry (src/core/sources.ts),
// each source has a coverage label, what grants it, and an optional probe for the
// setup screen. Vercel tokens can't be limited to reading: a token can do what its
// creator's team role allows, so `permission` names the role that can read it.

export interface VercelSource {
  label: string;
  /** Who can read it, as Vercel's team roles describe it. */
  permission: string;
  /** A cheap request that proves the token can read this source, for a team ID (setup screen). */
  probe?: (team: VercelScope) => string;
  /** Only teams have it: a personal account skips it instead of reporting a gap. */
  teamOnly?: boolean;
}

/** A team ID, or null for the token owner's personal account. */
export type VercelScope = string | null;

const ANY_ROLE = "Any team role (Viewer or higher)";

const DEFS = {
  team: { label: "Team settings", permission: ANY_ROLE, probe: (t) => (t ? `/v2/teams/${t}` : "/v2/user"), teamOnly: false },
  members: { label: "Team members and invitations", permission: ANY_ROLE, probe: (t) => `/v3/teams/${t}/members?limit=1`, teamOnly: true },
  tokens: {
    label: "Your access tokens",
    // Vercel answers 400 to a team-scoped token here; only a Full Account token can list tokens.
    permission: "A Full Account token (a token scoped to one team can't list tokens)",
    probe: () => "/v6/user/tokens?limit=1",
  },
  projects: { label: "Projects", permission: ANY_ROLE, probe: () => "/v10/projects?limit=1" },
  env: { label: "Environment variable names and types", permission: "Developer, Member or Owner" },
  projectDomains: { label: "Project domains", permission: ANY_ROLE },
  firewall: { label: "Firewall configuration", permission: "Developer, Member, Security or Owner" },
  domains: { label: "Domains", permission: ANY_ROLE, probe: () => "/v5/domains?limit=1" },
  certs: { label: "Custom certificates", permission: ANY_ROLE, probe: () => "/v8/certs" },
  drains: { label: "Drains", permission: "Member or Owner", probe: () => "/v1/drains" },
  webhooks: { label: "Webhooks", permission: "Member or Owner", probe: () => "/v1/webhooks" },
  integrations: { label: "Installed integrations", permission: ANY_ROLE, probe: () => "/v1/integrations/configurations?view=account" },
  sharedEnv: { label: "Shared environment variable names and types", permission: "Developer, Member or Owner", probe: () => "/v1/env?limit=1", teamOnly: true },
} satisfies Record<string, VercelSource>;

export type VercelSourceKey = keyof typeof DEFS;
export const VERCEL_SOURCES: Record<VercelSourceKey, VercelSource> = DEFS;
export const VERCEL_SOURCE_KEYS = Object.keys(DEFS) as VercelSourceKey[];
