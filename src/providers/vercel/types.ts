// What a Vercel scan collects: the fields checks read, typed from Vercel's OpenAPI
// description (openapi.vercel.sh). Payloads are trimmed when they're read, so the
// inventory never holds an environment variable's value, a drain's headers or a
// webhook secret.

import type { VercelSourceKey } from "./sources.ts";

/** Who a protection setting covers, in Vercel's words. */
export type DeploymentType = "all" | "all_except_custom_domains" | "preview" | "prod_deployment_urls_and_all_previews" | "production";

export type TeamRole = "OWNER" | "MEMBER" | "DEVELOPER" | "SECURITY" | "BILLING" | "VIEWER" | "VIEWER_FOR_PLUS" | "CONTRIBUTOR";

export interface VercelTeam {
  id: string;
  slug: string;
  name: string;
  plan: "hobby" | "pro" | "enterprise" | string | null;
  saml: { connected: boolean; enforced: boolean; directory: boolean } | null;
  sensitiveEnvPolicy: string | null;
  defaultProtection: { sso: DeploymentType | null; password: DeploymentType | null } | null;
  emailDomain: string | null;
  /** Whether members must use two-factor authentication; null when Vercel doesn't say. */
  mfaEnforced: boolean | null;
}

export interface VercelMember {
  uid: string;
  email: string | null;
  username: string | null;
  role: TeamRole | string;
  confirmed: boolean;
  createdAt: number | null;
  /** Joined through SAML SSO or directory sync. */
  viaSso: boolean;
  /** How they joined, in Vercel's words ("mail", "nsnb-request-access", "dsync"…). */
  joinedFrom: string | null;
}

export interface VercelInvite {
  email: string | null;
  role: TeamRole | string;
  createdAt: number | null;
  expired: boolean;
}

export interface VercelToken {
  id: string;
  name: string;
  createdAt: number | null;
  activeAt: number | null;
  expiresAt: number | null;
  leakedAt: number | null;
  leakedUrl: string | null;
  /** Teams the token reaches; empty when it reaches every team (Full Account). */
  teams: string[];
  fullAccount: boolean;
}

export interface VercelEnvVar {
  key: string;
  type: "encrypted" | "plain" | "secret" | "sensitive" | "system" | string;
  targets: string[];
  /** Problems Vercel itself flags ("readable-secret"). */
  issues: string[];
  /** Comes from an integration (a database, a store). */
  integration: boolean;
}

export interface FirewallConfig {
  enabled: boolean;
  /** False when the project has never been configured: Vercel's defaults apply (firewall on, managed rulesets off). */
  configured: boolean;
  /** Managed rulesets by Vercel's key: bot_filter (bot protection), ai_bots, owasp, vercel_ruleset. */
  managedRules: Record<string, { active: boolean; action: string | null }>;
  /** OWASP core ruleset categories (sqli, xss, rce…); null when the project has no firewall configuration. */
  crs: Record<string, { active: boolean; action: string | null }> | null;
  rules: { name: string; active: boolean; action: string | null }[];
  ips: { ip: string; action: string; hostname: string | null }[];
}

export interface VercelIntegration {
  slug: string;
  /** "all" when it reaches every project, now and future. */
  selection: string | null;
  projects: number;
  scopes: string[];
}

export interface VercelProject {
  id: string;
  name: string;
  framework: string | null;
  nodeVersion: string | null;
  createdAt: number | null;
  /** Git provider and repository, or null for projects deployed from the CLI. */
  git: { type: string; repo: string; productionBranch: string | null; deployHooks: number } | null;
  ssoProtection: DeploymentType | null;
  passwordProtection: DeploymentType | null;
  trustedIps: DeploymentType | null;
  /** Protection bypass secrets, by kind ("automation-bypass", "integration-automation-bypass"). */
  bypass: { scope: string; createdAt: number | null; note: string | null }[];
  gitForkProtection: boolean | null;
  directoryListing: boolean | null;
  autoExposeSystemEnvs: boolean | null;
  protectedSourcemaps: boolean | null;
  oidcIssuerMode: "global" | "team" | null;
  /** Days old previews stay reachable; null when deployments never expire. */
  previewRetentionDays: number | null;
  /** Firewall state from the project, used when the firewall configuration isn't readable. */
  firewallEnabled: boolean | null;
  domains: { name: string; verified: boolean; redirect: string | null; gitBranch: string | null }[] | null;
  env: VercelEnvVar[] | null;
  /** undefined: unreadable. Projects never configured get Vercel's defaults (configured: false). */
  firewall: FirewallConfig | undefined;
  /** Build, install, dev and ignore commands, held in memory only for the secret scan, never stored. */
  commands: { field: string; command: string }[];
  /** Cron job paths and schedules. */
  crons: { path: string; schedule: string }[];
  /** When the current production deployment was created; null when there is none. */
  productionDeployedAt: number | null;
}

export interface VercelDomain {
  name: string;
  verified: boolean;
  /** Bought through Vercel: renewal is Vercel's job. */
  registrar: boolean;
  renew: boolean | null;
  expiresAt: number | null;
  nameservers: string[];
}

export interface VercelCert {
  id: string;
  names: string[];
  expiresAt: number | null;
  autoRenew: boolean;
}

export interface VercelDrain {
  id: string;
  name: string;
  type: string;
  /** Only the scheme and host: a drain URL can carry a secret. */
  endpoint: string | null;
  s3Acl: string | null;
  disabled: boolean;
  erroring: boolean;
  projects: string[];
}

export interface VercelWebhook {
  id: string;
  /** Only the scheme and host. */
  endpoint: string;
  events: string[];
}

export interface VercelInventory {
  accountId: string;
  accountName: string | null;
  /** The team slug, or the username of a personal account: the first part of dashboard URLs. */
  slug: string | null;
  /** Personal (Hobby) accounts have no team, members or SAML. */
  personal: boolean;
  now: number;
  unreadable: VercelSourceKey[];
  team: VercelTeam | null;
  members: VercelMember[] | null;
  invites: VercelInvite[] | null;
  tokens: VercelToken[] | null;
  projects: VercelProject[];
  domains: VercelDomain[] | null;
  certs: VercelCert[] | null;
  drains: VercelDrain[] | null;
  webhooks: VercelWebhook[] | null;
  integrations: VercelIntegration[] | null;
  /** Team-wide environment variables shared with several projects. */
  sharedEnv: VercelEnvVar[] | null;
}

export type { Related } from "../../core/types.ts";
