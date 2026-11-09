// How Vercel check modules are written: the same shape as Cloudflare's (see
// src/core/checks/define.ts), over a Vercel inventory.
//
//   export default defineChecks({
//     "VDP-001": { category: "Deployments", severity: "high", title: "…", why: "…", fix: "…", requires: ["projects"] },
//   }, ({ inv, d }, report) => {
//     for (const p of inv.projects) report("VDP-001", { resource: p.name, pass: … , link: d.project(p.name, "deployment-protection") });
//   });

import { checksFor } from "../../../core/checks/define.ts";
import type { EngineOptions } from "../../../core/types.ts";
import type { VercelSourceKey } from "../sources.ts";
import type { Related, VercelInventory } from "../types.ts";

export interface VercelContext {
  inv: VercelInventory;
  opts: EngineOptions;
  /** Links into the Vercel dashboard. */
  d: ReturnType<typeof dash>;
  /** Email domains that count as internal: the entity's domains, the team's email domain and every project domain. */
  org: Set<string>;
  /** What the entity's other providers know, for checks that span providers. */
  related: Related;
}

export const defineChecks = checksFor<VercelContext, VercelSourceKey>();

export function dash(inv: Pick<VercelInventory, "slug" | "personal">) {
  const base = `https://vercel.com/${inv.slug ?? ""}`;
  const team = (page: string) => (inv.personal ? `https://vercel.com/account/settings` : `${base}/~/settings/${page}`);
  return {
    team,
    members: team("members"),
    security: team("security"),
    domains: `${base}/~/domains`,
    drains: team("drains"),
    webhooks: team("webhooks"),
    tokens: "https://vercel.com/account/settings/tokens",
    project: (name: string, page = "") => `${base}/${encodeURIComponent(name)}/settings${page ? `/${page}` : ""}`,
    firewall: (name: string) => `${base}/${encodeURIComponent(name)}/firewall`,
  };
}

/** Names that usually hold a secret. Public keys meant for browsers (publishable, anon, site keys) are left out. */
const SECRET_NAME =
  /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_?KEY|_KEY$|^KEY$|CREDENTIAL|DATABASE_URL|POSTGRES_URL|REDIS_URL|MONGODB_URI|_DSN$|CONNECTION_STRING|SIGNING|SALT)/i;
const PUBLIC_NAME = /(PUBLISHABLE|ANON_KEY|SITE_KEY|PUBLIC_KEY|_ID$|_URL$(?<!DATABASE_URL|POSTGRES_URL|REDIS_URL))/i;
export const looksSecret = (key: string): boolean => SECRET_NAME.test(key) && !PUBLIC_NAME.test(key);

/** Prefixes that frameworks inline into the JavaScript sent to browsers. */
export const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|NUXT_ENV_|PUBLIC_|EXPO_PUBLIC_|GATSBY_|VUE_APP_|STORYBOOK_|SANITY_STUDIO_)/;

/** The plan, for checks that only apply where Vercel offers the feature. Personal accounts are Hobby. */
export const plan = (inv: VercelInventory): "hobby" | "pro" | "enterprise" => {
  const p = inv.team?.plan;
  return p === "enterprise" || p === "pro" ? p : "hobby";
};

/**
 * Credentials written straight into a command, by kind. A reference to a variable (`$NPM_TOKEN`,
 * `${TOKEN}`) is fine and doesn't match. Only the kind is ever reported, never the value.
 */
const LITERAL = String.raw`(?!\$)`;
export const SECRET_IN_TEXT: [string, RegExp][] = [
  ["an npm auth token", new RegExp(String.raw`_authToken=${LITERAL}[^\s'"]{8,}`)],
  ["a GitHub token", /\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/],
  ["an AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["a Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ["a Stripe secret key", /\b[sr]k_live_[A-Za-z0-9]{16,}/],
  ["a password in a URL", new RegExp(String.raw`[a-z][a-z0-9+.-]*://[^/\s:@]+:${LITERAL}[^@\s/]{3,}@`, "i")],
  ["a bearer token", new RegExp(String.raw`Bearer\s+${LITERAL}[A-Za-z0-9._~+/-]{20,}`)],
  ["a token passed on the command line", new RegExp(`--(token|password|api-key)[ =]${LITERAL}[A-Za-z0-9._-]{16,}`)],
];
export const secretKindIn = (text: string): string | null => SECRET_IN_TEXT.find(([, re]) => re.test(text))?.[0] ?? null;
