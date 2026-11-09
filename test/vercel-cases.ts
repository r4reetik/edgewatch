// A well-configured Vercel team, and one failing case per Vercel check. The type is
// Record<VercelCheckId, …>, so a new check without a case doesn't compile, and
// test/vercel-checks.test.ts asserts each case really makes its check fail.

import type { VercelCheckId } from "../src/providers/vercel/checks/index.ts";
import type { EngineOptions } from "../src/core/types.ts";
import type { VercelInventory, VercelProject } from "../src/providers/vercel/types.ts";

export const NOW = Date.parse("2026-06-01T00:00:00Z");
const days = (n: number) => NOW + n * 86_400_000;

export function project(extra: Partial<VercelProject> = {}): VercelProject {
  return {
    id: "prj_1",
    name: "web",
    framework: "nextjs",
    nodeVersion: "22.x",
    createdAt: days(-100),
    git: { type: "github", repo: "web", productionBranch: "main", deployHooks: 0 },
    ssoProtection: "all_except_custom_domains",
    passwordProtection: null,
    trustedIps: null,
    bypass: [],
    gitForkProtection: true,
    directoryListing: false,
    autoExposeSystemEnvs: true,
    protectedSourcemaps: true,
    oidcIssuerMode: "team",
    previewRetentionDays: 90,
    firewallEnabled: true,
    domains: [{ name: "app.example.com", verified: true, redirect: null, gitBranch: null }],
    env: [
      { key: "DATABASE_URL", type: "sensitive", targets: ["production"], issues: [], integration: false },
      { key: "CRON_SECRET", type: "sensitive", targets: ["production"], issues: [], integration: false },
      { key: "NEXT_PUBLIC_SITE_URL", type: "plain", targets: ["production", "preview"], issues: [], integration: false },
    ],
    firewall: {
      enabled: true,
      configured: true,
      managedRules: { bot_filter: { active: true, action: "challenge" }, ai_bots: { active: true, action: "deny" }, owasp: { active: true, action: "deny" } },
      crs: { sqli: { active: true, action: "deny" }, xss: { active: true, action: "deny" } },
      rules: [{ name: "Rate limit sign-in", active: true, action: "rate_limit" }],
      ips: [{ ip: "203.0.113.7", action: "bypass", hostname: null }],
    },
    commands: [{ field: "installCommand", command: "npm config set //registry.npmjs.org/:_authToken=$NPM_TOKEN && npm ci" }],
    crons: [{ path: "/api/cron/cleanup", schedule: "0 3 * * *" }],
    productionDeployedAt: days(-10),
    ...extra,
  };
}

export function vercelInventory(extra: Partial<VercelInventory> = {}): VercelInventory {
  return {
    accountId: "team_test0000000000000001",
    accountName: "Example",
    slug: "example",
    personal: false,
    now: NOW,
    unreadable: [],
    team: {
      id: "team_test0000000000000001",
      slug: "example",
      name: "Example",
      plan: "enterprise",
      saml: { connected: true, enforced: true, directory: true },
      sensitiveEnvPolicy: "on",
      defaultProtection: { sso: "all_except_custom_domains", password: null },
      emailDomain: "example.com",
      mfaEnforced: true,
    },
    members: [
      { uid: "u1", email: "a@example.com", username: "a", role: "OWNER", confirmed: true, createdAt: days(-300), viaSso: true, joinedFrom: "mail" },
      { uid: "u2", email: "b@example.com", username: "b", role: "DEVELOPER", confirmed: true, createdAt: days(-200), viaSso: true, joinedFrom: "mail" },
    ],
    invites: [],
    tokens: [
      {
        id: "t1",
        name: "edgewatch",
        createdAt: days(-10),
        activeAt: days(-1),
        expiresAt: days(300),
        leakedAt: null,
        leakedUrl: null,
        teams: ["team_test0000000000000001"],
        fullAccount: false,
      },
    ],
    projects: [project()],
    domains: [{ name: "example.com", verified: true, registrar: true, renew: true, expiresAt: days(200), nameservers: [] }],
    certs: [],
    drains: [{ id: "d1", name: "logs", type: "http", endpoint: "https://logs.example.com", s3Acl: null, disabled: false, erroring: false, projects: [] }],
    webhooks: [{ id: "w1", endpoint: "https://hooks.example.com", events: ["deployment.created"] }],
    integrations: [{ slug: "slack", selection: "selected", projects: 1, scopes: ["read:project", "read-write:integration-configuration"] }],
    sharedEnv: [],
    ...extra,
  };
}

const withProject = (extra: Partial<VercelProject>) => vercelInventory({ projects: [project(extra)] });
const withEnv = (key: string, type: string, targets = ["production"], extra: Partial<VercelProject["env"] & object>[number] | object = {}) =>
  withProject({ env: [{ key, type, targets, issues: [], integration: false, ...extra }] });
const fw = project().firewall!;
const withFirewall = (extra: Partial<typeof fw>) => withProject({ firewall: { ...fw, ...extra } });
const base = vercelInventory();

export const VERCEL_CASES: Record<VercelCheckId, () => VercelInventory> = {
  "VID-001": () => vercelInventory({ team: { ...base.team!, saml: { connected: true, enforced: false, directory: true } } }),
  "VID-002": () =>
    vercelInventory({
      members: [1, 2, 3, 4].map((i) => ({
        uid: `u${i}`,
        email: `o${i}@example.com`,
        username: `o${i}`,
        role: "OWNER",
        confirmed: true,
        createdAt: days(-100),
        viaSso: true,
        joinedFrom: "mail",
      })),
    }),
  "VID-003": () =>
    vercelInventory({
      members: [
        ...base.members!,
        { uid: "x", email: "x@gmail.com", username: "x", role: "MEMBER", confirmed: true, createdAt: days(-5), viaSso: false, joinedFrom: "mail" },
      ],
    }),
  "VID-004": () => vercelInventory({ invites: [{ email: "late@example.com", role: "DEVELOPER", createdAt: days(-40), expired: false }] }),
  "VID-005": () => vercelInventory({ tokens: [{ ...base.tokens![0], leakedAt: days(-2), leakedUrl: "https://github.com/x/y" }] }),
  "VID-006": () => vercelInventory({ tokens: [{ ...base.tokens![0], expiresAt: null }] }),
  "VID-007": () => vercelInventory({ tokens: [{ ...base.tokens![0], activeAt: days(-120) }] }),
  "VID-008": () => vercelInventory({ team: { ...base.team!, mfaEnforced: false } }),
  "VID-009": () => vercelInventory({ integrations: [{ slug: "acme-ci", selection: "all", projects: 0, scopes: ["read-write:project", "read:team"] }] }),

  "VDP-001": () => withProject({ ssoProtection: null }),
  "VDP-002": () => withProject({ ssoProtection: "preview" }),
  "VDP-003": () => withProject({ gitForkProtection: false }),
  "VDP-004": () => withProject({ bypass: [{ scope: "automation-bypass", createdAt: days(-10), note: null }] }),
  "VDP-005": () => withProject({ git: { ...project().git!, deployHooks: 2 } }),
  "VDP-006": () => withProject({ previewRetentionDays: null }),
  "VDP-007": () => vercelInventory({ team: { ...base.team!, defaultProtection: null } }),
  "VDP-008": () => withProject({ env: project().env!.filter((e) => e.key !== "CRON_SECRET") }),

  "VEN-001": () => withEnv("SESSION_SECRET", "encrypted", ["production"], { issues: ["readable-secret"] }),
  "VEN-002": () => withEnv("CMS_TOKEN", "plain"),
  "VEN-003": () => withEnv("NEXT_PUBLIC_STRIPE_SECRET_KEY", "sensitive"),
  "VEN-004": () => withEnv("STRIPE_SECRET_KEY", "encrypted"),
  "VEN-005": () => withEnv("STRIPE_SECRET_KEY", "sensitive", ["production", "preview"]),
  "VEN-006": () => vercelInventory({ team: { ...base.team!, sensitiveEnvPolicy: "off" } }),
  "VEN-007": () => withEnv("STRIPE_SECRET_KEY", "encrypted", ["production", "development"]),
  "VEN-008": () =>
    withProject({
      commands: [{ field: "installCommand", command: "npm config set //registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789 && npm ci" }],
    }),

  "VFW-001": () => withProject({ firewall: { ...fw, enabled: false } }),
  "VFW-002": () => withFirewall({ managedRules: { ...fw.managedRules, bot_filter: { active: false, action: null } } }),
  "VFW-003": () => withFirewall({ managedRules: { ...fw.managedRules, ai_bots: { active: false, action: "deny" } } }),
  "VFW-004": () =>
    withFirewall({
      managedRules: { ...fw.managedRules, owasp: { active: false, action: null } },
      crs: { sqli: { active: true, action: "log" }, xss: { active: true, action: "log" } },
    }),
  "VFW-005": () => withFirewall({ rules: [...fw.rules, { name: "Try blocking bots", active: true, action: "log" }] }),
  "VFW-006": () => withFirewall({ ips: [{ ip: "10.0.0.0/8", action: "bypass", hostname: null }] }),
  "VFW-007": () => withFirewall({ rules: [] }),

  "VDM-001": () => vercelInventory({ domains: [{ ...base.domains![0], renew: false, expiresAt: days(10) }] }),
  "VDM-002": () => withProject({ domains: [{ name: "shop.example.com", verified: false, redirect: null, gitBranch: null }] }),
  "VDM-003": () => vercelInventory({ certs: [{ id: "c1", names: ["legacy.example.com"], expiresAt: days(5), autoRenew: false }] }),

  "VMN-001": () => vercelInventory({ drains: [] }),
  "VMN-002": () => vercelInventory({ drains: [{ ...base.drains![0], type: "s3", endpoint: null, s3Acl: "public-read" }] }),
  "VMN-003": () => vercelInventory({ drains: [{ ...base.drains![0], endpoint: "http://logs.example.com" }] }),
  "VMN-004": () => vercelInventory({ drains: [{ ...base.drains![0], erroring: true }] }),

  "VPL-001": () => withProject({ nodeVersion: "18.x" }),
  "VPL-002": () => withProject({ directoryListing: true }),
  "VPL-003": () => withProject({ protectedSourcemaps: false }),
  "VPL-004": () => withProject({ oidcIssuerMode: "global" }),
  "VPL-005": () => withProject({ git: null }),
  "VPL-006": () => withProject({ productionDeployedAt: days(-400) }),

  "XP-003": () => withProject({ ssoProtection: "preview" }),
};

/** Engine options a case needs beyond the defaults. */
export const VERCEL_CASE_OPTS: Partial<Record<VercelCheckId, Partial<EngineOptions>>> = {
  "XP-003": {
    related: {
      toVercel: [{ host: "app.example.com", zone: "example.com", type: "CNAME", target: "cname.vercel-dns.com", proxied: true }],
      vercelDomains: null,
    },
  },
};
