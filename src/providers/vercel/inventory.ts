// One Vercel scan's reads: the team, its members and invitations, the token owner's
// access tokens, every project with its domains, environment variable names and
// firewall, and the team's domains, certificates, drains and webhooks.
//
// Secrets never enter the inventory: environment variables are listed without
// `decrypt` and their values are dropped, and only the scheme and host of drain and
// webhook URLs are kept.

import type { VercelClient, Json } from "./client.ts";
import type {
  DeploymentType,
  FirewallConfig,
  VercelCert,
  VercelDomain,
  VercelDrain,
  VercelEnvVar,
  VercelIntegration,
  VercelInventory,
  VercelInvite,
  VercelMember,
  VercelProject,
  VercelTeam,
  VercelToken,
  VercelWebhook,
} from "./types.ts";
import type { ProgressEvent } from "../../core/types.ts";

const PROJECT_CONCURRENCY = 4;

export async function collectVercel(client: VercelClient, onProgress: (p: ProgressEvent) => void = () => {}): Promise<VercelInventory> {
  const personal = !client.team;
  onProgress({ phase: personal ? "Reading the account" : "Reading the team" });
  const [teamBody, memberBody, tokenBody] = await Promise.all([
    personal ? client.get("team", "/v2/user") : client.get("team", `/v2/teams/${client.team}`),
    personal ? Promise.resolve(null) : readMembers(client),
    client.get("tokens", "/v6/user/tokens"),
  ]);
  const team = personal ? null : teamBody ? toTeam(teamBody) : null;
  const accountName = personal ? (teamBody?.user?.name ?? teamBody?.user?.username ?? null) : (teamBody?.name ?? null);
  const slug = personal ? (teamBody?.user?.username ?? null) : (teamBody?.slug ?? null);

  onProgress({ phase: "Reading projects" });
  const rawProjects = (await client.list("projects", "/v10/projects", "projects")) ?? [];
  const projects: VercelProject[] = [];
  let done = 0;
  await pool(rawProjects, PROJECT_CONCURRENCY, async (p: Json) => {
    const [domains, env, firewall] = await Promise.all([
      client.list("projectDomains", `/v9/projects/${encodeURIComponent(p.id)}/domains`, "domains"),
      client.get("env", `/v10/projects/${encodeURIComponent(p.id)}/env`),
      client.getOptional("firewall", `/v1/security/firewall/config/active?projectId=${encodeURIComponent(p.id)}`),
    ]);
    projects.push(toProject(p, domains, env, firewall));
    onProgress({ phase: "Reading projects", done: ++done, total: rawProjects.length });
  });
  projects.sort((a, b) => a.name.localeCompare(b.name));

  onProgress({ phase: "Reading domains, certificates, drains and integrations" });
  const [domains, certs, drains, webhooks, integrations, sharedEnv] = await Promise.all([
    client.list("domains", "/v5/domains", "domains"),
    client.get("certs", "/v8/certs"),
    client.get("drains", "/v1/drains"),
    client.get("webhooks", "/v1/webhooks"),
    client.get("integrations", "/v1/integrations/configurations?view=account"),
    personal ? Promise.resolve(null) : client.list("sharedEnv", "/v1/env", "data"),
  ]);

  // A personal account has no members to read, so that source is never noted and isn't a gap.
  const unreadable = [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key);

  return {
    accountId: client.team ?? String(teamBody?.user?.id ?? ""),
    accountName,
    slug,
    personal,
    now: Date.now(),
    unreadable,
    team,
    members: memberBody?.members ?? null,
    invites: memberBody?.invites ?? null,
    tokens: tokenBody ? toTokens(tokenBody, client.team) : null,
    projects,
    domains: domains ? domains.map(toDomain) : null,
    certs: certs ? (certs.certs ?? []).map(toCert) : null,
    drains: drains ? ((Array.isArray(drains) ? drains : drains.drains) ?? []).map(toDrain) : null,
    webhooks: webhooks ? (Array.isArray(webhooks) ? webhooks : []).map(toWebhook) : null,
    integrations: integrations ? (Array.isArray(integrations) ? integrations : []).map(toIntegration) : null,
    sharedEnv: sharedEnv ? sharedEnv.map(toEnv) : null,
  };
}

async function readMembers(client: VercelClient): Promise<{ members: VercelMember[]; invites: VercelInvite[] } | null> {
  const members: VercelMember[] = [];
  let invites: VercelInvite[] = [];
  try {
    let until: number | null = null;
    do {
      const body: Json = await client.raw(`/v3/teams/${client.team}/members?limit=100${until != null ? `&until=${until}` : ""}`);
      members.push(...(body.members ?? []).map(toMember));
      if (until == null) invites = (body.emailInviteCodes ?? []).map(toInvite);
      until = body.pagination?.hasNext ? (body.pagination?.next ?? null) : null;
    } while (until != null && members.length < 10_000);
    client.note("members", true);
    return { members, invites };
  } catch (e) {
    client.note("members", false, e);
    return null;
  }
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const deploymentType = (v: Json): DeploymentType | null => str(v?.deploymentType) as DeploymentType | null;

/** "https://logs.example.com/ingest?key=…" -> "https://logs.example.com". Drain and webhook URLs can carry secrets. */
export function originOf(u: unknown): string | null {
  if (typeof u !== "string") return null;
  try {
    const x = new URL(u);
    return `${x.protocol}//${x.host}`;
  } catch {
    return null;
  }
}

function toTeam(t: Json): VercelTeam {
  return {
    id: String(t.id),
    slug: String(t.slug ?? ""),
    name: String(t.name ?? t.slug ?? t.id),
    plan: str(t.billing?.plan),
    saml: t.saml
      ? { connected: !!t.saml.connection, enforced: !!t.saml.enforced, directory: !!t.saml.directory }
      : { connected: false, enforced: false, directory: false },
    sensitiveEnvPolicy: str(t.sensitiveEnvironmentVariablePolicy),
    defaultProtection: t.defaultDeploymentProtection
      ? { sso: deploymentType(t.defaultDeploymentProtection.ssoProtection), password: deploymentType(t.defaultDeploymentProtection.passwordProtection) }
      : null,
    emailDomain: str(t.emailDomain),
    mfaEnforced: typeof t.mfa?.enforced === "boolean" ? t.mfa.enforced : null,
  };
}

function toMember(m: Json): VercelMember {
  const origin = m.joinedFrom?.origin;
  return {
    uid: String(m.uid),
    email: str(m.email),
    username: str(m.username),
    role: String(m.role ?? ""),
    confirmed: m.confirmed !== false,
    createdAt: num(m.createdAt),
    viaSso: origin === "dsync" || !!m.joinedFrom?.ssoUserId || !!m.joinedFrom?.dsyncUserId,
    joinedFrom: str(origin),
  };
}

function toInvite(i: Json): VercelInvite {
  return { email: str(i.email), role: String(i.role ?? ""), createdAt: num(i.createdAt), expired: !!i.expired };
}

function toTokens(body: Json, team: string | null): VercelToken[] {
  const list: Json[] = Array.isArray(body?.tokens) ? body.tokens : [];
  return list
    .filter((t) => !t.revokedAt)
    .map((t): VercelToken => {
      const scopes: Json[] = Array.isArray(t.scopes) ? t.scopes : [];
      const teams = scopes.filter((s) => s.type === "team" && s.teamId).map((s) => String(s.teamId));
      return {
        id: String(t.id),
        name: String(t.name ?? t.id),
        createdAt: num(t.createdAt),
        activeAt: num(t.activeAt),
        expiresAt: num(t.expiresAt),
        leakedAt: num(t.leakedAt),
        leakedUrl: str(t.leakedUrl),
        teams,
        fullAccount: scopes.some((s) => s.type === "user") || !scopes.length,
      };
    })
    .filter((t) => (team ? t.fullAccount || t.teams.includes(team) : t.fullAccount));
}

function toEnv(e: Json): VercelEnvVar {
  const target = e.target;
  return {
    key: String(e.key ?? ""),
    type: String(e.type ?? ""),
    targets: Array.isArray(target) ? target.map(String) : target ? [String(target)] : [],
    issues: Array.isArray(e.securityIssues) ? e.securityIssues.map(String) : [],
    integration: !!(e.configurationId || e.contentHint),
  };
}

const rulesetMap = (o: unknown): Record<string, { active: boolean; action: string | null }> => {
  const out: Record<string, { active: boolean; action: string | null }> = {};
  for (const [k, v] of Object.entries((o ?? {}) as Record<string, Json>)) out[k] = { active: !!v?.active, action: str(v?.action) };
  return out;
};

/**
 * The firewall as Vercel applies it. Managed rulesets live on the project (`security.managedRules`); the
 * firewall configuration holds custom rules, IP rules and the OWASP core ruleset (`crs`). A project that was
 * never configured has neither (the configuration answers 404): Vercel's defaults apply, firewall on and
 * managed rulesets off.
 */
function toFirewall(project: Json, config: Json): FirewallConfig {
  return {
    enabled: config ? config.firewallEnabled !== false : project.security?.firewallEnabled !== false,
    configured: !!config || !!project.security,
    managedRules: { ...rulesetMap(config?.managedRules), ...rulesetMap(project.security?.managedRules) },
    crs: config?.crs ? rulesetMap(config.crs) : null,
    rules: (Array.isArray(config?.rules) ? config.rules : []).map((r: Json) => ({
      name: String(r.name ?? r.id ?? ""),
      active: !!r.active,
      action: str(r.action?.mitigate?.action),
    })),
    ips: (Array.isArray(config?.ips) ? config.ips : []).map((i: Json) => ({
      ip: String(i.ip ?? ""),
      action: String(i.action ?? ""),
      hostname: str(i.hostname),
    })),
  };
}

const COMMAND_FIELDS = ["buildCommand", "installCommand", "devCommand", "commandForIgnoringBuildStep"] as const;

function toIntegration(i: Json): VercelIntegration {
  return {
    slug: String(i.slug ?? i.integrationId ?? i.id),
    selection: str(i.projectSelection),
    projects: Array.isArray(i.projects) ? i.projects.length : 0,
    scopes: Array.isArray(i.scopes) ? i.scopes.map(String) : [],
  };
}

function toProject(p: Json, domains: Json[] | null, envBody: Json, firewall: Json): VercelProject {
  const link = p.link;
  const envs: Json[] | null =
    envBody == null ? null : Array.isArray(envBody) ? envBody : Array.isArray(envBody.envs) ? envBody.envs : envBody.key ? [envBody] : [];
  const exp = p.deploymentExpiration;
  return {
    id: String(p.id),
    name: String(p.name ?? p.id),
    framework: str(p.framework),
    nodeVersion: str(p.nodeVersion),
    createdAt: num(p.createdAt),
    git: link?.type
      ? {
          type: String(link.type),
          // GitHub links name the org and repo separately; GitLab and Bitbucket carry the full path.
          repo: String(link.projectNameWithNamespace ?? (link.org && link.repo ? `${link.org}/${link.repo}` : (link.repo ?? link.slug ?? link.name ?? ""))),
          productionBranch: str(link.productionBranch),
          deployHooks: Array.isArray(link.deployHooks) ? link.deployHooks.length : 0,
        }
      : null,
    ssoProtection: deploymentType(p.ssoProtection),
    passwordProtection: deploymentType(p.passwordProtection),
    trustedIps: deploymentType(p.trustedIps),
    bypass: Object.values((p.protectionBypass ?? {}) as Record<string, Json>).map((b) => ({
      scope: String(b?.scope ?? ""),
      createdAt: num(b?.createdAt),
      note: str(b?.note),
    })),
    gitForkProtection: typeof p.gitForkProtection === "boolean" ? p.gitForkProtection : null,
    directoryListing: typeof p.directoryListing === "boolean" ? p.directoryListing : null,
    autoExposeSystemEnvs: typeof p.autoExposeSystemEnvs === "boolean" ? p.autoExposeSystemEnvs : null,
    protectedSourcemaps: typeof p.protectedSourcemaps === "boolean" ? p.protectedSourcemaps : null,
    oidcIssuerMode: p.oidcTokenConfig?.enabled === false ? null : (str(p.oidcTokenConfig?.issuerMode) as VercelProject["oidcIssuerMode"]),
    previewRetentionDays: num(exp?.expirationDays),
    firewallEnabled: typeof p.security?.firewallEnabled === "boolean" ? p.security.firewallEnabled : null,
    domains: domains
      ? domains.map((d: Json) => ({ name: String(d.name), verified: d.verified !== false, redirect: str(d.redirect), gitBranch: str(d.gitBranch) }))
      : null,
    env: envs ? envs.map(toEnv) : null,
    firewall: firewall === undefined ? undefined : toFirewall(p, firewall),
    commands: COMMAND_FIELDS.filter((f) => typeof p[f] === "string" && p[f]).map((f) => ({ field: f, command: String(p[f]) })),
    crons: (Array.isArray(p.crons?.definitions) ? p.crons.definitions : []).map((c: Json) => ({
      path: String(c.path ?? ""),
      schedule: String(c.schedule ?? ""),
    })),
    productionDeployedAt: num(p.targets?.production?.createdAt),
  };
}

function toDomain(d: Json): VercelDomain {
  return {
    name: String(d.name),
    verified: d.verified !== false,
    registrar: !!d.boughtAt,
    renew: typeof d.renew === "boolean" ? d.renew : null,
    expiresAt: num(d.expiresAt),
    nameservers: Array.isArray(d.nameservers) ? d.nameservers.map(String) : [],
  };
}

function toCert(c: Json): VercelCert {
  return { id: String(c.id), names: Array.isArray(c.cns) ? c.cns.map(String) : [], expiresAt: num(c.expiresAt), autoRenew: !!c.autoRenew };
}

function toDrain(d: Json): VercelDrain {
  const delivery = d.delivery ?? {};
  const endpoint = typeof delivery.endpoint === "string" ? delivery.endpoint : (delivery.endpoint?.traces ?? delivery.endpoint?.url ?? d.url);
  return {
    id: String(d.id),
    name: String(d.name ?? d.id),
    type: String(delivery.type ?? d.deliveryFormat ?? "http"),
    endpoint: originOf(endpoint),
    s3Acl: str(delivery.objectAcl),
    disabled: !!d.disabledAt,
    erroring: !!d.firstErrorTimestamp && !d.disabledAt,
    projects: Array.isArray(d.projectIds) ? d.projectIds.map(String) : [],
  };
}

function toWebhook(w: Json): VercelWebhook {
  return { id: String(w.id), endpoint: originOf(w.url) ?? "", events: Array.isArray(w.events) ? w.events.map(String) : [] };
}

async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) await fn(items[next++]);
    }),
  );
}
