// Collects everything the checks need in one pass. Checks never call the API
// themselves, so a scan's data is consistent and the call count is predictable.
// Any single source failing is recorded in coverage and never fails the scan.
// Every Cloudflare read is a GET; analytics use read-only GraphQL queries.

import { type CloudflareClient, pool, doh, dohStats, type DohAnswer } from "./cloudflare.ts";
import { deepDns } from "./deep-dns.ts";
import { probeTakeovers, takeoverCandidates } from "./probe.ts";
import { accessLogins, dnsLookups, trafficTotals, zoneAnalytics } from "./analytics.ts";
import { isHostRecord, unquote } from "./dns-util.ts";
import { isoSeconds, DAY_MS } from "../shared/time.ts";
import type * as CF from "./cf-types.ts";
import type { Api, CollectOptions, Inventory, ProgressEvent, ZoneInventory } from "./types.ts";

export type ProgressFn = (e: ProgressEvent) => void;

/** Awaits an object of promises in parallel, keeping the names (no positional tuples). */
export async function collect<T extends Record<string, Promise<unknown>>>(tasks: T): Promise<{ [K in keyof T]: Awaited<T[K]> }> {
  const keys = Object.keys(tasks);
  const values = await Promise.all(Object.values(tasks));
  return Object.fromEntries(keys.map((k, i) => [k, values[i]])) as { [K in keyof T]: Awaited<T[K]> };
}

// Rule phases read beyond the WAF: configuration, transform, redirect, cache, origin and logging rules.
const EXTRA_PHASES = [
  "http_config_settings",
  "http_request_transform",
  "http_request_late_transform",
  "http_response_headers_transform",
  "http_request_dynamic_redirect",
  "http_request_cache_settings",
  "http_request_origin",
  "http_log_custom_fields",
];
// Phases Enterprise accounts can deploy across every zone at once.
const ACCOUNT_PHASES = ["http_request_firewall_managed", "http_request_firewall_custom", "http_ratelimit"];
const PAID = new Set(["pro", "business", "enterprise"]);
const BUSINESS = new Set(["business", "enterprise"]);

/**
 * Account-level rulesets answer 403 on plans that don't include them: that's "not set up". A token
 * missing the permission gets Cloudflare's "Authentication error" instead, which must stay unreadable,
 * or zones protected at account level would fail the WAF checks.
 */
const notEntitled = (status: number, message: string) => status === 403 && !/authentication error/i.test(message);

export async function collectInventory(
  cf: CloudflareClient,
  onProgress: ProgressFn = () => {},
  opts: CollectOptions = { probeTakeovers: false },
): Promise<Inventory> {
  const acc = cf.accountId;
  const now = Date.now();
  const accountPath = (path: string) => `/accounts/${acc}${path ? `/${path}` : ""}`;

  onProgress({ phase: "Reading account" });
  const a = await collect({
    zones: cf.list<Api>("zones", `/zones?account.id=${acc}`, { perPage: 50 }),
    members: cf.list<CF.Member>("members", accountPath("members"), { perPage: 50 }),
    account: cf.get<Api>("account", accountPath("")),
    accountTokens: cf.list<CF.AccountToken>("accountTokens", accountPath("tokens"), { perPage: 50, max: 1000 }),
    accessApps: cf.list<CF.AccessApp>("accessApps", accountPath("access/apps")),
    accessIdps: cf.list("accessIdps", accountPath("access/identity_providers")),
    accessOrg: cf.get<CF.AccessOrg>("accessOrg", accountPath("access/organizations")),
    accessGroups: cf.list<CF.AccessGroup>("accessGroups", accountPath("access/groups")),
    accessPolicies: cf.list<CF.AccessPolicy>("accessPolicies", accountPath("access/policies")),
    accessUsers: cf.list<CF.AccessUser>("accessUsers", accountPath("access/users"), { perPage: 100, max: 5000 }),
    serviceTokens: cf.list<CF.ServiceToken>("accessServiceTokens", accountPath("access/service_tokens")),
    tunnels: cf.list<CF.Tunnel>("tunnels", accountPath("cfd_tunnel?is_deleted=false")),
    deletedTunnels: cf.list<CF.Tunnel>("tunnels", accountPath("cfd_tunnel?is_deleted=true"), { max: 1000 }),
    privateRoutes: cf.list<CF.PrivateRoute>("privateRoutes", accountPath("teamnet/routes?is_deleted=false")),
    alertPolicies: cf.get<Api[]>("notifications", accountPath("alerting/v3/policies")),
    availableAlerts: cf.get<Record<string, Api[]>>("notifications", accountPath("alerting/v3/available_alerts")),
    webhooks: cf.get<CF.WebhookDestination[]>("notifications", accountPath("alerting/v3/destinations/webhooks")),
    workers: cf.get<Api[]>("workers", accountPath("workers/scripts")),
    workerDomains: cf.list<CF.WorkerDomain>("workerDomains", accountPath("workers/domains")),
    pages: cf.list<CF.PagesProject>("pages", accountPath("pages/projects"), { perPage: 10, max: 500 }),
    r2Buckets: cf.listCursor<Api>("r2", accountPath("r2/buckets"), { key: "buckets", absent: [/enable R2/i] }),
    subscriptions: cf.get<Api[]>("subscriptions", accountPath("subscriptions")),
    audit: cf.list<CF.AuditEntry>("auditLogs", accountPath(`audit_logs?since=${isoSeconds(now - 7 * DAY_MS)}&direction=desc`), { perPage: 1000, max: 20_000 }),
    devices: cf.list("devices", accountPath("devices"), { max: 200 }),
    deviceProfiles: cf.get<CF.DeviceProfile[]>("deviceProfiles", accountPath("devices/policies")),
    devicePosture: cf.get<Api[]>("devicePosture", accountPath("devices/posture")),
    gatewayRules: cf.list<CF.GatewayRule>("gatewayRules", accountPath("gateway/rules")),
    gatewayConfig: cf.getOptional<CF.GatewayConfig>("gatewayConfig", accountPath("gateway/configuration")),
    accountIpRules: cf.list<CF.IpAccessRule>("accountIpRules", accountPath("firewall/access_rules/rules"), { perPage: 100, max: 2000 }),
    mtlsCertificates: cf.get<CF.ExpiringCertificate[]>("mtlsCertificates", accountPath("mtls_certificates")),
    lbPools: cf.get<CF.LbPool[]>("lbPools", accountPath("load_balancers/pools")),
    accountRulesets: collect(
      Object.fromEntries(
        ACCOUNT_PHASES.map((ph) => [ph, cf.getOptional<CF.Ruleset>("accountRulesets", accountPath(`rulesets/phases/${ph}/entrypoint`), [notEntitled])]),
      ),
    ),
    insights: securityCenter(cf),
  });

  onProgress({ phase: "Reading Workers, Pages and R2" });
  const workerList = await pool(a.workers || [], 5, async (w: Api) => {
    const name = String(w.id);
    const s = await collect({
      subdomain: cf.get<{ enabled?: boolean; previews_enabled?: boolean }>("workers", accountPath(`workers/scripts/${encodeURIComponent(name)}/subdomain`)),
      settings: cf.get<{ bindings?: CF.WorkerBinding[] }>("workerSettings", accountPath(`workers/scripts/${encodeURIComponent(name)}/settings`)),
    });
    return { name, modified: w.modified_on, subdomain: s.subdomain, bindings: s.settings?.bindings ?? null };
  });
  const workersSubdomain = a.workers?.length ? await cf.get<{ subdomain?: string }>("workers", accountPath("workers/subdomain")) : null;
  const r2List = await pool(a.r2Buckets || [], 5, async (b) => {
    const name = String(b.name),
      path = `r2/buckets/${encodeURIComponent(name)}`;
    const r = await collect({
      managed: cf.get<{ enabled?: boolean; domain?: string }>("r2", accountPath(`${path}/domains/managed`)),
      cors: cf.getOptional<{ rules?: CF.R2CorsRule[] }>("r2", accountPath(`${path}/cors`)),
    });
    return { name, managed: r.managed, cors: r.cors?.rules ?? null };
  });

  // Remotely managed tunnels expose their routing (ingress) rules; locally managed ones return none.
  let tunnelIngress: Inventory["tunnelIngress"] = a.tunnels ? {} : null;
  if (a.tunnels) {
    const cfgs = await pool(a.tunnels, 5, (t) =>
      cf.get<{ config?: { ingress?: CF.IngressRule[] } }>("tunnelConfigs", accountPath(`cfd_tunnel/${t.id}/configurations`)),
    );
    if (cf.coverage.get("tunnelConfigs")?.ok === false) tunnelIngress = null;
    else
      a.tunnels.forEach((t, i) => {
        const ing = cfgs[i]?.config?.ingress;
        if (Array.isArray(ing)) tunnelIngress![t.id] = ing;
      });
  }

  const zoneList = a.zones || [];
  let zonesDone = 0;
  onProgress({ phase: "Reading zones", done: 0, total: zoneList.length });
  const zones = await pool(zoneList, 6, async (z) => {
    const out = await collectZone(cf, z);
    onProgress({ phase: "Reading zones", done: ++zonesDone, total: zoneList.length });
    return out;
  });

  onProgress({ phase: "Reading analytics" });
  const traffic = await trafficTotals(
    cf,
    zones.map((z) => z.id),
    now,
  );
  let analyticsDone = 0;
  await pool(zones, 4, async (z) => {
    z.lookups = await dnsLookups(cf, z, now);
    onProgress({ phase: "Reading DNS and security analytics", done: ++analyticsDone, total: zones.length });
  });
  await zoneAnalytics(cf, zones, now);
  const logins = await accessLogins(cf, now, (a.accessApps || []).length > 0);

  onProgress({ phase: "Resolving DNS targets" });
  dohStats.lookups = dohStats.failed = 0;
  const resolved = await resolveCnames(zones);
  const spfLookups = await spfLookupCounts(zones);
  const deep = await deepDns(zones);
  // A failed lookup reads as "no record", so when many fail (blocked egress, a proxy) the checks built on them are skipped.
  const dohBroken = dohStats.failed > 0 && dohStats.failed >= dohStats.lookups / 5;
  cf.note("doh", !dohBroken, dohBroken ? new Error(`${dohStats.failed} of ${dohStats.lookups} lookups to cloudflare-dns.com failed`) : undefined);

  let takeover: Inventory["takeover"] = null;
  if (opts.probeTakeovers) {
    const targets = takeoverCandidates(zones);
    onProgress({ phase: "Checking hostnames for takeover", done: 0, total: targets.length });
    takeover = await probeTakeovers(targets);
    cf.note("takeoverProbes", true);
  }

  return {
    accountId: acc,
    accountName: a.account?.name ?? null,
    unreadable: [...cf.coverage.values()].filter((c) => !c.ok).map((c) => c.key),
    now,
    zones,
    members: a.members,
    account: a.account,
    accountTokens: a.accountTokens,
    accessApps: a.accessApps,
    accessIdps: a.accessIdps,
    accessOrg: a.accessOrg,
    accessGroups: a.accessGroups,
    accessPolicies: a.accessPolicies,
    accessUsers: a.accessUsers,
    serviceTokens: a.serviceTokens,
    tunnels: a.tunnels,
    deletedTunnels: a.deletedTunnels,
    tunnelIngress,
    privateRoutes: a.privateRoutes,
    devices: a.devices,
    deviceProfiles: a.deviceProfiles,
    devicePosture: a.devicePosture,
    gatewayRules: a.gatewayRules,
    gatewayConfig: a.gatewayConfig ?? null,
    alertPolicies: a.alertPolicies,
    availableAlerts: a.availableAlerts,
    webhooks: a.webhooks,
    subscriptions: a.subscriptions,
    audit: a.audit,
    insights: a.insights,
    workers: workerList,
    workersSubdomain,
    workerDomains: a.workerDomains,
    pages: a.pages,
    r2: r2List,
    accountRulesets: a.accountRulesets,
    accountIpRules: a.accountIpRules,
    mtlsCertificates: a.mtlsCertificates,
    lbPools: a.lbPools,
    accessLogins: logins,
    traffic,
    resolved,
    spfLookups,
    deepDns: deep,
    takeover,
  };
}

async function collectZone(cf: CloudflareClient, z: Api): Promise<ZoneInventory> {
  const id = z.id;
  const plan: string = z.plan?.legacy_id || "free";
  const zonePath = (path: string) => `/zones/${id}/${path}`;
  // Reads for features a plan doesn't have are skipped rather than counted as permission gaps.
  const paid = PAID.has(plan),
    business = BUSINESS.has(plan);
  const skip = Promise.resolve(null);
  const r = await collect({
    settings: cf.get<Api[]>("zoneSettings", zonePath("settings")),
    dns: cf.list<CF.DnsRecord>("dnsRecords", zonePath("dns_records"), { perPage: 1000, max: 50_000 }),
    dnssec: cf.get<{ status: string }>("dnssec", zonePath("dnssec")),
    certPacks: cf.list<CF.CertificatePack>("certificates", zonePath("ssl/certificate_packs?status=all")),
    originCerts: cf.get<CF.OriginCertificate[]>("originCertificates", `/certificates?zone_id=${id}`),
    aop: cf.get<{ enabled?: boolean }>("originCertificates", zonePath("origin_tls_client_auth/settings")),
    aopHostnames: cf.get<CF.ExpiringCertificate[]>("originCertificates", zonePath("origin_tls_client_auth/hostnames/certificates")),
    customCerts: business ? cf.getOptional<CF.ExpiringCertificate[]>("tlsSettings", zonePath("custom_certificates"), [400]) : skip,
    clientCerts: cf.getOptional<CF.ExpiringCertificate[]>("tlsSettings", zonePath("client_certificates?per_page=50"), [400]),
    mtls: cf.getOptional<CF.MtlsAssociation>("tlsSettings", zonePath("certificate_authorities/hostname_associations"), [400]),
    hostnameMinTls: business ? cf.getOptional<CF.HostnameTlsSetting[]>("tlsSettings", zonePath("hostnames/settings/min_tls_version"), [400]) : skip,
    universalSsl: cf.get<{ enabled?: boolean }>("tlsSettings", zonePath("ssl/universal/settings")),
    totalTls: paid ? cf.getOptional<{ enabled?: boolean }>("tlsSettings", zonePath("acm/total_tls"), [400, 403]) : skip,
    bot: cf.get("bot", zonePath("bot_management")),
    wafManaged: cf.getOptional<CF.Ruleset>("wafRulesets", zonePath("rulesets/phases/http_request_firewall_managed/entrypoint")),
    wafCustom: cf.getOptional<CF.Ruleset>("wafRulesets", zonePath("rulesets/phases/http_request_firewall_custom/entrypoint")),
    rateLimit: cf.getOptional<CF.Ruleset>("wafRulesets", zonePath("rulesets/phases/http_ratelimit/entrypoint")),
    ddos: cf.getOptional<CF.Ruleset>("ddosRules", zonePath("rulesets/phases/ddos_l7/entrypoint")),
    phases: collect(
      Object.fromEntries(EXTRA_PHASES.map((ph) => [ph, cf.getOptional<CF.Ruleset>("otherRulesets", zonePath(`rulesets/phases/${ph}/entrypoint`))])),
    ),
    pageShield: cf.get<{ enabled?: boolean }>("pageShield", zonePath("page_shield")),
    leaked: cf.get<{ enabled?: boolean }>("leakedCredentials", zonePath("leaked-credential-checks")),
    pageRules: cf.get<Api[]>("pageRules", zonePath("pagerules")),
    workerRoutes: cf.get<Api[]>("workerRoutes", zonePath("workers/routes")),
    urlNormalization: cf.get<{ type?: string; scope?: string }>("urlNormalization", zonePath("url_normalization")),
    managedHeaders: cf.get<ZoneInventory["managedHeaders"]>("managedHeaders", zonePath("managed_headers")),
    ipRules: cf.list<CF.IpAccessRule>("firewallRules", zonePath("firewall/access_rules/rules"), { perPage: 100, max: 2000 }),
    spectrum: paid ? cf.getOptional<CF.SpectrumApp[]>("spectrum", zonePath("spectrum/apps"), [403]) : skip,
    loadBalancers: cf.get<CF.LoadBalancer[]>("loadBalancers", zonePath("load_balancers")),
    healthChecks: paid ? cf.getOptional<CF.HealthCheck[]>("healthChecks", zonePath("healthchecks"), [403]) : skip,
    emailCatchAll: cf.getOptional<CF.EmailCatchAll>("emailRouting", zonePath("email/routing/rules/catch_all")),
    schemaValidation: business
      ? cf.getOptional<ZoneInventory["schemaValidation"]>("apiShield", zonePath("api_gateway/settings/schema_validation"), [403])
      : skip,
  });
  // Page Shield's script list is only worth reading when monitoring is on.
  const pageShieldScripts = r.pageShield?.enabled
    ? await cf.list<CF.PageShieldScript>("pageShield", zonePath("page_shield/scripts?exclude_cdn_cgi=true"), { perPage: 100, max: 1000 })
    : null;
  return {
    id,
    name: z.name,
    status: z.status,
    paused: !!z.paused,
    plan,
    planName: z.plan?.name || "Free",
    planPrice: z.plan?.price || 0,
    settings: r.settings ? Object.fromEntries(r.settings.map((s: Api) => [s.id, s.value])) : null,
    dns: r.dns || [],
    dnsReadable: !!r.dns,
    dnssec: r.dnssec,
    certPacks: r.certPacks,
    bot: r.bot,
    wafManaged: r.wafManaged,
    wafCustom: r.wafCustom,
    rateLimit: r.rateLimit,
    ddos: r.ddos,
    phases: r.phases,
    pageShield: r.pageShield,
    pageShieldScripts,
    leaked: r.leaked,
    pageRules: r.pageRules,
    originCerts: r.originCerts,
    aop: r.aop,
    aopHostnames: r.aopHostnames,
    customCerts: r.customCerts ?? null,
    clientCerts: r.clientCerts ?? null,
    mtlsHostnames: r.mtls === undefined ? null : (r.mtls?.hostnames ?? []),
    hostnameMinTls: r.hostnameMinTls ?? null,
    universalSsl: r.universalSsl,
    totalTls: r.totalTls ?? null,
    workerRoutes: r.workerRoutes,
    urlNormalization: r.urlNormalization,
    managedHeaders: r.managedHeaders,
    ipRules: r.ipRules,
    spectrum: r.spectrum ?? null,
    loadBalancers: r.loadBalancers,
    healthChecks: r.healthChecks ?? null,
    emailCatchAll: r.emailCatchAll ?? null,
    schemaValidation: r.schemaValidation ?? null,
  };
}

async function securityCenter(cf: CloudflareClient): Promise<Api[] | null> {
  const out: Api[] = [];
  try {
    for (let page = 1; page <= 400; page++) {
      const body = await cf.raw(`/accounts/${cf.accountId}/security-center/insights?dismissed=false&per_page=25&page=${page}`);
      const issues: Api[] = body.result?.issues || [];
      out.push(...issues);
      if (issues.length === 0 || out.length >= (body.result?.count || 0)) break;
    }
    cf.note("securityCenter", true);
    return out;
  } catch (e) {
    cf.note("securityCenter", false, e);
    return null;
  }
}

// CNAME targets that are not supposed to resolve (validation and DKIM delegations) are skipped.
const NON_RESOLVING_TARGET = /(acm-validations\.aws|validate-domain\.mimecast\.com|dcv\.cloudflare\.com|\.dkim\.|domainkey|cfargotunnel\.com)\.?$/i;

async function resolveCnames(zones: ZoneInventory[]): Promise<Record<string, DohAnswer>> {
  const targets = new Set<string>();
  for (const z of zones)
    for (const r of z.dns) {
      if (r.type === "CNAME" && isHostRecord(r) && !NON_RESOLVING_TARGET.test(r.content)) targets.add(String(r.content).toLowerCase().replace(/\.$/, ""));
    }
  const list = [...targets];
  const res = await pool(list, 10, (t) => doh(t, "A"));
  return Object.fromEntries(list.map((t, i) => [t, res[i]]));
}

/** Counts DNS-querying SPF mechanisms (include, a, mx, ptr, exists, redirect), recursively. */
async function spfLookupCounts(zones: ZoneInventory[]): Promise<Record<string, number>> {
  const cache = new Map<string, Promise<DohAnswer>>();
  async function txt(name: string): Promise<string[]> {
    if (!cache.has(name)) cache.set(name, doh(name, "TXT"));
    const r = await cache.get(name)!;
    return r.answers.filter((a) => a.type === 16).map((a) => unquote(a.data));
  }
  async function count(record: string, depth: number): Promise<number> {
    if (depth > 10) return 99;
    let n = 0;
    for (const term of record.split(/\s+/).slice(1)) {
      // "a/24" and "mx:host/24" count as well: a CIDR suffix doesn't make the lookup free.
      const m = term.match(/^[+~?-]?(include|a|mx|ptr|exists|redirect)(?:[:=]([^/]+))?(?:\/\/?\d+){0,2}$/i);
      if (!m) continue;
      n++;
      const mech = m[1].toLowerCase();
      if ((mech === "include" || mech === "redirect") && m[2]) {
        const child = (await txt(m[2])).find((t) => t.toLowerCase().startsWith("v=spf1"));
        if (child) n += await count(child, depth + 1);
      }
    }
    return n;
  }
  const spf = zones.flatMap((z) =>
    z.dns
      .filter((r) => r.type === "TXT" && unquote(r.content).toLowerCase().startsWith("v=spf1"))
      .map((r) => ({ name: String(r.name).toLowerCase(), v: unquote(r.content) })),
  );
  // In parallel: one lookup at a time would take minutes on accounts with hundreds of zones.
  const counts = await pool(spf, 8, (r) => count(r.v, 0));
  return Object.fromEntries(spf.map((r, i) => [r.name, counts[i]]));
}
