// Collects everything the checks need in one pass. Checks never call the API
// themselves, so a scan's data is consistent and the call count is predictable.
// Any single source failing is recorded in coverage and never fails the scan.
// Every Cloudflare read is a GET; analytics use read-only GraphQL queries.

import { type CloudflareClient, pool, doh, type DohAnswer } from "./cloudflare.ts";
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

export async function collectInventory(
  cf: CloudflareClient,
  onProgress: ProgressFn = () => {},
  opts: CollectOptions = { probeTakeovers: false },
): Promise<Inventory> {
  const acc = cf.accountId;
  const now = Date.now();
  const A = (path: string) => `/accounts/${acc}${path ? `/${path}` : ""}`;

  onProgress({ phase: "Reading account" });
  const a = await collect({
    zones: cf.list<Api>("zones", `/zones?account.id=${acc}`, { perPage: 50 }),
    members: cf.list<CF.Member>("members", A("members"), { perPage: 50 }),
    account: cf.get<Api>("account", A("")),
    accountTokens: cf.list<CF.AccountToken>("accountTokens", A("tokens"), { perPage: 50, max: 1000 }),
    accessApps: cf.list<CF.AccessApp>("accessApps", A("access/apps")),
    accessIdps: cf.list("accessIdps", A("access/identity_providers")),
    accessOrg: cf.get<CF.AccessOrg>("accessOrg", A("access/organizations")),
    accessGroups: cf.list<CF.AccessGroup>("accessGroups", A("access/groups")),
    accessPolicies: cf.list<CF.AccessPolicy>("accessPolicies", A("access/policies")),
    accessUsers: cf.list<CF.AccessUser>("accessUsers", A("access/users"), { perPage: 100, max: 5000 }),
    serviceTokens: cf.list<CF.ServiceToken>("accessServiceTokens", A("access/service_tokens")),
    tunnels: cf.list<CF.Tunnel>("tunnels", A("cfd_tunnel?is_deleted=false")),
    deletedTunnels: cf.list<CF.Tunnel>("tunnels", A("cfd_tunnel?is_deleted=true"), { max: 1000 }),
    privateRoutes: cf.list<CF.PrivateRoute>("privateRoutes", A("teamnet/routes?is_deleted=false")),
    alertPolicies: cf.get<Api[]>("notifications", A("alerting/v3/policies")),
    availableAlerts: cf.get<Record<string, Api[]>>("notifications", A("alerting/v3/available_alerts")),
    webhooks: cf.get<CF.WebhookDestination[]>("notifications", A("alerting/v3/destinations/webhooks")),
    workers: cf.get<Api[]>("workers", A("workers/scripts")),
    workerDomains: cf.list<CF.WorkerDomain>("workerDomains", A("workers/domains")),
    pages: cf.list<CF.PagesProject>("pages", A("pages/projects"), { perPage: 10, max: 500 }),
    r2: cf.getOptional<{ buckets?: Api[] }>("r2", A("r2/buckets"), [/enable R2/i]),
    subscriptions: cf.get<Api[]>("subscriptions", A("subscriptions")),
    audit: cf.get<CF.AuditEntry[]>("auditLogs", A(`audit_logs?since=${isoSeconds(now - 7 * DAY_MS)}&per_page=1000&direction=desc`)),
    devices: cf.list("devices", A("devices"), { max: 200 }),
    deviceProfiles: cf.get<CF.DeviceProfile[]>("deviceProfiles", A("devices/policies")),
    devicePosture: cf.get<Api[]>("devicePosture", A("devices/posture")),
    gatewayRules: cf.list<CF.GatewayRule>("gatewayRules", A("gateway/rules")),
    gatewayConfig: cf.getOptional<CF.GatewayConfig>("gatewayConfig", A("gateway/configuration")),
    accountIpRules: cf.list<CF.IpAccessRule>("accountIpRules", A("firewall/access_rules/rules"), { perPage: 100, max: 2000 }),
    mtlsCertificates: cf.get<CF.ExpiringCertificate[]>("mtlsCertificates", A("mtls_certificates")),
    lbPools: cf.get<CF.LbPool[]>("lbPools", A("load_balancers/pools")),
    accountRulesets: collect(
      Object.fromEntries(ACCOUNT_PHASES.map((ph) => [ph, cf.getOptional<CF.Ruleset>("accountRulesets", A(`rulesets/phases/${ph}/entrypoint`), [403])])),
    ),
    insights: securityCenter(cf),
  });

  onProgress({ phase: "Reading Workers, Pages and R2" });
  const workerList = await pool(a.workers || [], 5, async (w: Api) => {
    const name = String(w.id);
    const s = await collect({
      subdomain: cf.get<{ enabled?: boolean; previews_enabled?: boolean }>("workers", A(`workers/scripts/${encodeURIComponent(name)}/subdomain`)),
      settings: cf.get<{ bindings?: CF.WorkerBinding[] }>("workerSettings", A(`workers/scripts/${encodeURIComponent(name)}/settings`)),
    });
    return { name, modified: w.modified_on, subdomain: s.subdomain, bindings: s.settings?.bindings ?? null };
  });
  const workersSubdomain = a.workers?.length ? await cf.get<{ subdomain?: string }>("workers", A("workers/subdomain")) : null;
  const r2List = await pool((a.r2?.buckets || []) as Api[], 5, async (b) => {
    const name = String(b.name),
      path = `r2/buckets/${encodeURIComponent(name)}`;
    const r = await collect({
      managed: cf.get<{ enabled?: boolean; domain?: string }>("r2", A(`${path}/domains/managed`)),
      cors: cf.getOptional<{ rules?: CF.R2CorsRule[] }>("r2", A(`${path}/cors`)),
    });
    return { name, managed: r.managed, cors: r.cors?.rules ?? null };
  });

  // Remotely managed tunnels expose their routing (ingress) rules; locally managed ones return none.
  let tunnelIngress: Inventory["tunnelIngress"] = a.tunnels ? {} : null;
  if (a.tunnels) {
    const cfgs = await pool(a.tunnels, 5, (t) => cf.get<{ config?: { ingress?: CF.IngressRule[] } }>("tunnelConfigs", A(`cfd_tunnel/${t.id}/configurations`)));
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
  const resolved = await resolveCnames(zones);
  const spfLookups = await spfLookupCounts(zones);
  const deep = await deepDns(zones);
  cf.note("doh", true);

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
  const Z = (path: string) => `/zones/${id}/${path}`;
  // Reads for features a plan doesn't have are skipped rather than counted as permission gaps.
  const paid = PAID.has(plan),
    business = BUSINESS.has(plan);
  const skip = Promise.resolve(null);
  const r = await collect({
    settings: cf.get<Api[]>("zoneSettings", Z("settings")),
    dns: cf.list<CF.DnsRecord>("dnsRecords", Z("dns_records"), { perPage: 1000, max: 50_000 }),
    dnssec: cf.get<{ status: string }>("dnssec", Z("dnssec")),
    certPacks: cf.list<CF.CertificatePack>("certificates", Z("ssl/certificate_packs?status=all")),
    originCerts: cf.get<CF.OriginCertificate[]>("originCertificates", `/certificates?zone_id=${id}`),
    aop: cf.get<{ enabled?: boolean }>("originCertificates", Z("origin_tls_client_auth/settings")),
    aopHostnames: cf.get<CF.ExpiringCertificate[]>("originCertificates", Z("origin_tls_client_auth/hostnames/certificates")),
    customCerts: business ? cf.getOptional<CF.ExpiringCertificate[]>("tlsSettings", Z("custom_certificates"), [400]) : skip,
    clientCerts: cf.getOptional<CF.ExpiringCertificate[]>("tlsSettings", Z("client_certificates?per_page=50"), [400]),
    mtls: cf.getOptional<CF.MtlsAssociation>("tlsSettings", Z("certificate_authorities/hostname_associations"), [400]),
    hostnameMinTls: business ? cf.getOptional<CF.HostnameTlsSetting[]>("tlsSettings", Z("hostnames/settings/min_tls_version"), [400]) : skip,
    universalSsl: cf.get<{ enabled?: boolean }>("tlsSettings", Z("ssl/universal/settings")),
    totalTls: paid ? cf.getOptional<{ enabled?: boolean }>("tlsSettings", Z("acm/total_tls"), [400, 403]) : skip,
    bot: cf.get("bot", Z("bot_management")),
    wafManaged: cf.getOptional<CF.Ruleset>("wafRulesets", Z("rulesets/phases/http_request_firewall_managed/entrypoint")),
    wafCustom: cf.getOptional<CF.Ruleset>("wafRulesets", Z("rulesets/phases/http_request_firewall_custom/entrypoint")),
    rateLimit: cf.getOptional<CF.Ruleset>("wafRulesets", Z("rulesets/phases/http_ratelimit/entrypoint")),
    ddos: cf.getOptional<CF.Ruleset>("ddosRules", Z("rulesets/phases/ddos_l7/entrypoint")),
    phases: collect(Object.fromEntries(EXTRA_PHASES.map((ph) => [ph, cf.getOptional<CF.Ruleset>("otherRulesets", Z(`rulesets/phases/${ph}/entrypoint`))]))),
    pageShield: cf.get<{ enabled?: boolean }>("pageShield", Z("page_shield")),
    leaked: cf.get<{ enabled?: boolean }>("leakedCredentials", Z("leaked-credential-checks")),
    pageRules: cf.get<Api[]>("pageRules", Z("pagerules")),
    workerRoutes: cf.get<Api[]>("workerRoutes", Z("workers/routes")),
    urlNormalization: cf.get<{ type?: string; scope?: string }>("urlNormalization", Z("url_normalization")),
    managedHeaders: cf.get<ZoneInventory["managedHeaders"]>("managedHeaders", Z("managed_headers")),
    ipRules: cf.list<CF.IpAccessRule>("firewallRules", Z("firewall/access_rules/rules"), { perPage: 100, max: 2000 }),
    spectrum: paid ? cf.getOptional<CF.SpectrumApp[]>("spectrum", Z("spectrum/apps"), [403]) : skip,
    loadBalancers: cf.get<CF.LoadBalancer[]>("loadBalancers", Z("load_balancers")),
    healthChecks: paid ? cf.getOptional<CF.HealthCheck[]>("healthChecks", Z("healthchecks"), [403]) : skip,
    emailCatchAll: cf.getOptional<CF.EmailCatchAll>("emailRouting", Z("email/routing/rules/catch_all")),
    schemaValidation: business ? cf.getOptional<ZoneInventory["schemaValidation"]>("apiShield", Z("api_gateway/settings/schema_validation"), [403]) : skip,
  });
  // Page Shield's script list is only worth reading when monitoring is on.
  const pageShieldScripts = r.pageShield?.enabled
    ? await cf.list<CF.PageShieldScript>("pageShield", Z("page_shield/scripts?exclude_cdn_cgi=true"), { perPage: 100, max: 1000 })
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
      const m = term.match(/^[+~?-]?(include|a|mx|ptr|exists|redirect)(?:[:=](.+))?$/i);
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
  const out: Record<string, number> = {};
  for (const z of zones)
    for (const r of z.dns) {
      if (r.type !== "TXT") continue;
      const v = unquote(r.content);
      if (v.toLowerCase().startsWith("v=spf1")) out[String(r.name).toLowerCase()] = await count(v, 0);
    }
  return out;
}
