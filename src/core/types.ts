// Shapes the scanner passes around: the inventory a scan collects, and the
// results checks produce. Cloudflare payloads are typed in cf-types.ts; `Api`
// remains for the few that checks barely read.

import type * as CF from "./cf-types.ts";
import type { Category } from "./categories.ts";
import type { SourceKey } from "./sources.ts";
import type { Severity } from "../shared/severity.ts";
import type { Confidence, Evidence, EvidenceStep, ProviderLinks } from "../shared/api.ts";

export type Api = any;
export type { Severity, Confidence, Evidence, EvidenceStep, Category };
export type Source = "custom" | "security_center";

export interface CoverageEntry {
  key: SourceKey;
  label: string;
  permission: string;
  ok: boolean;
  status?: number;
  message?: string;
}

/** `undefined` = unreadable, `null` = not configured (no entrypoint, 404). */
export type Optional<T> = T | null | undefined;

export interface ZoneInventory {
  id: string;
  name: string;
  status: string;
  paused: boolean;
  plan: "free" | "pro" | "business" | "enterprise" | string;
  planName: string;
  planPrice: number;
  settings: CF.ZoneSettings | null;
  dns: CF.DnsRecord[];
  dnsReadable: boolean;
  dnssec: { status: string } | null;
  certPacks: CF.CertificatePack[] | null;
  bot: Api | null;
  wafManaged: Optional<CF.Ruleset>;
  wafCustom: Optional<CF.Ruleset>;
  rateLimit: Optional<CF.Ruleset>;
  /** Rule phases beyond the WAF, by phase name. */
  phases: Record<string, Optional<CF.Ruleset>>;
  /** The HTTP DDoS managed ruleset's entrypoint (overrides live here). */
  ddos: Optional<CF.Ruleset>;
  pageShield: { enabled?: boolean } | null;
  pageShieldScripts: CF.PageShieldScript[] | null;
  leaked: { enabled?: boolean } | null;
  pageRules: Api[] | null;
  originCerts: CF.OriginCertificate[] | null;
  /** Zone-level Authenticated Origin Pulls setting. */
  aop: { enabled?: boolean } | null;
  /** Per-hostname Authenticated Origin Pulls certificates. */
  aopHostnames: CF.ExpiringCertificate[] | null;
  customCerts: CF.ExpiringCertificate[] | null;
  clientCerts: CF.ExpiringCertificate[] | null;
  /** Hostnames with mTLS (client certificate) checking turned on. */
  mtlsHostnames: string[] | null;
  hostnameMinTls: CF.HostnameTlsSetting[] | null;
  universalSsl: { enabled?: boolean } | null;
  totalTls: { enabled?: boolean } | null;
  workerRoutes: Api[] | null;
  urlNormalization: { type?: string; scope?: string } | null;
  managedHeaders: { managed_request_headers?: { id: string; enabled: boolean }[]; managed_response_headers?: { id: string; enabled: boolean }[] } | null;
  ipRules: CF.IpAccessRule[] | null;
  spectrum: CF.SpectrumApp[] | null;
  loadBalancers: CF.LoadBalancer[] | null;
  healthChecks: CF.HealthCheck[] | null;
  emailCatchAll: CF.EmailCatchAll | null;
  schemaValidation: { validation_default_mitigation_action?: string; validation_override_mitigation_action?: string | null } | null;
  /** Sampled DNS lookups per hostname over 30 days; null when analytics are unreadable. */
  lookups?: Record<string, number> | null;
  /** Security signals from GraphQL analytics; null when unreadable. */
  analytics?: ZoneAnalytics | null;
}

/** What a zone's traffic showed over the analytics window. Lists are null when the plan can't query them. */
export interface ZoneAnalytics {
  from: string;
  to: string;
  days: number;
  /** Fields the zone's plan doesn't expose (for coverage notes). Any list below is null when it couldn't be read, never empty. */
  unavailable: string[];
  /** Requests answered 200 on paths that usually hold secrets or debug data. */
  sensitive: { host: string; path: string; contentType: string; count: number }[] | null;
  /** Requests a security rule matched but only logged, by the product that matched. */
  logOnly: { source: string; count: number }[] | null;
  /** The most requested hostnames. */
  hosts: { host: string; count: number }[] | null;
  oldTls: { host: string; protocol: string; count: number }[] | null;
  plainHttp: { host: string; count: number }[] | null;
  leakedLogins: { host: string; path: string; result: string; status: number; count: number }[] | null;
  attacksPassed: { host: string; path: string; count: number }[] | null;
  botsPassed: { host: string; path: string; count: number }[] | null;
  /** Security events per rule ID over the window; null when the window is too short to judge dead rules. */
  ruleHits: Record<string, number> | null;
  ruleHitsDays: number | null;
  logpushFailures: { jobId: string; error: string; count: number }[] | null;
  dmarcSources: { from: string; org: string; total: number; passing: number }[] | null;
}

export interface AccessLoginStats {
  appId: string;
  success: number;
  failed: number;
  countries: string[];
  idps: string[];
}

/** Outcome of an HTTP probe of a hostname that points at a takeover-prone provider. */
export interface TakeoverProbe {
  host: string;
  target: string;
  provider: string | null;
  status: number | null;
  unclaimed: boolean;
  /** The fingerprint text that matched, if any. */
  match: string | null;
  /** The provider requires domain verification, so the takeover is likely rather than certain. */
  verifiedProvider?: boolean;
}

export interface DeepDns {
  /** A/AAAA addresses of every MX host, by host name. */
  mxAddresses: Record<string, string[]>;
  /** Delegated subdomains (NS records below the apex) and whether their nameservers answer. */
  delegations: Record<string, { ns: string[]; status: "ok" | "lame" | "unresolvable"; detail: string }>;
  /** DKIM key strength per selector name, following CNAMEs. */
  dkim: Record<string, { bits: number | null; type: string; revoked: boolean } | null>;
  /** "<zone>|<external domain>" -> whether the external domain authorizes DMARC reports. */
  dmarcAuth: Record<string, boolean>;
  /** Domains with MX records -> whether an MTA-STS record exists. */
  mtaSts: Record<string, boolean>;
}

export interface WorkerInfo {
  name: string;
  modified?: string;
  subdomain: { enabled?: boolean; previews_enabled?: boolean } | null;
  bindings?: CF.WorkerBinding[] | null;
}

export interface Inventory {
  accountId: string;
  accountName: string | null;
  /**
   * Sources the token couldn't read in this scan. Every check that requires one is skipped,
   * so missing data never turns into a pass or a false failure.
   */
  unreadable?: SourceKey[];
  now: number;
  zones: ZoneInventory[];
  members: CF.Member[] | null;
  account: Api | null;
  accountTokens: CF.AccountToken[] | null;
  accessApps: CF.AccessApp[] | null;
  accessIdps: Api[] | null;
  accessOrg: CF.AccessOrg | null;
  accessGroups: CF.AccessGroup[] | null;
  accessPolicies: CF.AccessPolicy[] | null;
  accessUsers: CF.AccessUser[] | null;
  serviceTokens: CF.ServiceToken[] | null;
  tunnels: CF.Tunnel[] | null;
  deletedTunnels: CF.Tunnel[] | null;
  /** Tunnel id -> ingress rules (remotely managed tunnels only; null when unreadable). */
  tunnelIngress: Record<string, CF.IngressRule[]> | null;
  privateRoutes: CF.PrivateRoute[] | null;
  devices: Api[] | null;
  deviceProfiles: CF.DeviceProfile[] | null;
  devicePosture: Api[] | null;
  gatewayRules: CF.GatewayRule[] | null;
  gatewayConfig: CF.GatewayConfig | null;
  alertPolicies: Api[] | null;
  availableAlerts: Record<string, Api[]> | null;
  webhooks: CF.WebhookDestination[] | null;
  subscriptions: Api[] | null;
  audit: CF.AuditEntry[] | null;
  insights: Api[] | null;
  workers: WorkerInfo[];
  workersSubdomain: { subdomain?: string } | null;
  workerDomains: CF.WorkerDomain[] | null;
  pages: CF.PagesProject[] | null;
  r2: { name: string; managed: { enabled?: boolean; domain?: string } | null; cors?: CF.R2CorsRule[] | null }[];
  /** Account-level rulesets by phase (Enterprise can deploy WAF and rate limiting for all zones). */
  accountRulesets: Record<string, Optional<CF.Ruleset>>;
  accountIpRules: CF.IpAccessRule[] | null;
  mtlsCertificates: CF.ExpiringCertificate[] | null;
  lbPools: CF.LbPool[] | null;
  accessLogins: AccessLoginStats[] | null;
  traffic: Record<string, { requests: number; cachedRequests: number; threats: number; bytes: number }>;
  resolved: Record<string, { status: number; answers: { type: number; data: string }[] }>;
  spfLookups: Record<string, number>;
  deepDns: DeepDns;
  /** null when takeover probing is turned off. */
  takeover: TakeoverProbe[] | null;
}

/** One pass/fail evaluation of a check against one resource. */
export interface Result {
  checkId: string;
  source: Source;
  category: string;
  title: string;
  zone: string | null;
  resource: string;
  pass: boolean;
  severity: Severity;
  detail: string;
  evidence: Evidence | null;
  link: string | null;
  corroborated?: string[];
  fingerprint?: string;
  /**
   * "confirmed": verified by a live probe. "likely": a heuristic (name patterns,
   * sampled analytics). Absent: read directly from configuration.
   */
  confidence?: Confidence;
}

export interface EngineOptions {
  /** Email domains considered internal (zone names are always included). */
  orgDomains: string[];
  disabledChecks: Set<string>;
  severityOverrides: Record<string, Severity>;
  /** What the entity's other accounts, on other providers, share with this one. Absent: no checks that span providers. */
  related?: Related;
}

/** What checks that span providers know about the entity's other accounts, from their latest scans. */
export interface Related {
  /** Cloudflare DNS records in the entity that point at Vercel; null when the entity has no scanned Cloudflare account. */
  toVercel: NonNullable<ProviderLinks["toVercel"]> | null;
  /** Domains served by the entity's Vercel projects; null when the entity has no scanned Vercel account that could read them. */
  vercelDomains: NonNullable<ProviderLinks["vercelDomains"]> | null;
}

export const NO_RELATED: Related = { toVercel: null, vercelDomains: null };

export interface CollectOptions {
  /** Send HTTP probes to hostnames that point at takeover-prone providers. */
  probeTakeovers: boolean;
}

export interface CategoryTotals {
  [category: string]: { total: number; evaluated: number };
}

export interface ProgressEvent {
  phase: string;
  done?: number;
  total?: number;
}
