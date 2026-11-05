// Builds synthetic inventories for check tests. Defaults describe a well
// configured account; tests override the pieces they exercise.

import type { Api, Inventory, ZoneAnalytics, ZoneInventory, EngineOptions } from "../../src/core/types.ts";

export const ACCOUNT = "0123456789abcdef0123456789abcdef";
const OLD = "2025-01-01T00:00:00Z";

export function goodSettings(): Record<string, Api> {
  return {
    ssl: "strict",
    min_tls_version: "1.2",
    always_use_https: "on",
    tls_1_3: "on",
    automatic_https_rewrites: "on",
    "0rtt": "off",
    security_level: "medium",
    browser_check: "on",
    development_mode: "off",
    polish: "lossless",
    http3: "on",
    cname_flattening: "flatten_at_root",
    security_header: { strict_transport_security: { enabled: true, max_age: 31536000 } },
  };
}

export function record(name: string, type: string, content: string, extra: Api = {}): Api {
  return { id: `${name}-${type}-${content}`.slice(0, 32), name, type, content, proxied: false, ttl: 300, created_on: OLD, modified_on: OLD, ...extra };
}

/** Analytics for a quiet, well-protected zone: nothing suspicious in the window. */
export function analytics(extra: Partial<ZoneAnalytics> = {}): ZoneAnalytics {
  return {
    from: "2026-05-25T00:00:00Z",
    to: "2026-06-01T00:00:00Z",
    days: 7,
    unavailable: [],
    sensitive: [],
    logOnly: [],
    hosts: [],
    oldTls: [],
    plainHttp: [],
    leakedLogins: [],
    attacksPassed: [],
    botsPassed: [],
    ruleHits: null,
    ruleHitsDays: null,
    logpushFailures: [],
    dmarcSources: null,
    ...extra,
  };
}

export function zone(name: string, extra: Partial<ZoneInventory> = {}): ZoneInventory {
  return {
    id: `zone-${name}`,
    name,
    status: "active",
    paused: false,
    plan: "pro",
    planName: "Pro",
    planPrice: 25,
    settings: goodSettings(),
    dns: [
      record(name, "A", "203.0.113.10", { proxied: true }),
      record(name, "CAA", '0 issue "letsencrypt.org"'),
      record(name, "MX", "mx.example.net"),
      record(name, "TXT", '"v=spf1 include:_spf.example.net -all"'),
      record(`_dmarc.${name}`, "TXT", '"v=DMARC1; p=reject; rua=mailto:dmarc@example.net"'),
    ],
    dnsReadable: true,
    dnssec: { status: "active" },
    certPacks: [{ id: "pack1", type: "universal", status: "active", hosts: [name, `*.${name}`] }],
    bot: { sbfm_definitely_automated: "block", ai_bots_protection: "block", fight_mode: true },
    wafManaged: {
      rules: [
        { action: "execute", enabled: true, action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee" } },
        { action: "execute", enabled: true, action_parameters: { id: "4814384a9e5d4991b9815dcfc25d2f1f" } },
      ],
    },
    wafCustom: { rules: [] },
    rateLimit: { rules: [{ enabled: true }] },
    pageShield: { enabled: true },
    leaked: { enabled: true },
    phases: {},
    pageRules: [],
    originCerts: [],
    aop: { enabled: true },
    workerRoutes: [],
    ddos: null,
    pageShieldScripts: [],
    aopHostnames: [],
    customCerts: null,
    clientCerts: [],
    mtlsHostnames: [],
    hostnameMinTls: null,
    universalSsl: { enabled: true },
    totalTls: null,
    urlNormalization: { type: "cloudflare", scope: "incoming" },
    managedHeaders: null,
    ipRules: [],
    spectrum: null,
    loadBalancers: [],
    healthChecks: null,
    emailCatchAll: null,
    schemaValidation: null,
    lookups: { [name]: 500 },
    analytics: analytics(),
    ...extra,
  };
}

export function inventory(extra: Partial<Inventory> = {}): Inventory {
  return {
    accountId: ACCOUNT,
    accountName: "Example Inc",
    now: Date.parse("2026-06-01T00:00:00Z"),
    zones: [zone("example.com")],
    members: [
      {
        id: "m1",
        status: "accepted",
        user: { email: "a@example.com", two_factor_authentication_enabled: true },
        roles: [{ name: "Super Administrator - All Privileges" }],
      },
      { id: "m2", status: "accepted", user: { email: "b@example.com", two_factor_authentication_enabled: true }, roles: [{ name: "Administrator" }] },
    ],
    account: { name: "Example Inc", settings: { enforce_twofactor: true } },
    accessApps: [],
    accessIdps: [{ type: "google-apps" }],
    serviceTokens: [],
    tunnels: [],
    deletedTunnels: [],
    alertPolicies: ["security_insights_alert", "dos_attack_l7", "universal_ssl_event_type", "real_origin_monitoring", "incident_alert"].map((t) => ({
      enabled: true,
      alert_type: t,
    })),
    availableAlerts: {
      All: [
        "security_insights_alert",
        "dos_attack_l7",
        "universal_ssl_event_type",
        "tunnel_health_event",
        "expiring_service_token_alert",
        "real_origin_monitoring",
        "incident_alert",
      ].map((type) => ({ type })),
    },
    subscriptions: [],
    audit: [],
    devices: [],
    gatewayRules: [],
    insights: [],
    workers: [],
    workersSubdomain: null,
    r2: [],
    accountTokens: [],
    accessOrg: { service_token_inactivity: { enabled: true } },
    accessGroups: [],
    accessPolicies: [],
    accessUsers: [],
    privateRoutes: [],
    deviceProfiles: [],
    devicePosture: [],
    gatewayConfig: null,
    webhooks: [],
    workerDomains: [],
    pages: [],
    accountRulesets: {},
    accountIpRules: [],
    mtlsCertificates: [],
    lbPools: [],
    accessLogins: [],
    traffic: { "zone-example.com": { requests: 5_000_000, cachedRequests: 1_000_000, threats: 10, bytes: 1 } },
    resolved: {},
    spfLookups: { "example.com": 2 },
    tunnelIngress: {},
    deepDns: { mxAddresses: {}, delegations: {}, dkim: {}, dmarcAuth: {}, mtaSts: { "example.com": true } },
    takeover: [],
    ...extra,
  };
}

export const opts = (o: Partial<EngineOptions> = {}): EngineOptions => ({ orgDomains: [], disabledChecks: new Set(), severityOverrides: {}, ...o });
