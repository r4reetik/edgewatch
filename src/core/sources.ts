// Every data source a scan reads, in one place. A source has a coverage label
// (shown when it can't be read), the token permission that grants it, and an
// optional probe for the setup screen. Checks declare the sources they need
// (`requires`), so the UI can say exactly which checks a missing permission skips.

export interface Source {
  label: string;
  /** Token permission as Cloudflare's token form names it. */
  permission: string;
  /** A cheap request that proves the token can read this source (setup screen). */
  probe?: (account: string, zone: string | null) => string | null;
  /** Reached through GraphQL rather than REST. */
  graphql?: boolean;
  /** Not a Cloudflare API read (DNS-over-HTTPS, live probes): never a permission problem. */
  external?: boolean;
}

const zone = (path: string) => (_a: string, z: string | null) => z && `/zones/${z}/${path}`;
const account = (path: string) => (a: string) => `/accounts/${a}/${path}`;

const DEFS = {
  // ---- account
  zones: { label: "Zones", permission: "Zone · Zone · Read", probe: (a) => `/zones?account.id=${a}&per_page=5` },
  account: { label: "Account settings", permission: "Account · Account Settings · Read", probe: account("members?per_page=5") },
  members: { label: "Account members", permission: "Account · Account Settings · Read" },
  auditLogs: { label: "Audit logs", permission: "Account · Account Settings · Read", probe: account("audit_logs?per_page=1") },
  accountTokens: { label: "Account API tokens", permission: "Account · Account API Tokens · Read", probe: account("tokens?per_page=1") },
  subscriptions: { label: "Subscriptions", permission: "Account · Billing · Read", probe: account("subscriptions") },
  securityCenter: {
    label: "Security Center insights",
    permission: "Account · Security Center Insights · Read",
    probe: account("security-center/insights?per_page=5"),
  },
  notifications: { label: "Notifications", permission: "Account · Notifications · Read", probe: account("alerting/v3/policies") },

  accessApps: { label: "Access applications", permission: "Account · Access: Apps and Policies · Read", probe: account("access/apps?per_page=5") },
  accessPolicies: { label: "Access policies", permission: "Account · Access: Apps and Policies · Read" },
  accessIdps: {
    label: "Access identity providers",
    permission: "Account · Access: Organizations, Identity Providers, and Groups · Read",
    probe: account("access/identity_providers?per_page=5"),
  },
  accessOrg: { label: "Access organization", permission: "Account · Access: Organizations, Identity Providers, and Groups · Read" },
  accessGroups: { label: "Access groups", permission: "Account · Access: Organizations, Identity Providers, and Groups · Read" },
  accessServiceTokens: {
    label: "Access service tokens",
    permission: "Account · Access: Service Tokens · Read",
    probe: account("access/service_tokens?per_page=5"),
  },
  accessUsers: { label: "Access users", permission: "Account · Access: Audit Logs · Read", probe: account("access/users?per_page=1") },

  tunnels: { label: "Tunnels", permission: "Account · Cloudflare Tunnel · Read", probe: account("cfd_tunnel?per_page=5") },
  tunnelConfigs: { label: "Tunnel configurations", permission: "Account · Cloudflare Tunnel · Read" },
  privateRoutes: { label: "Private network routes", permission: "Account · Cloudflare Tunnel · Read" },
  devices: { label: "Zero Trust devices", permission: "Account · Zero Trust · Read", probe: account("gateway/rules") },
  deviceProfiles: { label: "WARP device profiles", permission: "Account · Zero Trust · Read" },
  devicePosture: { label: "Device posture rules", permission: "Account · Zero Trust · Read" },
  gatewayRules: { label: "Gateway rules", permission: "Account · Zero Trust · Read" },
  gatewayConfig: { label: "Gateway configuration", permission: "Account · Zero Trust · Read" },

  workers: { label: "Workers", permission: "Account · Workers Scripts · Read", probe: account("workers/scripts") },
  workerSettings: { label: "Worker settings", permission: "Account · Workers Scripts · Read" },
  workerDomains: { label: "Worker custom domains", permission: "Account · Workers Scripts · Read" },
  pages: { label: "Pages projects", permission: "Account · Cloudflare Pages · Read", probe: account("pages/projects") },
  r2: { label: "R2", permission: "Account · Workers R2 Storage · Read", probe: account("r2/buckets") },
  accountRulesets: { label: "Account rulesets", permission: "Account · Account Rulesets · Read", probe: account("rulesets") },
  accountIpRules: {
    label: "Account IP access rules",
    permission: "Account · Account Firewall Access Rules · Read",
    probe: account("firewall/access_rules/rules?per_page=1"),
  },
  ruleLists: { label: "Lists", permission: "Account · Account Filter Lists · Read", probe: account("rules/lists") },
  mtlsCertificates: { label: "mTLS certificates", permission: "Account · SSL and Certificates · Read", probe: account("mtls_certificates") },
  lbPools: { label: "Load balancer pools", permission: "Account · Load Balancing: Monitors and Pools · Read", probe: account("load_balancers/pools") },

  // ---- per zone
  zoneSettings: { label: "Zone settings", permission: "Zone · Zone Settings · Read", probe: zone("settings") },
  dnsRecords: { label: "DNS records", permission: "Zone · DNS · Read", probe: zone("dns_records?per_page=5") },
  dnssec: { label: "DNSSEC", permission: "Zone · DNS · Read" },
  certificates: { label: "Edge certificates", permission: "Zone · SSL and Certificates · Read", probe: zone("ssl/certificate_packs?per_page=5") },
  originCertificates: { label: "Origin certificates", permission: "Zone · SSL and Certificates · Read" },
  tlsSettings: { label: "TLS and mTLS settings", permission: "Zone · SSL and Certificates · Read" },
  wafRulesets: { label: "WAF rulesets", permission: "Zone · Zone WAF · Read", probe: zone("rulesets") },
  otherRulesets: { label: "Configuration and transform rules", permission: "Zone · Transform Rules · Read (and Config, Redirect, Cache Rules)" },
  ddosRules: { label: "HTTP DDoS settings", permission: "Zone · HTTP DDoS Managed Ruleset · Read" },
  firewallRules: { label: "IP access and lockdown rules", permission: "Zone · Firewall Services · Read" },
  bot: { label: "Bot settings", permission: "Zone · Bot Management · Read", probe: zone("bot_management") },
  pageShield: { label: "Page Shield", permission: "Zone · Page Shield · Read", probe: zone("page_shield") },
  leakedCredentials: { label: "Leaked credential checks", permission: "Zone · Zone WAF · Read" },
  pageRules: { label: "Page rules", permission: "Zone · Page Rules · Read" },
  workerRoutes: { label: "Worker routes", permission: "Zone · Workers Routes · Read" },
  urlNormalization: { label: "URL normalization", permission: "Zone · Zone Settings · Read" },
  managedHeaders: { label: "Managed transforms", permission: "Zone · Transform Rules · Read" },
  spectrum: { label: "Spectrum applications", permission: "Zone · Zone Settings · Read" },
  loadBalancers: { label: "Load balancers", permission: "Zone · Load Balancers · Read" },
  healthChecks: { label: "Health checks", permission: "Zone · Health Checks · Read" },
  emailRouting: { label: "Email Routing", permission: "Zone · Email Routing Rules · Read" },
  snippets: { label: "Snippets", permission: "Zone · Snippets · Read" },
  apiShield: { label: "API Shield", permission: "Zone · API Gateway · Read" },

  // ---- GraphQL analytics
  traffic: { label: "Traffic analytics", permission: "Zone · Analytics · Read", graphql: true, probe: () => "/graphql" },
  dnsAnalytics: { label: "DNS analytics", permission: "Zone · Analytics · Read", graphql: true },
  securityAnalytics: { label: "Security analytics", permission: "Zone · Analytics · Read", graphql: true },
  dmarcReports: { label: "DMARC reports", permission: "Zone · Analytics · Read", graphql: true },
  accessLogins: { label: "Access login analytics", permission: "Account · Account Analytics · Read", graphql: true },
  logpushHealth: { label: "Logpush health", permission: "Account · Account Analytics · Read", graphql: true },

  // ---- outside Cloudflare's API
  doh: { label: "Public DNS lookups", permission: "", external: true },
  takeoverProbes: { label: "Takeover probes", permission: "", external: true },
} satisfies Record<string, Source>;

export type SourceKey = keyof typeof DEFS;
export const SOURCES: Record<SourceKey, Source> = DEFS;
export const SOURCE_KEYS = Object.keys(SOURCES) as SourceKey[];
export const source = (k: SourceKey): Source => SOURCES[k];
