// One failing case per check. The type is Record<CheckId, …>, so adding a check
// without a case here doesn't compile, and test/contract.test.ts asserts that
// each case really makes its check fail. Cases start from the well-configured
// fixture and change only what the check looks at.

import type { CheckId } from "../../src/core/catalog.ts";
import type { Inventory, ZoneInventory } from "../../src/core/types.ts";
import { analytics, goodSettings, inventory, record, zone } from "../fixtures/inventory.ts";

const NOW = Date.parse("2026-06-01T00:00:00Z");
const days = (n: number) => new Date(NOW + n * 86_400_000).toISOString();
const Z = "example.com";
const TUNNEL = "6ff42ae2-765d-4adf-8112-31c55c1551ef";

/** The fixture inventory with its one zone changed. */
const withZone = (extra: Partial<ZoneInventory>, inv: Partial<Inventory> = {}) => inventory({ zones: [zone(Z, extra)], ...inv });
const withSettings = (s: Record<string, unknown>) => withZone({ settings: { ...goodSettings(), ...s } });
const withDns = (...recs: ReturnType<typeof record>[]) => withZone({ dns: [...zone(Z).dns, ...recs] });
const withTxt = (name: string, value: string, base = zone(Z).dns.filter((r) => !(r.type === "TXT" && r.name === name))) =>
  withZone({ dns: [...base, record(name, "TXT", `"${value}"`)] });
const withAnalytics = (a: Parameters<typeof analytics>[0], z: Partial<ZoneInventory> = {}) => withZone({ analytics: analytics(a), ...z });
const app = (extra: Record<string, unknown> = {}) => ({ id: "a1", name: "App", domain: `app.${Z}`, type: "self_hosted", policies: [], ...extra });
const badToken = {
  id: "t1",
  name: "ci",
  status: "active",
  issued_on: days(-400),
  last_used_on: days(-200),
  expires_on: null,
  policies: [{ effect: "allow", permission_groups: [{ name: "DNS Write" }], resources: { "com.cloudflare.api.account.zone.*": "*" } }],
};
const audit = (type: string, extra: Record<string, unknown>) => ({
  when: days(-1),
  actor: { email: "x@example.com" },
  action: { type, result: true },
  ...extra,
});

export const CASES: Record<CheckId, () => Inventory> = {
  "IAM-001": () => inventory({ members: [{ id: "m", status: "accepted", user: { email: `a@${Z}`, two_factor_authentication_enabled: false }, roles: [] }] }),
  "IAM-002": () =>
    inventory({
      members: [1, 2, 3, 4].map((i) => ({
        id: `m${i}`,
        status: "accepted",
        user: { email: `u${i}@${Z}`, two_factor_authentication_enabled: true },
        roles: [{ name: "Super Administrator - All Privileges" }],
      })),
    }),
  "IAM-003": () => inventory({ members: [{ id: "m", status: "pending", user: { email: `new@${Z}` }, roles: [] }] }),
  "IAM-004": () =>
    inventory({ members: [{ id: "m", status: "accepted", user: { email: "someone@gmail.com", two_factor_authentication_enabled: true }, roles: [] }] }),
  "IAM-005": () => inventory({ account: { name: "x", settings: { enforce_twofactor: false } } }),
  "IAM-006": () => inventory({ accountTokens: [badToken] }),
  "IAM-007": () => inventory({ accountTokens: [badToken] }),
  "IAM-008": () => inventory({ accountTokens: [badToken] }),
  "IAM-009": () => inventory({ accountTokens: [badToken] }),

  "ZT-001": () => inventory({ accessApps: [app({ policies: [{ name: "p", decision: "allow", include: [{ email: { email: "friend@gmail.com" } }] }] })] }),
  "ZT-002": () => inventory({ accessApps: [app({ session_duration: "720h" })] }),
  "ZT-003": () => inventory({ accessApps: [app({ policies: [{ name: "p", decision: "bypass", include: [{ everyone: {} }] }] })] }),
  "ZT-004": () => inventory({ accessIdps: [{ type: "onetimepin" }] }),
  "ZT-005": () => inventory({ serviceTokens: [{ name: "t", duration: "720h", created_at: days(-20), expires_at: days(5), last_seen_at: days(-1) }] }),
  "ZT-006": () =>
    inventory({ serviceTokens: [{ name: "t", duration: "forever", created_at: days(-20), expires_at: "2126-01-01T00:00:00Z", last_seen_at: days(-1) }] }),
  "ZT-007": () => inventory({ tunnels: [{ id: TUNNEL, name: "t", status: "down" }] }),
  "ZT-008": () => inventory({ tunnels: [{ id: TUNNEL, name: "t", status: "healthy" }] }),
  "ZT-009": () => inventory({ serviceTokens: [{ name: "t", duration: "8760h", created_at: days(-300), expires_at: days(300), last_seen_at: days(-200) }] }),
  "ZT-010": () =>
    inventory({
      serviceTokens: [{ name: "t", duration: "8760h", created_at: days(-30), expires_at: days(300), last_seen_at: days(-1), leak_reported_at: days(-2) }],
    }),
  "ZT-011": () =>
    inventory({
      accessOrg: { service_token_inactivity: { enabled: false } },
      serviceTokens: [{ name: "t", duration: "8760h", created_at: days(-10), expires_at: days(300), last_seen_at: days(-1) }],
    }),
  "ZT-012": () =>
    inventory({
      accessGroups: [{ id: "g", name: "All", include: [{ everyone: {} }] }],
      accessPolicies: [{ name: "Staff", decision: "allow", include: [{ group: { id: "g" } }] }],
    }),
  "ZT-013": () => inventory({ accessApps: [app({ cors_headers: { allow_all_origins: true, allow_credentials: true } })] }),
  "ZT-014": () => inventory({ accessApps: [app({ http_only_cookie_attribute: false })] }),
  "ZT-015": () =>
    inventory({
      accessIdps: [
        { id: "otp", type: "onetimepin" },
        { id: "g", type: "google-apps" },
      ],
      accessApps: [app({ allowed_idps: [] })],
    }),
  "ZT-016": () =>
    inventory({
      gatewayRules: [{ name: "r", enabled: true, filters: ["http"] }],
      gatewayConfig: { settings: { tls_decrypt: { enabled: false }, activity_log: { enabled: true } } },
    }),
  "ZT-017": () =>
    inventory({ gatewayRules: [{ name: "r", enabled: true, filters: ["dns"] }], gatewayConfig: { settings: { activity_log: { enabled: false } } } }),
  "ZT-018": () => inventory({ devices: [{ id: "d" }], deviceProfiles: [{ name: "Default", default: true, switch_locked: false }] }),
  "ZT-019": () => inventory({ privateRoutes: [{ network: "10.0.0.0/8", tunnel_id: TUNNEL }] }),
  "ZT-020": () => inventory({ devices: [{ id: "d" }], devicePosture: [] }),
  "ZT-021": () => inventory({ tunnels: [{ id: TUNNEL, name: "t", status: "healthy", connections: [{ client_version: "2024.1.0" }] }] }),
  "ZT-022": () => inventory({ accessUsers: [{ id: "u", email: `old@${Z}`, access_seat: true, last_successful_login: days(-200) }] }),

  "TLS-001": () => withSettings({ ssl: "flexible" }),
  "TLS-002": () => withSettings({ min_tls_version: "1.0" }),
  "TLS-003": () => withSettings({ always_use_https: "off" }),
  "TLS-004": () => withSettings({ security_header: { strict_transport_security: { enabled: false } } }),
  "TLS-005": () => withSettings({ security_header: { strict_transport_security: { enabled: true, max_age: 3600 } } }),
  "TLS-006": () => withSettings({ tls_1_3: "off" }),
  "TLS-007": () => withSettings({ automatic_https_rewrites: "off" }),
  "TLS-008": () => withZone({ certPacks: [{ id: "c", type: "advanced", status: "active", hosts: [Z, `*.${Z}`], certificates: [{ expires_on: days(5) }] }] }),
  "TLS-009": () => withSettings({ "0rtt": "on" }),
  "TLS-010": () => withDns(record(`a.b.${Z}`, "A", "203.0.113.11", { proxied: true })),
  "TLS-011": () => withZone({ originCerts: [{ hostnames: [Z], expires_on: days(10) }] }),
  "TLS-012": () => withZone({ plan: "business", planName: "Business" }),
  "TLS-013": () => withZone({ plan: "business", hostnameMinTls: [{ hostname: `old.${Z}`, value: "1.0" }] }),
  "TLS-014": () => withZone({ clientCerts: [{ id: "c", common_name: "device-1", status: "active", expires_on: days(10) }] }),
  "TLS-015": () => withZone({ universalSsl: { enabled: false }, certPacks: [] }),

  "WAF-001": () => withZone({ wafManaged: { rules: [] } }),
  "WAF-002": () => withZone({ wafManaged: { rules: [{ action: "execute", enabled: true, action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee" } }] } }),
  "WAF-003": () => withZone({ rateLimit: { rules: [] } }),
  "WAF-004": () => withZone({ bot: { sbfm_definitely_automated: "allow", ai_bots_protection: "block" } }),
  "WAF-005": () => withZone({ bot: { sbfm_definitely_automated: "block", ai_bots_protection: "disabled" } }),
  "WAF-006": () => withSettings({ security_level: "low" }),
  "WAF-007": () => withSettings({ browser_check: "off" }),
  "WAF-008": () => withZone({ leaked: { enabled: false } }),
  "WAF-009": () => withZone({ pageShield: { enabled: false } }),
  "WAF-010": () =>
    withZone({ wafCustom: { rules: [{ action: "skip", expression: "true", action_parameters: { phases: ["http_request_firewall_managed"] } }] } }),
  "WAF-011": () => withSettings({ development_mode: "on" }),
  "WAF-012": () =>
    withZone({
      wafManaged: {
        rules: [{ action: "execute", enabled: true, action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee", overrides: { action: "log" } } }],
      },
    }),
  "WAF-013": () =>
    withZone({
      wafCustom: {
        rules: [{ action: "skip", description: "partners", expression: 'http.user_agent contains "Partner"', action_parameters: { ruleset: "current" } }],
      },
    }),
  "WAF-014": () =>
    withZone({
      wafCustom: { rules: [{ action: "skip", description: "cloud", expression: "ip.src in {1.0.0.0/8}", action_parameters: { ruleset: "current" } }] },
    }),
  "WAF-015": () => withZone({ wafCustom: { rules: [{ action: "block", description: "old", expression: `http.host eq "gone.${Z}"` }] } }),
  "WAF-016": () =>
    withZone({ rateLimit: { rules: [{ enabled: true, action: "log", description: "login", ratelimit: { requests_per_period: 10, period: 60 } }] } }),
  "WAF-017": () =>
    withZone({
      phases: {
        http_config_settings: {
          rules: [{ enabled: true, description: "api", expression: `http.host eq "${Z}"`, action_parameters: { security_level: "off" } }],
        },
      },
    }),
  "WAF-018": () =>
    withZone({
      phases: {
        http_request_late_transform: {
          rules: [
            {
              enabled: true,
              description: "auth",
              expression: "true",
              action_parameters: { headers: { "X-Origin-Auth": { operation: "set", value: "0123456789abcdef0123" } } },
            },
          ],
        },
      },
    }),
  "WAF-019": () => withZone({ ddos: { rules: [{ action: "execute", enabled: true, action_parameters: { overrides: { sensitivity_level: "eoff" } } }] } }),
  "WAF-020": () => withZone({ ipRules: [{ id: "i", mode: "whitelist", configuration: { target: "country", value: "XX" } }] }),
  "WAF-021": () => withZone({ urlNormalization: { type: "cloudflare", scope: "none" } }),
  "WAF-022": () => withZone({ mtlsHostnames: [`api.${Z}`] }),
  "WAF-023": () => withZone({ pageShieldScripts: [{ id: "s", url: "https://evil.example/skim.js", url_reported_malicious: true }] }),

  "DNS-001": () =>
    inventory({
      zones: [zone(Z, { dns: [...zone(Z).dns, record(`old.${Z}`, "CNAME", `${TUNNEL}.cfargotunnel.com`, { proxied: true })] })],
      deletedTunnels: [{ id: TUNNEL, name: "gone", deleted_at: days(-10) }],
    }),
  "DNS-002": () =>
    inventory({
      zones: [zone(Z, { dns: [...zone(Z).dns, record(`shop.${Z}`, "CNAME", "gone.myshopify.com")] })],
      resolved: { "gone.myshopify.com": { status: 3, answers: [] } },
    }),
  "DNS-003": () => withDns(record(`intranet.${Z}`, "A", "10.0.0.5")),
  "DNS-004": () => withDns(record(`www.${Z}`, "CNAME", "elsewhere.net"), record(`www.${Z}`, "TXT", '"hello"')),
  "DNS-005": () => withDns(record(`unused.${Z}`, "A", "203.0.113.99")),
  "DNS-006": () => withZone({ dnssec: { status: "disabled" } }),
  "DNS-007": () => withZone({ dns: zone(Z).dns.filter((r) => r.type !== "CAA") }),
  "DNS-008": () => withDns(record(`*.${Z}`, "A", "203.0.113.7")),
  "DNS-009": () => withZone({ loadBalancers: [{ id: "lb", name: `lb.${Z}`, proxied: false, enabled: true }] }),

  "EML-001": () => withTxt(Z, "v=spf1 +all"),
  "EML-002": () => withTxt(`_dmarc.${Z}`, "v=DMARC1; p=none; rua=mailto:d@example.net"),
  "EML-003": () => withDns(record(`dmarc.${Z}`, "TXT", '"v=DMARC1; p=reject"')),
  "EML-004": () => withZone({ dns: zone(Z).dns.filter((r) => r.type !== "MX" && !(r.type === "TXT" && r.name === Z)) }),
  "EML-005": () => withTxt(`_dmarc.${Z}`, "v=DMARC1; p=reject"),
  "EML-006": () => inventory({ spfLookups: { [Z]: 14 } }),
  "EML-007": () => inventory({ deepDns: { ...inventory().deepDns, dkim: { [`s1._domainkey.${Z}`]: { bits: 1024, type: "rsa", revoked: false } } } }),
  "EML-008": () => inventory({ deepDns: { ...inventory().deepDns, dmarcAuth: { [`${Z}|reports.example.net`]: false } } }),
  "EML-009": () => inventory({ deepDns: { ...inventory().deepDns, mtaSts: { [Z]: false } } }),
  "EML-010": () => withZone({ emailCatchAll: { enabled: true, actions: [{ type: "forward", value: [`all@${Z}`] }] } }),
  "EML-011": () =>
    inventory({
      zones: [
        zone(Z, {
          dns: [...zone(Z).dns.filter((r) => !r.name.startsWith("_dmarc")), record(`_dmarc.${Z}`, "TXT", '"v=DMARC1; p=none; rua=mailto:d@example.net"')],
          analytics: analytics({ dmarcSources: [{ from: Z, org: "Unknown", total: 500, passing: 10 }] }),
        }),
      ],
    }),

  "PLT-001": () => inventory({ workersSubdomain: { subdomain: "acme" }, workers: [{ name: "api", subdomain: { enabled: true } }] }),
  "PLT-002": () => inventory({ r2: [{ name: "b", managed: { enabled: true, domain: "pub-1.r2.dev" } }] }),
  "PLT-003": () => inventory({ workers: [{ name: "api", subdomain: null, bindings: [{ type: "plain_text", name: "API_KEY", text: "x" }] }] }),
  "PLT-004": () => inventory({ pages: [{ name: "site", subdomain: "site.pages.dev", source: { config: { preview_deployment_setting: "all" } } }] }),
  "PLT-005": () => inventory({ r2: [{ name: "b", managed: null, cors: [{ allowed: { origins: ["*"], methods: ["PUT"] } }] }] }),

  "MON-001": () => inventory({ alertPolicies: [] }),
  "MON-002": () => withAnalytics({ logpushFailures: [{ jobId: "1", error: "denied", count: 5 }] }),
  "MON-003": () => inventory({ webhooks: [{ id: "w", name: "hook", url: "http://hooks.example.net" }] }),
  "MON-004": () => inventory({ accessApps: [app()], accessLogins: [{ appId: "a1", success: 10, failed: 5000, countries: ["US"], idps: ["onetimepin"] }] }),

  "ATS-001": () => withDns(record(`direct.${Z}`, "A", "203.0.113.10")),
  "ATS-002": () => withZone({ aop: { enabled: false } }),
  "ATS-003": () => withDns(record(`grafana.${Z}`, "A", "203.0.113.30", { proxied: true })),
  "ATS-004": () =>
    inventory({
      tunnels: [{ id: TUNNEL, name: "t", status: "healthy" }],
      tunnelIngress: { [TUNNEL]: [{ hostname: `ssh.${Z}`, service: "ssh://localhost:22" }] },
    }),
  "ATS-005": () =>
    inventory({
      tunnels: [{ id: TUNNEL, name: "t", status: "healthy" }],
      tunnelIngress: { [TUNNEL]: [{ hostname: Z, service: "https://localhost", originRequest: { noTLSVerify: true } }] },
    }),
  "ATS-006": () =>
    inventory({
      tunnels: [{ id: TUNNEL, name: "t", status: "healthy" }],
      tunnelIngress: { [TUNNEL]: [{ hostname: `nodns.${Z}`, service: "http://localhost" }] },
    }),
  "ATS-007": () =>
    inventory({
      takeover: [
        {
          host: `shop.${Z}`,
          target: "gone.myshopify.com",
          provider: "Shopify",
          status: 404,
          unclaimed: true,
          match: "Sorry, this shop is currently unavailable",
        },
      ],
    }),
  "ATS-008": () =>
    inventory({
      deepDns: {
        ...inventory().deepDns,
        delegations: { [`dev.${Z}`]: { ns: ["ns1.gone.example"], status: "unresolvable", detail: "No nameserver resolves" } },
      },
    }),
  "ATS-009": () => withZone({ spectrum: [{ id: "s", protocol: "tcp/22", dns: { name: `bastion.${Z}` } }] }),

  "TRF-001": () =>
    withAnalytics(
      { logOnly: [{ source: "firewallManaged", count: 5000 }] },
      {
        wafManaged: {
          rules: [{ action: "execute", enabled: true, action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee", overrides: { action: "log" } } }],
        },
      },
    ),
  "TRF-002": () => withAnalytics({ attacksPassed: [{ host: Z, path: "/search", count: 50 }] }),
  "TRF-003": () => withAnalytics({ leakedLogins: [{ host: Z, path: "/login", result: "password_leaked", status: 200, count: 3 }] }),
  "TRF-004": () => withAnalytics({ sensitive: [{ host: Z, path: "/.env", contentType: "txt", count: 4 }] }),
  "TRF-005": () => withAnalytics({ plainHttp: [{ host: Z, count: 200 }] }),
  "TRF-006": () => withAnalytics({ oldTls: [{ host: Z, protocol: "TLSv1", count: 200 }] }),
  "TRF-007": () =>
    withAnalytics(
      { ruleHits: {}, ruleHitsDays: 30 },
      { wafCustom: { rules: [{ id: "r1", action: "block", enabled: true, description: "old path", expression: 'http.request.uri.path eq "/old"' }] } },
    ),
  "TRF-008": () => withAnalytics({ botsPassed: [{ host: Z, path: "/login", count: 800 }] }),
  "TRF-009": () => withAnalytics({ hosts: [{ host: `ghost.${Z}`, count: 5000 }] }),

  "CHG-001": () =>
    inventory({
      audit: [
        audit("rulesets_update", {
          metadata: { zone_name: Z },
          oldValueJson: { modified_rules: [{ id: "r", description: "Block bad", action: "block", enabled: true, expression: "true" }] },
          newValueJson: { modified_rules: [{ id: "r", description: "Block bad", action: "block", enabled: false, expression: "true" }] },
        }),
      ],
    }),
  "CHG-002": () =>
    inventory({
      audit: [
        audit("access_update_application_policy", {
          oldValue: JSON.stringify({ name: "p", include: [] }),
          newValue: JSON.stringify({ name: "p", include: [{ everyone: {} }] }),
        }),
      ],
    }),
  "CHG-003": () => inventory({ audit: [audit("change_setting", { metadata: { zone_name: Z, name: "SSL", value: "off" } })] }),

  "COST-001": () => inventory({ traffic: { [`zone-${Z}`]: { requests: 10, cachedRequests: 0, threats: 0, bytes: 0 } } }),
};
