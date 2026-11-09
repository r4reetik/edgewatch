// A fetch replacement that serves small, realistic Cloudflare accounts, so full
// scans run end to end without network access (tests and `npm run dev -- --mock`).
// Each account has its own token, as two legal entities would. `deny` makes
// chosen endpoints answer 403 to simulate a token missing permissions.
//
// The data is deliberately imperfect, so every family of checks has something
// to find: an Access group open to everyone, a leaked service token, a tunnel
// publishing SSH, a DNS-only load balancer, a .env file served in traffic, and so on.
// Dates are relative to now, so findings don't drift as time passes.

import { rateLimit } from "../../src/core/cloudflare.ts";

const DAY = 86_400_000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();
const ahead = (days: number) => new Date(Date.now() + days * DAY).toISOString();

const ACC = "0123456789abcdef0123456789abcdef";
const Z = "zone0000000000000000000000000001";
const Z2 = "zone0000000000000000000000000002";
const TUNNEL = "6ff42ae2-765d-4adf-8112-31c55c1551ef";

type Handler = (url: URL, init?: RequestInit) => unknown;

export const MOCK_ACCOUNT = ACC;
export const MOCK_TOKEN = "mock-token-0123456789-SECRET-VALUE";
export const MOCK_ACCOUNT_2 = "fedcba9876543210fedcba9876543210";
export const MOCK_TOKEN_2 = "mock-token-2-abcdefghij-OTHER-SECRET";
/** A second account behind MOCK_TOKEN: one token covering two accounts of the same company. */
export const MOCK_ACCOUNT_3 = "00112233445566778899aabbccddeeff";

const ACCOUNTS: Record<string, { name: string; token: string; zone: string; zoneName: string }> = {
  [ACC]: { name: "Mock Co", token: MOCK_TOKEN, zone: Z, zoneName: "mock.example" },
  [MOCK_ACCOUNT_2]: { name: "Other Ltd", token: MOCK_TOKEN_2, zone: Z2, zoneName: "other.example" },
  [MOCK_ACCOUNT_3]: { name: "Mock Co Staging", token: MOCK_TOKEN, zone: "zone0000000000000000000000000003", zoneName: "mock-staging.example" },
};
const byToken = (t: string) =>
  Object.entries(ACCOUNTS)
    .filter(([, a]) => a.token === t)
    .map(([id, a]) => ({ id, ...a }));
const zoneName = (u: URL) => Object.values(ACCOUNTS).find((a) => u.pathname.includes(a.zone))?.zoneName || "mock.example";
const isMain = (u: URL) => u.pathname.includes(Z) || u.pathname.includes(`/accounts/${ACC}`);

const token = (init?: RequestInit) => String((init?.headers as Record<string, string>)?.Authorization || "").replace(/^Bearer /, "");
const ok = (result: unknown, extra: Record<string, unknown> = {}) => ({ success: true, errors: [], result, ...extra });
const list = (result: unknown[]) => ok(result, { result_info: { total_pages: 1 } });
const NOT_FOUND = { __status: 404 };

const routes: [RegExp, Handler][] = [
  [/^\/user\/tokens\/verify$/, () => ok({ status: "active" })],
  [/^\/accounts$/, (_u, init) => list(byToken(token(init)).map((a) => ({ id: a.id, name: a.name })))],
  [
    /^\/zones$/,
    (u) => {
      const a = ACCOUNTS[u.searchParams.get("account.id") || ""];
      return list(a ? [{ id: a.zone, name: a.zoneName, status: "active", plan: { legacy_id: "pro", name: "Pro", price: 25 } }] : []);
    },
  ],
  [
    /^\/accounts\/[0-9a-f]{32}\/members$/,
    () =>
      list([
        {
          id: "m1",
          status: "accepted",
          user: { email: "owner@mock.example", two_factor_authentication_enabled: true },
          roles: [{ name: "Super Administrator - All Privileges" }],
        },
        { id: "m2", status: "accepted", user: { email: "dev@mock.example", two_factor_authentication_enabled: false }, roles: [{ name: "Administrator" }] },
      ]),
  ],
  [
    /^\/accounts\/[0-9a-f]{32}$/,
    (u) => {
      const id = u.pathname.split("/").pop()!;
      return ok({ id, name: ACCOUNTS[id].name, settings: { enforce_twofactor: false } });
    },
  ],
  [
    /\/accounts\/[0-9a-f]{32}\/tokens$/,
    () =>
      list([
        {
          id: "t1",
          name: "ci-deploy",
          status: "active",
          issued_on: ago(400),
          last_used_on: ago(200),
          expires_on: null,
          policies: [
            { effect: "allow", permission_groups: [{ name: "DNS Write" }, { name: "Zone Read" }], resources: { [`com.cloudflare.api.account.zone.*`]: "*" } },
          ],
        },
        {
          id: "t2",
          name: "reporting",
          status: "active",
          issued_on: ago(60),
          last_used_on: ago(1),
          expires_on: ahead(300),
          condition: { request_ip: { in: ["198.51.100.0/24"] } },
          policies: [{ effect: "allow", permission_groups: [{ name: "Analytics Read" }], resources: { [`com.cloudflare.api.account.${ACC}`]: "*" } }],
        },
      ]),
  ],
  [
    /\/access\/apps$/,
    (u) =>
      list(
        isMain(u)
          ? [
              {
                id: "app1",
                name: "Grafana",
                domain: "grafana.mock.example",
                type: "self_hosted",
                session_duration: "24h",
                http_only_cookie_attribute: true,
                cors_headers: { allow_all_origins: true, allow_credentials: true },
                policies: [{ name: "Staff", decision: "allow", include: [{ group: { id: "g1" } }] }],
              },
            ]
          : [],
      ),
  ],
  [/\/access\/groups$/, (u) => list(isMain(u) ? [{ id: "g1", name: "Everyone (temporary)", include: [{ everyone: {} }] }] : [])],
  [/\/access\/policies$/, () => list([])],
  [/\/access\/organizations$/, () => ok({ auth_domain: "mock.cloudflareaccess.com", service_token_inactivity: { enabled: false } })],
  [/\/access\/users$/, (u) => list(isMain(u) ? [{ id: "u1", email: "former@mock.example", access_seat: true, last_successful_login: ago(200) }] : [])],
  [/\/access\/identity_providers$/, () => list([{ id: "idp1", type: "onetimepin" }])],
  [
    /\/access\/service_tokens$/,
    (u) =>
      list(
        isMain(u)
          ? [{ id: "st1", name: "ci-runner", duration: "8760h", created_at: ago(100), expires_at: ahead(200), last_seen_at: ago(2), leak_reported_at: ago(3) }]
          : [],
      ),
  ],
  [
    /\/cfd_tunnel$/,
    (u) =>
      list(
        isMain(u) && u.searchParams.get("is_deleted") === "false"
          ? [
              {
                id: TUNNEL,
                name: "prod",
                status: "healthy",
                conns_active_at: ago(0),
                config_src: "cloudflare",
                connections: [{ client_version: "2024.1.5", origin_ip: "203.0.113.50" }],
              },
            ]
          : [],
      ),
  ],
  [
    /\/cfd_tunnel\/[^/]+\/configurations$/,
    () => ok({ config: { ingress: [{ hostname: "ssh.mock.example", service: "ssh://localhost:22" }, { service: "http_status:404" }] } }),
  ],
  [/\/teamnet\/routes$/, (u) => list(isMain(u) ? [{ network: "10.0.0.0/8", tunnel_id: TUNNEL, tunnel_name: "prod" }] : [])],
  [/\/alerting\/v3\/policies$/, () => ok([])],
  [/\/alerting\/v3\/available_alerts$/, () => ok({ All: [{ type: "security_insights_alert" }, { type: "dos_attack_l7" }] })],
  [
    /\/alerting\/v3\/destinations\/webhooks$/,
    (u) => ok(isMain(u) ? [{ id: "w1", name: "Old SIEM", url: "http://siem.mock.example/hook", last_success: ago(30), last_failure: ago(1) }] : []),
  ],
  [/\/workers\/scripts$/, (u) => ok(isMain(u) ? [{ id: "api", modified_on: ago(10) }] : [])],
  [/\/workers\/scripts\/[^/]+\/subdomain$/, () => ok({ enabled: false, previews_enabled: false })],
  [
    /\/workers\/scripts\/[^/]+\/settings$/,
    () =>
      ok({
        bindings: [
          { type: "plain_text", name: "STRIPE_API_KEY", text: "sk_live_not_a_real_key" },
          { type: "secret_text", name: "DB_PASSWORD" },
        ],
      }),
  ],
  [/\/workers\/subdomain$/, () => ok({ subdomain: "mockco" })],
  [/\/workers\/domains$/, () => list([])],
  [
    /\/pages\/projects$/,
    (u) =>
      list(
        isMain(u)
          ? [
              {
                name: "site",
                subdomain: "site-mock.pages.dev",
                domains: ["www.mock.example"],
                source: { config: { preview_deployment_setting: "all" } },
                deployment_configs: {
                  production: { env_vars: { PUBLIC_URL: { type: "plain_text", value: "https://www.mock.example" } } },
                  preview: { env_vars: { SECRET_TOKEN: { type: "plain_text", value: "x" } } },
                },
              },
            ]
          : [],
      ),
  ],
  [/\/r2\/buckets$/, (u) => ok({ buckets: isMain(u) ? [{ name: "uploads" }] : [] })],
  [/\/r2\/buckets\/[^/]+\/domains\/managed$/, () => ok({ enabled: false, domain: "pub-123.r2.dev" })],
  [/\/r2\/buckets\/[^/]+\/cors$/, () => ok({ rules: [{ allowed: { origins: ["*"], methods: ["GET", "PUT"] } }] })],
  [
    /\/subscriptions$/,
    () => ok([{ rate_plan: { public_name: "Pro", scope: "zone" }, zone: { name: "mock.example" }, price: 25, frequency: "monthly", state: "Paid" }]),
  ],
  [
    /\/audit_logs$/,
    () =>
      ok([{ when: ago(1), actor: { email: "dev@mock.example", type: "user" }, action: { type: "rec_del", result: true }, resource: { type: "dns.record" } }]),
  ],
  [
    /\/devices$/,
    (u) =>
      list(
        isMain(u)
          ? [
              { id: "d1", name: "laptop-1" },
              { id: "d2", name: "laptop-2" },
            ]
          : [],
      ),
  ],
  [/\/devices\/policies$/, () => ok([{ policy_id: "p1", name: "Default", default: true, enabled: true, switch_locked: false, allowed_to_leave: true }])],
  [/\/devices\/posture$/, () => ok([])],
  [/\/gateway\/rules$/, (u) => list(isMain(u) ? [{ id: "gr1", name: "Block gambling", action: "block", enabled: true, filters: ["http"] }] : [])],
  [/\/gateway\/configuration$/, () => ok({ settings: { tls_decrypt: { enabled: false }, activity_log: { enabled: false } } })],
  [
    /\/firewall\/access_rules\/rules$/,
    (u) =>
      list(
        u.pathname.includes(`/accounts/${ACC}/`)
          ? [{ id: "ip1", mode: "whitelist", notes: "office", configuration: { target: "country", value: "XX" }, scope: { type: "account" } }]
          : [],
      ),
  ],
  [/\/mtls_certificates$/, (u) => ok(isMain(u) ? [{ id: "mt1", name: "device CA", expires_on: ahead(10) }] : [])],
  [/\/load_balancers\/pools$/, () => ok([{ id: "pool1", name: "web", origins: [{ name: "web-1", address: "198.51.100.7", enabled: true }] }])],
  [/^\/accounts\/[^/]+\/rulesets\/phases\/[^/]+\/entrypoint$/, () => NOT_FOUND],
  [
    /\/security-center\/insights$/,
    () =>
      ok({
        count: 1,
        issues: [
          {
            id: "i1",
            issue_class: "security_txt_not_enabled",
            issue_type: "configuration_suggestion",
            severity: "Low",
            subject: "mock.example",
            payload: { zone_tag: Z },
          },
        ],
      }),
  ],

  // ---- zone
  [/\/origin_tls_client_auth\/settings$/, () => ok({ enabled: false })],
  [/\/origin_tls_client_auth\/hostnames\/certificates$/, () => ok([])],
  [
    /\/pagerules$/,
    () =>
      ok([{ status: "active", targets: [{ constraint: { value: "mock.example/admin*" } }], actions: [{ id: "security_level", value: "essentially_off" }] }]),
  ],
  [/^\/certificates$/, () => ok([{ hostnames: ["mock.example"], expires_on: ahead(9) }])],
  [/\/client_certificates$/, () => ok([])],
  [/\/certificate_authorities\/hostname_associations$/, () => ok({ hostnames: [] })],
  [/\/ssl\/universal\/settings$/, () => ok({ enabled: true })],
  [/\/acm\/total_tls$/, () => ok({ enabled: false })],
  [/\/workers\/routes$/, () => ok([])],
  [/\/url_normalization$/, (u) => ok(isMain(u) ? { type: "cloudflare", scope: "none" } : { type: "cloudflare", scope: "incoming" })],
  [/\/managed_headers$/, () => ok({ managed_request_headers: [], managed_response_headers: [] })],
  [
    /\/spectrum\/apps$/,
    (u) =>
      ok(
        isMain(u)
          ? [{ id: "sp1", protocol: "tcp/22", dns: { name: "bastion.mock.example" }, ip_firewall: false, origin_direct: ["tcp://203.0.113.60:22"] }]
          : [],
      ),
  ],
  [
    /\/zones\/[^/]+\/load_balancers$/,
    (u) => ok(isMain(u) ? [{ id: "lb1", name: "lb.mock.example", proxied: false, enabled: true, default_pools: ["pool1"] }] : []),
  ],
  [/\/healthchecks$/, () => ok([])],
  [
    /\/email\/routing\/rules\/catch_all$/,
    (u) => ok(isMain(u) ? { enabled: true, actions: [{ type: "forward", value: ["ops@mock.example"] }] } : { enabled: false, actions: [{ type: "drop" }] }),
  ],
  [
    /\/settings$/,
    () =>
      ok([
        { id: "ssl", value: "full" },
        { id: "min_tls_version", value: "1.0" },
        { id: "always_use_https", value: "on" },
        { id: "tls_1_3", value: "on" },
        { id: "automatic_https_rewrites", value: "on" },
        { id: "security_level", value: "medium" },
        { id: "browser_check", value: "on" },
        { id: "development_mode", value: "off" },
        { id: "security_header", value: { strict_transport_security: { enabled: false } } },
      ]),
  ],
  [
    /\/dns_records$/,
    (u) =>
      list([
        { id: "r1", name: zoneName(u), type: "A", content: "203.0.113.1", proxied: true, created_on: ago(500), modified_on: ago(500) },
        { id: "r2", name: `old.${zoneName(u)}`, type: "A", content: "203.0.113.2", proxied: false, created_on: ago(500), modified_on: ago(500) },
        { id: "r3", name: zoneName(u), type: "MX", content: `mx.${zoneName(u)}`, created_on: ago(500), modified_on: ago(500) },
        ...(isMain(u)
          ? [
              { id: "r4", name: "grafana.mock.example", type: "A", content: "203.0.113.20", proxied: true, created_on: ago(300), modified_on: ago(300) },
              {
                id: "r5",
                name: "ssh.mock.example",
                type: "CNAME",
                content: `${TUNNEL}.cfargotunnel.com`,
                proxied: true,
                created_on: ago(300),
                modified_on: ago(300),
              },
              { id: "r6", name: "www.mock.example", type: "CNAME", content: "site-mock.pages.dev", proxied: true, created_on: ago(300), modified_on: ago(300) },
              // Served by the mock Vercel team's "web" project, proxied through Cloudflare (dev/mock/vercel.ts).
              {
                id: "r7",
                name: "app.mock.example",
                type: "CNAME",
                content: "cname.vercel-dns.com",
                proxied: true,
                created_on: ago(200),
                modified_on: ago(200),
              },
              // No Vercel project serves this one any more.
              {
                id: "r8",
                name: "launch.mock.example",
                type: "CNAME",
                content: "cname.vercel-dns.com",
                proxied: false,
                created_on: ago(400),
                modified_on: ago(400),
              },
            ]
          : []),
      ]),
  ],
  [/\/dnssec$/, () => ok({ status: "disabled" })],
  [
    /\/certificate_packs$/,
    (u) => list([{ id: "cp1", type: "universal", status: "active", hosts: [zoneName(u), `*.${zoneName(u)}`], certificates: [{ expires_on: ahead(80) }] }]),
  ],
  [/\/bot_management$/, () => ok({ sbfm_definitely_automated: "allow", ai_bots_protection: "disabled" })],
  // Other Ltd's managed rules are deployed but overridden to log only, so traffic checks have something to correlate.
  [
    /\/phases\/http_request_firewall_managed\/entrypoint$/,
    (u) =>
      ok({
        rules: u.pathname.includes(Z2)
          ? [{ id: "x1", action: "execute", enabled: true, action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee", overrides: { action: "log" } } }]
          : [],
      }),
  ],
  [
    /\/phases\/ddos_l7\/entrypoint$/,
    (u) =>
      isMain(u)
        ? ok({
            rules: [
              { action: "execute", enabled: true, action_parameters: { id: "4d21379b4f9f4bb088e0729962c8b3cf", overrides: { sensitivity_level: "eoff" } } },
            ],
          })
        : NOT_FOUND,
  ],
  [/\/phases\/.+\/entrypoint$/, () => NOT_FOUND],
  [/\/page_shield$/, () => ok({ enabled: false })],
  [/\/leaked-credential-checks$/, () => ok({ enabled: false })],
  [/^\/graphql$/, (_u, init) => graphql(JSON.parse(String(init?.body)))],
];

/** Answers the GraphQL queries the collector sends, by dataset. */
function graphql({ query, variables }: { query: string; variables: Record<string, unknown> }): unknown {
  if (query.includes("accessLoginRequestsAdaptiveGroups")) {
    return {
      data: {
        viewer: {
          accounts: [
            {
              accessLoginRequestsAdaptiveGroups: [
                { count: 4200, dimensions: { appId: "app1", isSuccessfulLogin: 0, country: "US", identityProvider: "onetimepin" } },
                { count: 40, dimensions: { appId: "app1", isSuccessfulLogin: 1, country: "GB", identityProvider: "onetimepin" } },
              ],
            },
          ],
        },
      },
    };
  }
  if (query.includes("httpRequests1dGroups")) {
    const tags = (variables.tags as string[]) || [Z];
    return {
      data: {
        viewer: {
          zones: tags.map((t) => ({ zoneTag: t, httpRequests1dGroups: [{ sum: { requests: 10_000_000, cachedRequests: 0, threats: 3, bytes: 1 } }] })),
        },
      },
    };
  }
  if (query.includes("dnsAnalyticsAdaptiveGroups"))
    return { data: { viewer: { zones: [{ dnsAnalyticsAdaptiveGroups: [{ count: 100, dimensions: { queryName: "mock.example" } }] }] } } };
  // Security analytics: one entry per zone in the batch, with the aliases the query asked for.
  const tags = (variables.tags as string[]) || [];
  const rows = (zone: string): Record<string, unknown> => {
    const main = zone === Z,
      name = main ? "mock.example" : "other.example";
    const all: Record<string, unknown[]> = {
      sensitive: main
        ? [
            { count: 12, dimensions: { clientRequestHTTPHost: "mock.example", clientRequestPath: "/.env", edgeResponseContentTypeName: "txt" } },
            { count: 40, dimensions: { clientRequestHTTPHost: "mock.example", clientRequestPath: "/.git/config", edgeResponseContentTypeName: "html" } },
          ]
        : [],
      logOnly: main ? [] : [{ count: 52_000, dimensions: { securitySource: "firewallManaged" } }],
      hosts: [{ count: 900_000, dimensions: { clientRequestHTTPHost: name } }],
      oldTls: main ? [{ count: 320, dimensions: { clientRequestHTTPHost: name, clientSSLProtocol: "TLSv1" } }] : [],
      leakedLogins: [],
      plainHttp: [],
      logpushFailures: main ? [{ count: 14, dimensions: { jobId: "1234", error: "destination bucket not found" } }] : [],
      dmarcSources: main
        ? [{ sum: { totalMatchingMessages: 400, dmarc: 20 }, dimensions: { headerFrom: "mock.example", sourceOrgName: "Unknown sender" } }]
        : [],
    };
    return Object.fromEntries(Object.entries(all).filter(([k]) => new RegExp(`\\b${k}:`).test(query)));
  };
  return { data: { viewer: { zones: tags.map((t) => ({ zoneTag: t, ...rows(t) })) } } };
}

export interface MockOptions {
  deny?: RegExp[];
  onRequest?: (url: URL, init?: RequestInit) => void;
}

export function installMockCloudflare(o: MockOptions = {}): () => void {
  const real = globalThis.fetch;
  // The mock has no rate limit; tests and the mock server make far more calls than one real scan.
  const limit = rateLimit.perWindow;
  rateLimit.perWindow = Number.POSITIVE_INFINITY;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    o.onRequest?.(url, init);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.hostname === "cloudflare-dns.com") return json({ Status: 0, Answer: [] });
    if (url.hostname !== "api.cloudflare.com") return real(input as string, init);
    const path = url.pathname.replace(/^\/client\/v4/, "");
    const visible = byToken(token(init));
    if (!visible.length) return json({ success: false, errors: [{ message: "Invalid API Token" }] }, 401);
    // A token only reaches its own accounts and their zones.
    const acc = /^\/accounts\/([0-9a-f]{32})/.exec(path)?.[1] ?? url.searchParams.get("account.id");
    const zone = /^\/zones\/([^/]+)/.exec(path)?.[1];
    const denied = (acc && !visible.some((a) => a.id === acc)) || (zone && !visible.some((a) => a.zone === zone));
    if (denied || o.deny?.some((re) => re.test(path))) return json({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }, 403);
    const route = routes.find(([re]) => re.test(path));
    if (!route) return json({ success: false, errors: [{ message: `No mock for ${path}` }] }, 404);
    const body = route[1](url, init) as { __status?: number };
    if (body?.__status) return json({ success: false, errors: [{ message: "not found" }] }, body.__status);
    return json(body);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
    rateLimit.perWindow = limit;
  };
}
