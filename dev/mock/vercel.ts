// A fetch replacement that serves a small, fictional Vercel API, so Vercel scans
// run end to end without network access (tests and `npm run dev -- --mock`). It
// chains onto whatever fetch is installed, so it works together with the
// Cloudflare mock.
//
// Two tokens: one reaches the "Mock Web" team (Pro), whose app.mock.example also
// sits in the Cloudflare mock; the other reaches a personal Hobby account. As with
// the Cloudflare mock, the data is deliberately imperfect so every check family
// has something to find, and dates are relative to now.

const DAY = 86_400_000;
const ago = (days: number) => Date.now() - days * DAY;
const ahead = (days: number) => Date.now() + days * DAY;

export const MOCK_VERCEL_TEAM = "team_MockWeb0000000000000001";
export const MOCK_VERCEL_TOKEN = "mock-vercel-token-0123456789-SECRET";
export const MOCK_VERCEL_USER = "MockUser0000000000000001";
export const MOCK_VERCEL_TOKEN_2 = "mock-vercel-token-2-abcdefghij-SECRET";

interface MockOptions {
  onRequest?: (url: URL, init?: RequestInit) => void;
  /** Paths (regex) that answer 403, to simulate a role that can't read them. */
  deny?: RegExp[];
}

const team = {
  id: MOCK_VERCEL_TEAM,
  slug: "mock-web",
  name: "Mock Web",
  billing: { plan: "pro" },
  saml: { connection: { type: "OktaSAML", status: "linked", state: "active" }, enforced: false },
  sensitiveEnvironmentVariablePolicy: "off",
  emailDomain: "mock.example",
  mfa: { enforced: false, updatedAt: ago(100) },
};

const member = (uid: string, email: string, role: string, days: number) => ({
  uid,
  email,
  username: email.split("@")[0],
  role,
  confirmed: true,
  createdAt: ago(days),
  joinedFrom: { origin: "link" },
});

const env = (key: string, type: string, target: string[], extra: Record<string, unknown> = {}) => ({
  id: `env_${key}`,
  key,
  type,
  target,
  // The mock returns values like the real API would, so the scanner's job of dropping them is tested.
  value: type === "sensitive" ? "" : `mock-value-for-${key}`,
  createdAt: ago(100),
  updatedAt: ago(10),
  ...extra,
});

/**
 * As Vercel stores it: the firewall configuration holds custom rules, IP rules and the OWASP core ruleset
 * (`crs`); managed rulesets live on the project (`security.managedRules`, see `security()`). A project that
 * was never configured has neither, and its configuration answers 404.
 */
const firewall = (o: { enabled: boolean; logRule?: boolean; wideBypass?: boolean; owaspLogOnly?: boolean }) => ({
  id: "fw",
  version: 3,
  firewallEnabled: o.enabled,
  crs: o.owaspLogOnly
    ? {
        sqli: { active: true, action: "log" },
        xss: { active: true, action: "log" },
        rce: { active: true, action: "log" },
        lfi: { active: false, action: "log" },
      }
    : { sqli: { active: true, action: "deny" }, xss: { active: true, action: "deny" } },
  rules: [
    { id: "r1", name: "Rate limit sign-in", active: true, action: { mitigate: { action: "rate_limit" } }, conditionGroup: [] },
    ...(o.logRule ? [{ id: "r2", name: "Block old API", active: true, action: { mitigate: { action: "log" } }, conditionGroup: [] }] : []),
  ],
  ips: o.wideBypass ? [{ id: "ip1", ip: "100.64.0.0/10", action: "bypass", hostname: "app.mock.example", notes: "office" }] : [],
});

const security = (o: { enabled: boolean; bots: boolean; aiBots: boolean }) => ({
  firewallEnabled: o.enabled,
  firewallConfigVersion: 3,
  managedRules: { bot_filter: { active: o.bots }, ai_bots: { active: o.aiBots }, owasp: { active: false }, vercel_ruleset: { active: false } },
});

interface MockProject {
  project: Record<string, unknown>;
  domains: { name: string; verified: boolean; redirect?: string | null }[];
  env: ReturnType<typeof env>[];
  firewall: ReturnType<typeof firewall> | null;
}

const TEAM_PROJECTS: MockProject[] = [
  {
    project: {
      id: "prj_web00000000000000000001",
      name: "web",
      framework: "nextjs",
      nodeVersion: "22.x",
      createdAt: ago(400),
      link: { type: "github", repo: "web", org: "mock-co", productionBranch: "main", deployHooks: [] },
      ssoProtection: { deploymentType: "preview" },
      gitForkProtection: true,
      directoryListing: false,
      protectedSourcemaps: true,
      oidcTokenConfig: { enabled: true, issuerMode: "team" },
      deploymentExpiration: { expirationDays: 90 },
      protectionBypass: { "mock-bypass-secret": { scope: "automation-bypass", createdAt: ago(200), createdBy: "u1", note: "e2e" } },
      security: security({ enabled: true, bots: true, aiBots: false }),
      // A cron job with no CRON_SECRET among the project's variables.
      crons: { enabledAt: ago(100), definitions: [{ host: "web-mock.vercel.app", path: "/api/cron/digest", schedule: "0 8 * * *" }] },
      installCommand: "npm config set //registry.npmjs.org/:_authToken=$NPM_TOKEN && npm ci",
      targets: { production: { id: "dpl_web", readyState: "READY", createdAt: ago(3) } },
    },
    domains: [
      { name: "app.mock.example", verified: true },
      { name: "web-mock.vercel.app", verified: true },
    ],
    env: [
      env("DATABASE_URL", "sensitive", ["production"]),
      env("STRIPE_SECRET_KEY", "encrypted", ["production", "preview"]),
      env("NEXT_PUBLIC_API_URL", "plain", ["production", "preview", "development"]),
      env("POSTGRES_URL", "encrypted", ["production"], { configurationId: "icfg_1", contentHint: { type: "postgres-url", storeId: "store_1" } }),
    ],
    firewall: firewall({ enabled: true, logRule: true, wideBypass: true, owaspLogOnly: true }),
  },
  {
    project: {
      id: "prj_mkt00000000000000000002",
      name: "marketing",
      framework: "astro",
      nodeVersion: "18.x",
      createdAt: ago(700),
      link: {
        type: "github",
        repo: "marketing",
        org: "mock-co",
        productionBranch: "main",
        deployHooks: [{ id: "h1", name: "cms", ref: "main", url: "https://api.vercel.com/v1/integrations/deploy/prj/x" }],
      },
      gitForkProtection: false,
      directoryListing: true,
      protectedSourcemaps: false,
      // Never configured: no security block, and the firewall configuration answers 404.
      // A credential written straight into the install command.
      installCommand: "npm config set //registry.npmjs.org/:_authToken=npm_MockMockMockMockMockMockMock0000 && npm ci",
      targets: { production: { id: "dpl_mkt", readyState: "READY", createdAt: ago(500) } },
    },
    domains: [
      { name: "launch.mock-web.dev", verified: true },
      { name: "promo.mock.example", verified: false },
    ],
    env: [env("PUBLIC_SENDGRID_API_KEY", "plain", ["production", "preview"]), env("CMS_TOKEN", "plain", ["production"])],
    firewall: null,
  },
  {
    project: {
      id: "prj_int00000000000000000003",
      name: "internal-tool",
      framework: "vite",
      nodeVersion: "24.x",
      createdAt: ago(90),
      ssoProtection: { deploymentType: "all" },
      gitForkProtection: true,
      directoryListing: false,
      protectedSourcemaps: true,
      oidcTokenConfig: { enabled: true, issuerMode: "global" },
      deploymentExpiration: { expirationDays: 30 },
      security: security({ enabled: false, bots: true, aiBots: true }),
    },
    domains: [{ name: "internal-tool-mock.vercel.app", verified: true }],
    env: [env("ADMIN_PASSWORD", "encrypted", ["production"], { securityIssues: ["readable-secret"] })],
    firewall: firewall({ enabled: false }),
  },
];

const PERSONAL_PROJECTS: MockProject[] = [
  {
    project: {
      id: "prj_blog0000000000000000004",
      name: "blog",
      framework: "nextjs",
      nodeVersion: "20.x",
      createdAt: ago(300),
      link: { type: "github", repo: "blog", org: "sam", productionBranch: "main", deployHooks: [] },
      gitForkProtection: true,
      directoryListing: false,
      security: security({ enabled: true, bots: false, aiBots: false }),
    },
    domains: [{ name: "sam-blog.example", verified: true }],
    env: [env("OPENAI_API_KEY", "encrypted", ["production", "preview", "development"])],
    firewall: firewall({ enabled: true }),
  },
];

const TEAM_DATA = {
  members: [
    member("u1", "owner1@mock.example", "OWNER", 900),
    member("u2", "owner2@mock.example", "OWNER", 800),
    member("u3", "owner3@mock.example", "OWNER", 600),
    member("u4", "owner4@mock.example", "OWNER", 300),
    member("u5", "dev@mock.example", "DEVELOPER", 200),
    member("u6", "contractor@gmail.com", "MEMBER", 120),
    // Asked to join three weeks ago; nobody has approved it.
    { ...member("u7", "visitor@gmail.com", "MEMBER", 21), confirmed: false, joinedFrom: { origin: "nsnb-request-access" } },
  ],
  invites: [{ id: "inv1", email: "new.hire@mock.example", role: "DEVELOPER", createdAt: ago(30), expired: false }],
  domains: [
    { id: "d1", name: "mock-web.dev", verified: true, boughtAt: ago(345), expiresAt: ahead(20), renew: false, nameservers: ["ns1.vercel-dns.com"] },
    { id: "d2", name: "mock.example", verified: true, nameservers: ["ns.cloudflare.com"] },
  ],
  certs: [{ id: "cert_1", cns: ["legacy.mock.example"], expiresAt: ahead(10), autoRenew: false, createdAt: ago(355) }],
  drains: [
    {
      id: "dr1",
      name: "datadog",
      delivery: { type: "http", endpoint: "http://logs.mock.example/ingest?key=hidden", headers: { Authorization: "Bearer mock-drain-header-SECRET" } },
      projectIds: [],
    },
    {
      id: "dr2",
      name: "archive",
      delivery: { type: "s3", endpoint: "s3://mock-logs", objectAcl: "public-read", region: "us-east-1" },
      firstErrorTimestamp: ago(3),
      projectIds: [],
    },
  ],
  webhooks: [{ id: "wh1", url: "https://hooks.mock.example/vercel?token=hidden", events: ["deployment.created", "deployment.error"], projectIds: [] }],
};

const TOKENS = {
  [MOCK_VERCEL_TOKEN]: [
    {
      id: "tok1",
      name: "edgewatch",
      createdAt: ago(5),
      activeAt: ago(0),
      expiresAt: ahead(360),
      scopes: [{ type: "team", teamId: MOCK_VERCEL_TEAM, origin: "manual" }],
    },
    { id: "tok2", name: "ci-deploy", createdAt: ago(400), activeAt: ago(200), scopes: [{ type: "team", teamId: MOCK_VERCEL_TEAM, origin: "manual" }] },
    {
      id: "tok3",
      name: "old-script",
      createdAt: ago(500),
      activeAt: ago(30),
      leakedAt: ago(12),
      leakedUrl: "https://github.com/mock-co/old-script",
      scopes: [{ type: "user" }],
    },
  ],
  [MOCK_VERCEL_TOKEN_2]: [{ id: "tok4", name: "laptop", createdAt: ago(40), activeAt: ago(1), scopes: [{ type: "user" }] }],
} as Record<string, unknown[]>;

/** What a token reaches: the team, or the personal account. */
const reach = (token: string) => (token === MOCK_VERCEL_TOKEN ? "team" : token === MOCK_VERCEL_TOKEN_2 ? "personal" : null);

export function installMockVercel(o: MockOptions = {}): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (url.hostname !== "api.vercel.com") return real(input as string, init);
    o.onRequest?.(url, init);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const fail = (status: number, message: string) => json({ error: { code: String(status), message } }, status);
    const token = String(new Headers(init?.headers).get("authorization") || "").replace(/^Bearer /, "");
    const who = reach(token);
    if (!who) return fail(403, "Not authorized");
    if ((init?.method || "GET") !== "GET") return fail(405, "The mock only reads");
    if (o.deny?.some((re) => re.test(url.pathname))) return fail(403, "You don't have permission to access this resource.");

    const path = url.pathname;
    const teamId = url.searchParams.get("teamId") ?? /^\/v\d\/teams\/(team_[^/]+)/.exec(path)?.[1] ?? null;
    if (teamId && (who !== "team" || teamId !== MOCK_VERCEL_TEAM)) return fail(403, "Not authorized for this team");
    const projects = teamId ? TEAM_PROJECTS : who === "personal" ? PERSONAL_PROJECTS : null;

    if (path === "/v2/user")
      return json({
        user:
          who === "team" ? { id: "MockOwner000000000000001", username: "owner1", name: "Owner One" } : { id: MOCK_VERCEL_USER, username: "sam", name: "Sam" },
      });
    if (path === "/v2/teams") return json({ teams: who === "team" ? [team] : [], pagination: { count: who === "team" ? 1 : 0, next: null, prev: null } });
    if (path === `/v2/teams/${MOCK_VERCEL_TEAM}`) return json(team);
    if (path === `/v3/teams/${MOCK_VERCEL_TEAM}/members`)
      return json({
        members: TEAM_DATA.members,
        emailInviteCodes: TEAM_DATA.invites,
        pagination: { hasNext: false, count: TEAM_DATA.members.length, next: null, prev: null },
      });
    if (path === "/v6/user/tokens") return json({ tokens: TOKENS[token] ?? [], pagination: { count: (TOKENS[token] ?? []).length, next: null, prev: null } });
    // The team-scoped token can't read the personal account's projects.
    if (!projects) return fail(403, "This token is scoped to a team");

    if (path === "/v10/projects") return json({ projects: projects.map((p) => p.project), pagination: { count: projects.length, next: null, prev: null } });
    const byId = (id: string) => projects.find((p) => p.project.id === decodeURIComponent(id));
    let m = /^\/v9\/projects\/([^/]+)\/domains$/.exec(path);
    if (m) {
      const p = byId(m[1]);
      return p
        ? json({
            domains: p.domains.map((d) => ({ ...d, projectId: p.project.id, apexName: d.name })),
            pagination: { count: p.domains.length, next: null, prev: null },
          })
        : fail(404, "Not found");
    }
    m = /^\/v10\/projects\/([^/]+)\/env$/.exec(path);
    if (m) {
      const p = byId(m[1]);
      return p ? json({ envs: p.env }) : fail(404, "Not found");
    }
    if (path === "/v1/security/firewall/config/active") {
      const p = byId(url.searchParams.get("projectId") || "");
      return p?.firewall ? json(p.firewall) : fail(404, "Not found");
    }
    const data = teamId ? TEAM_DATA : null;
    if (path === "/v5/domains") return json({ domains: data?.domains ?? [], pagination: { count: data?.domains.length ?? 0, next: null, prev: null } });
    if (path === "/v8/certs") return json({ certs: data?.certs ?? [], pagination: { count: data?.certs.length ?? 0, next: null, prev: null } });
    if (path === "/v1/drains") return json({ drains: data?.drains ?? [] });
    if (path === "/v1/webhooks") return json(data?.webhooks ?? []);
    if (path === "/v1/integrations/configurations")
      return json(
        teamId
          ? [
              {
                id: "icfg_ci",
                slug: "mock-ci",
                projectSelection: "all",
                projects: [],
                scopes: ["read-write:project", "read:team"],
                installationType: "external",
              },
              {
                id: "icfg_db",
                slug: "mock-db",
                projectSelection: "selected",
                projects: ["prj_web00000000000000000001"],
                scopes: ["read-write:integration-resource"],
              },
            ]
          : [],
      );
    if (path === "/v1/env")
      return json({
        data: teamId ? [env("SHARED_API_TOKEN", "encrypted", ["production", "preview", "development"])] : [],
        pagination: { count: 1, next: null, prev: null },
      });
    return fail(404, `No mock for ${path}`);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}
