import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { hostsIn, cidrsIn, broadNetwork, spoofableOnly, ipInCidr } from "../src/core/checks/expr.ts";
import { parseDkim } from "../src/core/deep-dns.ts";
import { probeTakeovers, takeoverCandidates } from "../src/core/probe.ts";
import { Scanner } from "../src/scanner.ts";
import { inventory, zone, record } from "./fixtures/inventory.ts";
import { installMockCloudflare, MOCK_ACCOUNT } from "../dev/mock/cloudflare.ts";
import { seedAccount, testRepo } from "../dev/mock/accounts.ts";

import { evaluated, failing as findings, failuresOf as of } from "./helpers/checks.ts";

describe("baseline", () => {
  test("a well-configured account still has no findings with the deep checks", () => {
    assert.deepEqual(
      findings(inventory()).map((f) => f.checkId),
      [],
    );
  });
});

describe("rule expressions", () => {
  test("hosts, CIDRs, broad networks and forgeable inputs", () => {
    assert.deepEqual(hostsIn('(http.host eq "a.example.com") or http.host in {"b.example.com" "c.example.com"}').sort(), [
      "a.example.com",
      "b.example.com",
      "c.example.com",
    ]);
    assert.deepEqual(cidrsIn("ip.src in {10.0.0.0/8 192.0.2.1} and ip.src eq 203.0.113.7"), ["10.0.0.0/8", "192.0.2.1", "203.0.113.7"]);
    assert.equal(broadNetwork("ip.src in {10.0.0.0/8}"), "10.0.0.0/8");
    assert.equal(broadNetwork("ip.src in {203.0.113.0/24}"), null);
    assert.match(broadNetwork("ip.geoip.asnum eq 16509")!, /asnum/);
    assert.deepEqual(spoofableOnly('http.request.headers["x-internal"][0] eq "yes"'), ["a request header"]);
    assert.equal(spoofableOnly('http.request.headers["x-internal"][0] eq "yes" and ip.src in $office'), null);
    assert.equal(spoofableOnly('starts_with(http.request.uri.path, "/api")'), null);
    assert.ok(ipInCidr("10.1.2.3", "10.0.0.0/8") && !ipInCidr("11.0.0.1", "10.0.0.0/8"));
  });
});

describe("attack surface", () => {
  test("ATS-001: origin IP published by a DNS-only record and SPF, critical when unlocked", () => {
    const z = zone("example.com", { aop: { enabled: false } });
    z.dns.push(record("app.example.com", "A", "198.51.100.7", { proxied: true }));
    z.dns.push(record("direct.example.com", "A", "198.51.100.7"));
    z.dns.push(record("example.com", "TXT", '"v=spf1 ip4:198.51.100.0/24 -all"'));
    z.dns = z.dns.filter((r) => !(r.type === "TXT" && r.content.includes("_spf.example.net")));
    const f = of(inventory({ zones: [z] }), "ATS-001").find((x) => x.resource === "app.example.com")!;
    assert.equal(f.severity, "critical");
    const chain = (f.evidence!.chain as { label: string; value: string }[]).map((s) => s.label);
    assert.ok(chain.includes("Published by a DNS-only record") && chain.includes("Listed in SPF"));
  });

  test("ATS-001/002 ignore multi-tenant platforms and placeholder records", () => {
    const z = zone("example.com", { aop: { enabled: false } });
    z.dns.push(
      record("site.example.com", "CNAME", "abc.vercel-dns-016.com", { proxied: true }),
      record("site-dev.example.com", "CNAME", "abc.vercel-dns-016.com"),
    );
    z.dns.push(record("www.example.com", "AAAA", "100::", { proxied: true }));
    const inv = inventory({ zones: [z] });
    assert.equal(of(inv, "ATS-001").length, 0);
    assert.doesNotMatch(of(inv, "ATS-002")[0]?.detail || "", /site\.example\.com|www\.example\.com/);
  });

  test("ATS-002: unlocked origins, unless a tunnel, Worker, AOP or origin-auth header protects them", () => {
    const z = zone("example.com", { aop: { enabled: false } });
    assert.equal(of(inventory({ zones: [z] }), "ATS-002").length, 1);
    const locked = zone("example.com", {
      aop: { enabled: false },
      phases: {
        http_request_late_transform: {
          rules: [
            {
              action: "rewrite",
              expression: 'http.host eq "example.com"',
              action_parameters: { headers: { "X-Origin-Auth": { operation: "set", value: "x".repeat(32) } } },
            },
          ],
        },
      },
    });
    assert.equal(of(inventory({ zones: [locked] }), "ATS-002").length, 0);
  });

  test("ATS-003: admin tools and internal names without Access; product names and covered hosts pass", () => {
    const z = zone("example.com");
    z.dns.push(
      record("grafana.example.com", "CNAME", "lb-1.elb.amazonaws.com"),
      record("ascend-vault-subgraph.example.com", "A", "203.0.113.9"),
      record("staging.example.com", "A", "203.0.113.10"),
      record("preview-staging.example.com", "CNAME", "x.vercel-dns-016.com"),
      record("kibana.example.com", "A", "203.0.113.11"),
    );
    const accessApps = [
      {
        type: "self_hosted",
        name: "Kibana",
        domain: "kibana.example.com",
        policies: [{ decision: "allow", include: [{ email_domain: { domain: "example.com" } }] }],
      },
    ];
    const fs = of(inventory({ zones: [z], accessApps }), "ATS-003");
    assert.deepEqual(fs.map((f) => [f.resource, f.severity]).sort(), [
      ["grafana.example.com", "high"],
      ["staging.example.com", "low"],
    ]);
    assert.ok(fs.every((f) => f.confidence === "likely"));
  });

  test("ATS-004/005/006: tunnel exposure, TLS verification and DNS drift", () => {
    const z = zone("example.com");
    z.dns.push(record("ssh.example.com", "CNAME", "11111111-1111-1111-1111-111111111111.cfargotunnel.com", { proxied: true }));
    z.dns.push(record("lost.example.com", "CNAME", "11111111-1111-1111-1111-111111111111.cfargotunnel.com", { proxied: true }));
    const inv = inventory({
      zones: [z],
      tunnels: [{ id: "11111111-1111-1111-1111-111111111111", name: "edge", status: "healthy" }],
      tunnelIngress: {
        "11111111-1111-1111-1111-111111111111": [
          { hostname: "ssh.example.com", service: "ssh://localhost:22" },
          { hostname: "app.example.com", service: "https://localhost:8443", originRequest: { noTLSVerify: true } },
          { service: "http_status:404" },
        ],
      },
    });
    assert.equal(of(inv, "ATS-004")[0].resource, "ssh.example.com");
    assert.equal(of(inv, "ATS-005")[0].resource, "app.example.com");
    assert.deepEqual(
      of(inv, "ATS-006")
        .map((f) => f.resource)
        .sort(),
      ["app.example.com (route)", "lost.example.com (DNS)"],
    );
  });

  test("ATS-007: probe results become confirmed or likely takeovers", () => {
    const inv = inventory({
      takeover: [
        { host: "files.example.com", target: "gone.s3.amazonaws.com", provider: "Amazon S3", status: 404, unclaimed: true, match: "NoSuchBucket" },
        {
          host: "site.example.com",
          target: "x.vercel-dns-016.com",
          provider: "Vercel",
          status: 404,
          unclaimed: true,
          match: "DEPLOYMENT_NOT_FOUND",
          verifiedProvider: true,
        },
        { host: "ok.example.com", target: "live.s3.amazonaws.com", provider: "Amazon S3", status: 200, unclaimed: false, match: null },
      ],
    });
    const fs = of(inv, "ATS-007");
    assert.deepEqual(fs.map((f) => [f.resource, f.confidence]).sort(), [
      ["files.example.com", "confirmed"],
      ["site.example.com", "likely"],
    ]);
    assert.ok(fs.every((f) => f.severity === "critical"));
  });

  test("ATS-008: lame delegation", () => {
    const inv = inventory();
    inv.deepDns.delegations = {
      "dev.example.com": { ns: ["ns1.gone.example"], status: "unresolvable", detail: "None of the nameservers exist" },
      "ok.example.com": { ns: ["a"], status: "ok", detail: "" },
    };
    assert.deepEqual(
      of(inv, "ATS-008").map((f) => f.resource),
      ["dev.example.com"],
    );
  });
});

describe("rules", () => {
  test("WAF-012: managed rules switched to log-only; paranoia levels alone are fine", () => {
    const z = zone("example.com", {
      wafManaged: {
        rules: [
          { action: "execute", enabled: true, action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee", overrides: { action: "log" } } },
          {
            action: "execute",
            enabled: true,
            action_parameters: { id: "4814384a9e5d4991b9815dcfc25d2f1f", overrides: { categories: [{ category: "paranoia-level-2", enabled: false }] } },
          },
        ],
      },
    });
    const fs = of(inventory({ zones: [z] }), "WAF-012");
    assert.equal(fs.length, 1);
    assert.equal(fs[0].severity, "high");
  });

  test("WAF-013/014: skips keyed on headers or broad networks", () => {
    const z = zone("example.com", {
      wafCustom: {
        rules: [
          {
            action: "skip",
            enabled: true,
            description: "partner",
            expression: 'http.request.headers["x-partner"][0] eq "secret"',
            action_parameters: { phases: ["http_request_firewall_managed"] },
          },
          { action: "skip", enabled: true, description: "cloud", expression: "ip.src in {10.0.0.0/8}", action_parameters: { ruleset: "current" } },
          { action: "skip", enabled: true, description: "office", expression: "ip.src in {203.0.113.0/24}", action_parameters: { ruleset: "current" } },
        ],
      },
    });
    const inv = inventory({ zones: [z] });
    assert.deepEqual(
      of(inv, "WAF-013").map((f) => f.resource),
      ["partner"],
    );
    assert.deepEqual(
      of(inv, "WAF-014").map((f) => f.resource),
      ["cloud"],
    );
  });

  test("WAF-015/016/017/018: stale hosts, toothless rate limits, downgrades and secrets", () => {
    const z = zone("example.com", {
      rateLimit: {
        rules: [
          {
            enabled: true,
            action: "log",
            description: "login",
            expression: 'http.host eq "old.example.com"',
            ratelimit: { requests_per_period: 10, period: 60 },
          },
        ],
      },
      phases: {
        http_config_settings: {
          rules: [{ enabled: true, description: "api", expression: 'http.host eq "example.com"', action_parameters: { security_level: "essentially_off" } }],
        },
        http_request_late_transform: {
          rules: [
            {
              enabled: true,
              description: "lock",
              expression: 'http.host eq "example.com"',
              action_parameters: { headers: { "X-Api-Key": { operation: "set", value: "s3cr3t-s3cr3t-s3cr3t" } } },
            },
          ],
        },
      },
      pageRules: [{ status: "active", targets: [{ constraint: { value: "example.com/admin*" } }], actions: [{ id: "ssl", value: "flexible" }] }],
    });
    const inv = inventory({ zones: [z] });
    assert.match(of(inv, "WAF-015")[0].detail, /old\.example\.com/);
    assert.match(of(inv, "WAF-016")[0].detail, /only logs/);
    assert.equal(of(inv, "WAF-017").length, 2);
    const secret = of(inv, "WAF-018")[0];
    assert.ok(!JSON.stringify(secret).includes("s3cr3t"), "the secret value must never be stored");
  });
});

describe("TLS, email, Zero Trust", () => {
  test("TLS-010: two-level names aren't covered by the universal wildcard", () => {
    const z = zone("example.com");
    z.dns.push(record("a.b.example.com", "A", "203.0.113.20", { proxied: true }), record("b.example.com", "A", "203.0.113.21", { proxied: true }));
    assert.deepEqual(
      of(inventory({ zones: [z] }), "TLS-010").map((f) => f.resource),
      ["a.b.example.com"],
    );
  });

  test("TLS-011: Origin CA certificate expiring", () => {
    const z = zone("example.com", {
      originCerts: [
        { hostnames: ["example.com"], expires_on: "2026-06-10 00:00:00 +0000 UTC" },
        { hostnames: ["x.example.com"], expires_on: "2030-01-01 00:00:00 +0000 UTC" },
      ],
    });
    assert.deepEqual(
      of(inventory({ zones: [z] }), "TLS-011").map((f) => f.detail),
      ["Expires in 9 days (2026-06-10)."],
    );
  });

  test("EML-007/008/009: weak DKIM, unauthorized DMARC reports, missing MTA-STS", () => {
    const inv = inventory();
    inv.deepDns.dkim = {
      "s1._domainkey.example.com": { bits: 1024, type: "rsa", revoked: false },
      "s2._domainkey.example.com": { bits: 2048, type: "rsa", revoked: false },
    };
    inv.deepDns.dmarcAuth = { "example.com|reports.example.net": false };
    inv.deepDns.mtaSts = { "example.com": false };
    assert.deepEqual(
      of(inv, "EML-007").map((f) => f.resource),
      ["s1._domainkey.example.com"],
    );
    assert.equal(of(inv, "EML-008").length, 1);
    assert.equal(of(inv, "EML-009").length, 1);
  });

  test("DKIM key size from the record", () => {
    assert.equal(parseDkim("v=DKIM1; k=rsa; p=" + "A".repeat(216))!.bits, 1024);
    assert.equal(parseDkim("v=DKIM1; k=rsa; p=" + "A".repeat(392))!.bits, 2048);
    assert.equal(parseDkim("v=DKIM1; p=")!.revoked, true);
    assert.equal(parseDkim("v=DKIM1; k=ed25519; p=abc")!.type, "ed25519");
  });

  test("ZT-009: service tokens unused for 90 days or never used", () => {
    const inv = inventory({
      serviceTokens: [
        { name: "never", created_at: "2026-01-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z", duration: "8760h", last_seen_at: null },
        { name: "stale", created_at: "2025-01-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z", duration: "8760h", last_seen_at: "2026-01-01T00:00:00Z" },
        { name: "busy", created_at: "2025-01-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z", duration: "8760h", last_seen_at: "2026-05-30T00:00:00Z" },
      ],
    });
    assert.deepEqual(
      of(inv, "ZT-009")
        .map((f) => f.resource)
        .sort(),
      ["never", "stale"],
    );
  });
});

describe("change risk", () => {
  const actor = { email: "dev@example.com", type: "user", ip: "198.51.100.1" };
  test("CHG-001/002/003 from audit before-and-after values; a clean week passes", () => {
    const audit = [
      {
        when: "2026-05-30T10:00:00Z",
        actor,
        action: { type: "rulesets_update", result: true },
        metadata: { zone_name: "example.com" },
        oldValueJson: { modified_rules: [{ id: "r1", action: "block", description: "Block bad bots", enabled: true, expression: "true" }] },
        newValueJson: { modified_rules: [{ id: "r1", action: "block", description: "Block bad bots", enabled: false, expression: "true" }] },
      },
      {
        when: "2026-05-30T11:00:00Z",
        actor,
        action: { type: "access_update_policy", result: true },
        oldValue: JSON.stringify({ name: "Admins", decision: "allow", include: [{ email_domain: { domain: "example.com" } }] }),
        newValue: JSON.stringify({
          name: "Admins",
          decision: "allow",
          include: [{ email_domain: { domain: "example.com" } }, { email: { email: "friend@gmail.com" } }],
        }),
      },
      {
        when: "2026-05-30T12:00:00Z",
        actor,
        action: { type: "change_setting", result: true },
        metadata: { name: "SSL", value: "flexible", zone_name: "example.com" },
      },
    ];
    const inv = inventory({ audit });
    assert.match(of(inv, "CHG-001")[0].detail, /Block bad bots/);
    assert.match(of(inv, "CHG-002")[0].detail, /friend@gmail\.com/);
    assert.match(of(inv, "CHG-003")[0].detail, /SSL to flexible/);
    assert.deepEqual(
      evaluated(inventory(), "CHG-001").map((r) => r.pass),
      [true],
    );
  });
});

describe("takeover probe", () => {
  test("only CNAMEs to known providers are probed, and fingerprints must match the provider", async () => {
    const z = zone("example.com");
    z.dns.push(
      record("files.example.com", "CNAME", "gone.s3.amazonaws.com"),
      record("app.example.com", "CNAME", "lb.example.net"),
      record("docs.example.com", "CNAME", "org.github.io"),
    );
    const targets = takeoverCandidates([z]);
    assert.deepEqual(targets.map((t) => t.host).sort(), ["docs.example.com", "files.example.com"]);
    const real = globalThis.fetch;
    const seen: string[] = [];
    globalThis.fetch = (async (url: string) => {
      seen.push(new URL(url).hostname);
      return url.includes("files") ? new Response("<Error><Code>NoSuchBucket</Code></Error>", { status: 404 }) : new Response("<h1>Docs</h1>", { status: 200 });
    }) as typeof fetch;
    after(() => {
      globalThis.fetch = real;
    });
    const res = await probeTakeovers(targets);
    assert.deepEqual(
      res.filter((r) => r.unclaimed).map((r) => r.host),
      ["files.example.com"],
    );
    assert.deepEqual([...new Set(seen)].sort(), ["docs.example.com", "files.example.com"]);
  });

  test("with probes off a full scan makes no request outside Cloudflare", async () => {
    const hosts = new Set<string>();
    const restore = installMockCloudflare({ onRequest: (u) => hosts.add(u.hostname) });
    after(restore);
    const { repo, vault } = testRepo();
    seedAccount(repo, vault);
    await new Scanner(repo, vault, () => {}).start("t").done;
    assert.deepEqual(
      [...hosts].filter((h) => h !== "api.cloudflare.com" && h !== "cloudflare-dns.com"),
      [],
    );
    const ids = new Set(repo.findings.forScan(repo.scans.latest(MOCK_ACCOUNT)!.id as number, repo.settings.get().slaDays).map((f) => f.checkId));
    assert.ok(ids.has("WAF-017") && ids.has("TLS-011") && ids.has("ATS-002"), [...ids].join(","));
  });
});
