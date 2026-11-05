import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/core/engine.ts";
import { CHECKS } from "../src/core/catalog.ts";
import { inventory, zone, record, opts, goodSettings } from "./fixtures/inventory.ts";

import { evaluated, failIds, failing } from "./helpers/checks.ts";

describe("baseline", () => {
  test("a well-configured account has no custom findings", () => {
    assert.deepEqual([...failIds(inventory())], []);
  });

  test("every catalog check has a title, why and fix", () => {
    for (const c of CHECKS) assert.ok(c.title && c.why && c.fix, c.id);
  });
});

describe("identity", () => {
  test("member without 2FA and too many super admins", () => {
    const members = Array.from({ length: 5 }, (_, i) => ({
      status: "accepted",
      user: { email: `u${i}@example.com`, two_factor_authentication_enabled: i > 0 },
      roles: [{ name: "Super Administrator - All Privileges" }],
    }));
    const f = failing(inventory({ members }));
    assert.equal(f.filter((x) => x.checkId === "IAM-001").length, 1);
    const iam2 = f.find((x) => x.checkId === "IAM-002")!;
    assert.equal(iam2.severity, "high");
    assert.match(iam2.detail, /5 of 5/);
  });

  test("external member and 2FA enforcement off", () => {
    const inv = inventory({ account: { settings: { enforce_twofactor: false } } });
    inv.members!.push({ status: "accepted", user: { email: "x@gmail.com", two_factor_authentication_enabled: true }, roles: [] });
    const ids = failIds(inv);
    assert.ok(ids.has("IAM-004") && ids.has("IAM-005"));
  });

  test("configured org domains count as internal", () => {
    const inv = inventory();
    inv.members!.push({ status: "accepted", user: { email: "x@corp.example.org", two_factor_authentication_enabled: true }, roles: [] });
    assert.ok(failIds(inv).has("IAM-004"));
    assert.ok(!failIds(inv, opts({ orgDomains: ["corp.example.org"] })).has("IAM-004"));
  });

  test("unreadable members means skipped, not passed", () => {
    assert.equal(evaluated(inventory({ members: null }), "IAM-001").length, 0);
  });
});

describe("zero trust", () => {
  test("external emails, bypass policies, long sessions", () => {
    const accessApps = [
      {
        id: "1",
        name: "Admin",
        type: "self_hosted",
        domain: "admin.example.com",
        session_duration: "168h",
        policies: [
          { name: "guests", decision: "allow", include: [{ email: { email: "friend@gmail.com" } }] },
          { name: "open", decision: "bypass", include: [{ everyone: {} }] },
        ],
      },
    ];
    const ids = failIds(inventory({ accessApps }));
    for (const id of ["ZT-001", "ZT-002", "ZT-003"]) assert.ok(ids.has(id), id);
  });

  test("service token expiry and one-time-PIN-only login", () => {
    const now = Date.parse("2026-06-01T00:00:00Z");
    const ids = failIds(
      inventory({
        accessIdps: [{ type: "onetimepin" }],
        serviceTokens: [
          { name: "ci", expires_at: new Date(now + 5 * 86_400_000).toISOString(), duration: "720h" },
          { name: "forever", expires_at: "2126-01-01T00:00:00Z", duration: "forever" },
        ],
      }),
    );
    for (const id of ["ZT-004", "ZT-005", "ZT-006"]) assert.ok(ids.has(id), id);
  });

  test("unhealthy tunnel and hostname pointing at a deleted tunnel", () => {
    const z = zone("example.com");
    z.dns.push(record("old.example.com", "CNAME", "11111111-2222-3333-4444-555555555555.cfargotunnel.com", { proxied: true }));
    const inv = inventory({
      zones: [z],
      tunnels: [{ id: "aaaaaaaa-2222-3333-4444-555555555555", name: "edge", status: "down" }],
      deletedTunnels: [{ id: "11111111-2222-3333-4444-555555555555", name: "retired", deleted_at: "2026-01-01T00:00:00Z" }],
    });
    const f = failing(inv);
    assert.ok(f.some((x) => x.checkId === "ZT-007"));
    assert.match(f.find((x) => x.checkId === "DNS-001")!.detail, /retired/);
  });
});

describe("edge", () => {
  test("weak TLS settings", () => {
    const s = {
      ...goodSettings(),
      ssl: "flexible",
      min_tls_version: "1.0",
      always_use_https: "off",
      security_header: { strict_transport_security: { enabled: false } },
    };
    const f = failing(inventory({ zones: [zone("example.com", { settings: s })] }));
    assert.equal(f.find((x) => x.checkId === "TLS-001")!.severity, "high");
    for (const id of ["TLS-002", "TLS-003", "TLS-004"])
      assert.ok(
        f.some((x) => x.checkId === id),
        id,
      );
  });

  test("paid zone without managed WAF is critical; free zones aren't judged on it", () => {
    const pro = zone("example.com", { wafManaged: { rules: [] } });
    assert.equal(failing(inventory({ zones: [pro] })).find((x) => x.checkId === "WAF-001")!.severity, "critical");
    const free = zone("example.com", { plan: "free", planName: "Free", wafManaged: null, bot: { fight_mode: true, ai_bots_protection: "block" } });
    assert.equal(evaluated(inventory({ zones: [free] }), "WAF-001").length, 0);
  });

  test("custom rule that skips managed rules", () => {
    const z = zone("example.com", {
      wafCustom: {
        rules: [
          { action: "skip", enabled: true, description: "skip api", expression: "true", action_parameters: { phases: ["http_request_firewall_managed"] } },
        ],
      },
    });
    assert.ok(failIds(inventory({ zones: [z] })).has("WAF-010"));
  });

  test("DNS-only zones are not judged on edge settings", () => {
    const z = zone("example.com", { settings: { ...goodSettings(), ssl: "off" } });
    z.dns = z.dns.map((r) => ({ ...r, proxied: false }));
    assert.equal(evaluated(inventory({ zones: [z] }), "TLS-001").length, 0);
  });
});

describe("dns", () => {
  test("dangling CNAME to a cloud provider is high", () => {
    const z = zone("example.com");
    z.dns.push(record("files.example.com", "CNAME", "gone-bucket.s3.amazonaws.com"));
    const f = failing(inventory({ zones: [z], resolved: { "gone-bucket.s3.amazonaws.com": { status: 3, answers: [] } } }));
    assert.equal(f.find((x) => x.checkId === "DNS-002")!.severity, "high");
  });

  test("CNAME with a path is invalid", () => {
    const z = zone("example.com");
    z.dns.push(record("go.example.com", "CNAME", "www.example.com/landing", { proxied: true }));
    assert.ok(failIds(inventory({ zones: [z] })).has("DNS-002"));
  });

  test("private IPs, CNAME conflicts, stale records, DNS-only wildcards", () => {
    const z = zone("example.com");
    z.dns.push(record("db.example.com", "A", "10.0.0.5"));
    z.dns.push(record("app.example.com", "CNAME", "app.example.net"), record("app.example.com", "TXT", '"verify"'));
    z.dns.push(record("*.dev.example.com", "A", "203.0.113.9"));
    z.lookups = { "example.com": 100, "db.example.com": 0, "app.example.com": 50 };
    const ids = failIds(inventory({ zones: [z] }));
    for (const id of ["DNS-003", "DNS-004", "DNS-005", "DNS-008"]) assert.ok(ids.has(id), id);
  });

  test("apex and proxied CNAMEs are not conflicts", () => {
    const z = zone("example.com");
    z.dns.push(record("example.com", "CNAME", "site.example.net"));
    assert.ok(!failIds(inventory({ zones: [z] })).has("DNS-004"));
  });

  test("DNSSEC off and missing CAA", () => {
    const z = zone("example.com", { dnssec: { status: "disabled" } });
    z.dns = z.dns.filter((r) => r.type !== "CAA");
    const ids = failIds(inventory({ zones: [z] }));
    assert.ok(ids.has("DNS-006") && ids.has("DNS-007"));
  });
});

describe("email", () => {
  test("missing SPF and DMARC on a mail domain", () => {
    const z = zone("example.com");
    z.dns = z.dns.filter((r) => r.type !== "TXT");
    const f = failing(inventory({ zones: [z] }));
    assert.ok(f.some((x) => x.checkId === "EML-001"));
    assert.equal(f.find((x) => x.checkId === "EML-002")!.severity, "high");
  });

  test("p=none and misnamed DMARC", () => {
    const z = zone("example.com");
    z.dns = z.dns.filter((r) => !r.name.startsWith("_dmarc"));
    z.dns.push(record("_dmarc.example.com", "TXT", '"v=DMARC1; p=none; rua=mailto:x@example.net"'), record("dmarc.example.com", "TXT", '"v=DMARC1; p=reject"'));
    const f = failing(inventory({ zones: [z] }));
    assert.equal(f.find((x) => x.checkId === "EML-002")!.severity, "medium");
    assert.ok(f.some((x) => x.checkId === "EML-003"));
  });

  test("parked domain must be locked down", () => {
    const z = zone("parked.example", { dns: [record("parked.example", "CAA", '0 issue "x"')] });
    assert.ok(failIds(inventory({ zones: [z] })).has("EML-004"));
    z.dns.push(record("parked.example", "TXT", '"v=spf1 -all"'), record("_dmarc.parked.example", "TXT", '"v=DMARC1; p=reject"'));
    assert.ok(!failIds(inventory({ zones: [z] })).has("EML-004"));
  });

  test("SPF over 10 lookups", () => {
    assert.ok(failIds(inventory({ spfLookups: { "example.com": 14 } })).has("EML-006"));
  });
});

describe("platform, monitoring, cost", () => {
  test("workers.dev exposure, public R2, missing alerts, low-traffic paid zone", () => {
    const ids = failIds(
      inventory({
        workers: [{ name: "api", subdomain: { enabled: true, previews_enabled: false } }],
        workersSubdomain: { subdomain: "example" },
        r2: [{ name: "assets", managed: { enabled: true, domain: "pub-1.r2.dev" } }],
        alertPolicies: [],
        traffic: { "zone-example.com": { requests: 50, cachedRequests: 0, threats: 0, bytes: 0 } },
      }),
    );
    for (const id of ["PLT-001", "PLT-002", "MON-001", "COST-001"]) assert.ok(ids.has(id), id);
  });
});

describe("options and Security Center", () => {
  test("disabled checks are dropped; severity overrides apply", () => {
    const inv = inventory({ account: { settings: { enforce_twofactor: false } } });
    assert.ok(!failIds(inv, opts({ disabledChecks: new Set(["IAM-005"]) })).has("IAM-005"));
    assert.equal(failing(inv, opts({ severityOverrides: { "IAM-005": "low" } })).find((x) => x.checkId === "IAM-005")!.severity, "low");
  });

  test("insights covered by our own failing check are merged, others imported", () => {
    const z = zone("example.com", { settings: { ...goodSettings(), always_use_https: "off" } });
    const insights = [
      {
        id: "1",
        issue_class: "always_https_not_enabled",
        issue_type: "insecure_configuration",
        severity: "Moderate",
        subject: "example.com",
        payload: { zone_tag: "zone-example.com" },
      },
      {
        id: "2",
        issue_class: "cname_record_not_proxied",
        issue_type: "exposed_infrastructure",
        severity: "Moderate",
        subject: "www.example.com",
        payload: { zone_tag: "zone-example.com", dns_record_content: "x.example.net." },
      },
    ];
    const r = evaluate(inventory({ zones: [z], insights }), opts());
    const sc = r.findings.filter((f) => f.source === "security_center");
    assert.deepEqual(
      sc.map((f) => f.checkId),
      ["SC:cname_record_not_proxied"],
    );
    assert.deepEqual(r.findings.find((f) => f.checkId === "TLS-003")!.corroborated, ["always_https_not_enabled"]);
    assert.equal(r.securityCenter.imported, 1);
  });
});
