// The rules every AWS check follows, as the other providers' checks do: each
// fails on its case, the well-configured fixture passes everything, and an
// unreadable source skips its checks instead of passing them. Then the judgement
// calls that make AWS findings worth reading.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { evaluateAws } from "../src/providers/aws/engine.ts";
import { AWS_CHECKS } from "../src/providers/aws/catalog.ts";
import { AWS_MODULES } from "../src/providers/aws/checks/index.ts";
import { AWS_SOURCES } from "../src/providers/aws/sources.ts";
import { DEPRECATED_RUNTIMES } from "../src/providers/aws/checks/compute.ts";
import { grantsEverything, trustOf } from "../src/providers/aws/inventory.ts";
import { addressHistory, ownEndpoints, awsLinks } from "../src/providers/aws/views.ts";
import { awsEndpointOf } from "../src/core/links.ts";
import { CATEGORIES } from "../src/core/categories.ts";
import { providerOfUrl } from "../src/shared/providers.ts";
import { AWS_CASE_OPTS, AWS_CASES, awsInventory, region, role } from "./aws-cases.ts";
import { inPrefixes, toPrefixes } from "../src/core/aws-ranges.ts";
import { secretInUserData } from "../src/providers/aws/inventory.ts";
import { accountOf } from "../src/providers/aws/checks/define.ts";
import { opts } from "./fixtures/inventory.ts";

const run = (inv = awsInventory(), o = {}) => evaluateAws(inv, opts(o));
const by = (r: ReturnType<typeof run>, id: string) => r.results.filter((x) => x.checkId === id);

test("every AWS check fails on its case", () => {
  const missing = AWS_CHECKS.filter((c) => !AWS_CASES[c.id]).map((c) => c.id);
  assert.deepEqual(missing, []);
  const silent = AWS_CHECKS.filter((c) => !run(AWS_CASES[c.id](), AWS_CASE_OPTS[c.id]).findings.some((f) => f.checkId === c.id)).map((c) => c.id);
  assert.deepEqual(silent, [], "these cases don't make their check fail");
});

test("the well-configured AWS account passes every check it evaluates", () => {
  const failing = run(awsInventory(), { related: { vercelDomains: [] } }).findings.map((f) => `${f.checkId} ${f.resource}`);
  assert.deepEqual(failing, []);
});

test("an AWS check whose source was unreadable reports nothing, even on its failing case", () => {
  const leaked: string[] = [];
  for (const c of AWS_CHECKS)
    for (const source of c.requires ?? []) {
      const inv = { ...AWS_CASES[c.id](), unreadable: [source] };
      if (run(inv, AWS_CASE_OPTS[c.id]).results.some((r) => r.checkId === c.id)) leaked.push(`${c.id} (${source})`);
    }
  assert.deepEqual(leaked, []);
});

test("AWS check metadata: shared categories, AWS docs, known sources, and every module file registered", () => {
  for (const c of AWS_CHECKS) {
    assert.match(c.id, /^(A[A-Z0-9]{2}|XP)-\d{3}$/, c.id);
    assert.ok((CATEGORIES as readonly string[]).includes(c.category), c.id);
    assert.ok(c.title && c.why && c.fix, c.id);
    assert.ok(!c.docs || providerOfUrl(c.docs) === (c.id.startsWith("XP-") ? providerOfUrl(c.docs) : "aws"), `${c.id} links AWS's docs`);
    for (const s of c.requires ?? []) assert.ok(s in AWS_SOURCES, `${c.id} requires a known source: ${s}`);
  }
  const dir = new URL("../src/providers/aws/checks/", import.meta.url);
  const files = readdirSync(dir).filter((f) => /^export default defineChecks\(/m.test(readFileSync(new URL(f, dir), "utf8")));
  assert.equal(files.length, AWS_MODULES.length, `modules on disk: ${files.join(", ")}`);
});

test("a bucket is public only when neither its own nor the account's block stops it", () => {
  const open = { name: "b", region: "eu-west-1", block: null, policyPublic: true, aclPublic: [] };
  const blocked = { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true };
  assert.equal(by(run(awsInventory({ s3Block: null, buckets: [open] })), "AS3-002")[0].pass, false);
  assert.equal(by(run(awsInventory({ s3Block: blocked, buckets: [open] })), "AS3-002")[0].pass, true, "the account's block restricts a public policy");
  assert.equal(by(run(awsInventory({ s3Block: null, buckets: [{ ...open, block: blocked }] })), "AS3-002")[0].pass, true, "so does the bucket's own");
  const acl = { ...open, policyPublic: null, aclPublic: ["everyone"] };
  assert.match(
    run(awsInventory({ s3Block: null, buckets: [acl] })).findings.find((f) => f.checkId === "AS3-002")!.detail,
    /ACL that grants access to everyone/,
  );
  // A bucket whose settings couldn't be read is left out, not passed.
  const unread = { name: "b", region: "eu-west-1", block: undefined, policyPublic: undefined, aclPublic: undefined };
  assert.equal(by(run(awsInventory({ buckets: [unread] })), "AS3-002").length, 0);
});

test("an open admin port is judged by what the group is attached to: public, private, or nothing", () => {
  const rule = [{ protocol: "tcp", from: 22, to: 22, cidr: "0.0.0.0/0" }];
  const group = { id: "sg-web", name: "web", vpcId: "vpc-1", open: rule };
  const finding = (id: string) =>
    run(awsInventory({ regions: [region({ securityGroups: [{ ...group, id }] })] })).findings.find((f) => f.checkId === "ANW-001")!;
  // On the instance's interface, which has a public address.
  assert.equal(finding("sg-web").severity, "high");
  assert.match(finding("sg-web").detail, /reachable on 1 public address: web \(i-1\)/);
  assert.ok(finding("sg-web").evidence?.chain?.some((s) => s.label === "Reachable from the internet"));
  // On the database's interface, which has none.
  assert.equal(finding("sg-db").severity, "medium");
  assert.match(finding("sg-db").detail, /attached to 1 network interface, none with a public address/);
  // On nothing at all.
  assert.equal(finding("sg-unused").severity, "low");
  assert.match(finding("sg-unused").detail, /not attached to anything/);
  // An all-traffic rule is one finding (ANW-003), not three.
  const all = run(awsInventory({ regions: [region({ securityGroups: [{ ...group, open: [{ protocol: "-1", from: null, to: null, cidr: "::/0" }] }] })] }));
  assert.deepEqual([...new Set(all.findings.map((f) => f.checkId))], ["ANW-003"]);
});

test("a public database behind a group that opens its port is critical, with the chain", () => {
  const db = { ...region().databases![0], public: true };
  const quiet = run(awsInventory({ regions: [region({ databases: [db] })] })).findings.find((f) => f.checkId === "ADB-001")!;
  assert.equal(quiet.severity, "medium", "a public address behind closed groups needs one more mistake");
  const open = { id: "sg-db", name: "db", vpcId: "vpc-1", open: [{ protocol: "tcp", from: 5432, to: 5432, cidr: "0.0.0.0/0" }] };
  const exposed = run(awsInventory({ regions: [region({ databases: [db], securityGroups: [open] })] })).findings.find((f) => f.checkId === "ADB-001")!;
  assert.equal(exposed.severity, "critical");
  assert.equal(exposed.evidence?.chain?.length, 2);
  // A read replica has no backups of its own.
  const replica = run(awsInventory({ regions: [region({ databases: [{ ...region().databases![0], backupDays: 0, replica: true }] })] }));
  assert.equal(by(replica, "ADB-003").length, 0);
});

test("per-region settings are judged only where something runs", () => {
  const idle = region({ instances: [], databases: [], loadBalancers: [], functions: [], guardDuty: false, ebsEncryptionByDefault: false });
  const r = run(awsInventory({ regions: [idle] }));
  for (const id of ["AMO-001", "AMO-002", "AEC-002"]) assert.equal(by(r, id).length, 0, id);
});

test("an administrator without keys passes, and one with a key is reported with how they are an administrator", () => {
  assert.equal(by(run(), "AID-008")[0].pass, true);
  const f = run(AWS_CASES["AID-008"]()).findings.find((x) => x.checkId === "AID-008")!;
  assert.match(f.detail, /through the AdministratorAccess policy, with 1 active access key/);
  // The password policy only matters when someone has a console password.
  const noConsole = awsInventory({ passwordPolicy: null, users: [awsInventory().users![1]] });
  assert.equal(by(run(noConsole), "AID-007").length, 0);
});

test("policy documents: full administrator access and who may assume a role", () => {
  assert.ok(grantsEverything([{ Effect: "Allow", Action: "*", Resource: "*" }]));
  assert.ok(grantsEverything([{ Effect: "Allow", Action: ["s3:Get*", "*"], Resource: ["*"] }]));
  assert.ok(!grantsEverything([{ Effect: "Allow", Action: "s3:*", Resource: "*" }]));
  assert.ok(!grantsEverything([{ Effect: "Deny", Action: "*", Resource: "*" }]));
  assert.ok(!grantsEverything([{ Effect: "Allow", Action: "*", Resource: "*", Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }]));
  assert.deepEqual(trustOf([{ Effect: "Allow", Principal: "*" }]), [{ principal: "*", kind: "anyone", conditional: false }]);
  assert.deepEqual(
    trustOf([{ Effect: "Allow", Principal: { AWS: ["arn:aws:iam::111122223333:root", "*"] }, Condition: { StringEquals: { "sts:ExternalId": "x" } } }]),
    [
      { principal: "arn:aws:iam::111122223333:root", kind: "account", conditional: true },
      { principal: "*", kind: "anyone", conditional: true },
    ],
  );
  // A wildcard with a condition (an external ID, an organization) isn't "anyone".
  const guarded = awsInventory({ roles: [role({ name: "r", trust: [{ principal: "*", kind: "anyone", conditional: true }] })] });
  assert.equal(by(run(guarded), "AID-009")[0].pass, true);
});

test("Route 53 records are compared with this account's endpoints and the entity's other AWS accounts", () => {
  const dangling = AWS_CASES["ADN-001"]();
  assert.equal(by(run(dangling), "ADN-001")[0].pass, false);
  const sibling = { related: { awsEndpoints: [{ kind: "cloudfront" as const, name: "d9gone.cloudfront.net" }] } };
  assert.equal(by(run(dangling, sibling), "ADN-001")[0].pass, true, "another AWS account in the entity has it");
  // An alias to S3's website endpoint names the bucket by the record's own name.
  const site = (buckets: string[]) =>
    awsInventory({
      buckets: buckets.map((name) => ({ name, region: "eu-west-1", block: null, policyPublic: null, aclPublic: [] })),
      s3Block: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true },
      hostedZones: [
        {
          id: "Z1",
          name: "example.com",
          private: false,
          records: [{ name: "static.example.com", type: "A", targets: ["s3-website-eu-west-1.amazonaws.com"], alias: true }],
        },
      ],
    });
  assert.equal(by(run(site(["static.example.com"])), "ADN-001")[0].pass, true);
  assert.equal(by(run(site([])), "ADN-001")[0].pass, false);
  // A load balancer in a region that refused the scan can't be judged, and incomplete endpoints aren't shared.
  const lb = awsInventory({
    skippedRegions: ["ap-south-1"],
    hostedZones: [
      {
        id: "Z1",
        name: "example.com",
        private: false,
        records: [{ name: "api.example.com", type: "A", targets: ["x-1.ap-south-1.elb.amazonaws.com"], alias: true }],
      },
    ],
  });
  assert.equal(by(run(lb), "ADN-001").length, 0);
  assert.deepEqual(awsLinks(lb), { awsAccounts: ["111122223333"], awsReleased: [] }, "only the account's ID is shared when a region couldn't be read");
  assert.equal(ownEndpoints(awsInventory({ distributions: null })), null);
  // XP-005 is skipped, not passed, when the entity has no scanned Vercel account.
  assert.equal(by(run(AWS_CASES["XP-005"]()), "XP-005").length, 0);
});

test("AWS endpoints are recognised by name", () => {
  assert.deepEqual(awsEndpointOf("d111111abcdef8.cloudfront.net."), { kind: "cloudfront", name: "d111111abcdef8.cloudfront.net" });
  assert.deepEqual(awsEndpointOf("dualstack.my-lb-1.eu-west-1.elb.amazonaws.com"), { kind: "elb", name: "my-lb-1.eu-west-1.elb.amazonaws.com" });
  assert.deepEqual(awsEndpointOf("my.bucket.s3-website-eu-west-1.amazonaws.com"), { kind: "s3", name: "my.bucket" });
  assert.deepEqual(awsEndpointOf("assets.s3.eu-west-1.amazonaws.com"), { kind: "s3", name: "assets" });
  assert.deepEqual(awsEndpointOf("assets.s3.amazonaws.com"), { kind: "s3", name: "assets" });
  for (const other of ["cname.vercel-dns.com", "ec2-203-0-113-9.compute-1.amazonaws.com", "example.com"]) assert.equal(awsEndpointOf(other), null, other);
});

test("deprecated Lambda runtimes are flagged and current ones aren't", () => {
  for (const r of [
    "nodejs",
    "nodejs8.10",
    "nodejs16.x",
    "nodejs18.x",
    "python2.7",
    "python3.8",
    "ruby2.7",
    "java8",
    "go1.x",
    "dotnetcore3.1",
    "dotnet6",
    "provided",
  ])
    assert.ok(DEPRECATED_RUNTIMES.test(r), r);
  for (const r of ["nodejs22.x", "python3.12", "python3.13", "java21", "java8.al2", "provided.al2023", "dotnet8", "ruby3.3"])
    assert.ok(!DEPRECATED_RUNTIMES.test(r), r);
});

test("an internet-facing instance with an administrator's role is critical while IMDSv1 is allowed", () => {
  const exposed = (extra: object) =>
    awsInventory({ roles: [role({ admin: true })], regions: [region({ instances: [{ ...region().instances![0], ...extra }] })] });
  const v2 = run(exposed({})).findings.find((f) => f.checkId === "AEC-007")!;
  assert.equal(v2.severity, "high");
  assert.equal(v2.evidence?.chain?.length, 4);
  assert.equal(run(exposed({ imdsV2: false })).findings.find((f) => f.checkId === "AEC-007")!.severity, "critical");
  // Not reachable, or no role: nothing to report, pass or fail.
  assert.equal(by(run(exposed({ publicIp: null })), "AEC-007").length, 0);
  assert.equal(by(run(exposed({ profile: null })), "AEC-007").length, 0);
  // A least-privilege role on a reachable instance passes.
  assert.equal(by(run(), "AEC-007")[0].pass, true);
});

test("the people and functions that hold administrator access raise their findings", () => {
  const noMfa = awsInventory({ users: [{ ...awsInventory().users![0], mfa: false }] });
  const admin = run(noMfa).findings.find((f) => f.checkId === "AID-003")!;
  assert.equal(admin.severity, "critical", "dana is an administrator");
  assert.match(admin.detail, /Administrator through the group Admins/);
  assert.equal(run({ ...noMfa, admins: [] }).findings.find((f) => f.checkId === "AID-003")!.severity, "high");
  const fn = (admin: boolean) =>
    awsInventory({
      roles: [role({ admin })],
      regions: [region({ functions: [{ name: "fn", runtime: "nodejs22.x", role: "app", urls: [{ authType: "NONE" }] }] })],
    });
  assert.equal(run(fn(true)).findings.find((f) => f.checkId === "AEC-006")!.severity, "high");
  assert.equal(run(fn(false)).findings.find((f) => f.checkId === "AEC-006")!.severity, "medium");
});

test("a role is only an outside trust when the account isn't in the entity and nothing conditions it", () => {
  const vendor = AWS_CASES["AID-011"]();
  assert.match(
    run(vendor).findings.find((f) => f.checkId === "AID-011")!.detail,
    /999988887777 can assume it without a condition.*Not used in the last 400 days/,
  );
  // The same account, once it is one of the entity's own.
  assert.equal(by(run(vendor, { related: { awsAccounts: ["999988887777"] } }), "AID-011")[0].pass, true);
  // With an external ID.
  const conditioned = awsInventory({ roles: [role({ trust: [{ principal: "999988887777", kind: "account", conditional: true }] })] });
  assert.equal(by(run(conditioned), "AID-011")[0].pass, true);
  // While another AWS account in the entity hasn't been scanned, nobody can say who is outside it.
  assert.equal(by(run(vendor, { related: { unknown: ["awsAccounts"] } }), "AID-011").length, 0);
  assert.equal(accountOf("arn:aws:iam::111122223333:role/x"), "111122223333");
  assert.equal(accountOf("111122223333"), "111122223333");
  assert.equal(accountOf("ec2.amazonaws.com"), null);
});

test("a Cloudflare-proxied hostname's origin must refuse everyone else", () => {
  const lbDns = region().loadBalancers![0].dnsName;
  const viaLb = { related: { toAws: [{ host: "shop.example.com", zone: "example.com", target: lbDns, kind: "elb" as const, name: lbDns, proxied: true }] } };
  const open = run(awsInventory(), viaLb).findings.find((f) => f.checkId === "XP-006")!;
  assert.equal(open.resource, "alb");
  assert.match(open.detail, /shop.example.com is proxied through Cloudflare to this load balancer/);
  // Locked to Cloudflare (no rule for the whole internet): passes.
  const locked = awsInventory({ regions: [region({ securityGroups: [{ id: "sg-web", name: "web", vpcId: "vpc-1", open: [] }] })] });
  assert.equal(by(run(locked, viaLb), "XP-006")[0].pass, true);
  // By address: a proxied A record to the instance.
  const viaIp = { related: { dnsAddresses: [{ host: "api.example.com", zone: "example.com", ip: "198.51.100.9", proxied: true }] } };
  assert.equal(run(awsInventory(), viaIp).findings.find((f) => f.checkId === "XP-006")!.resource, "web (i-1)");
  // A record that isn't proxied isn't behind Cloudflare, and without Cloudflare in the entity nothing is judged.
  const grey = { related: { dnsAddresses: [{ host: "api.example.com", zone: "example.com", ip: "198.51.100.9", proxied: false }] } };
  assert.equal(by(run(awsInventory(), grey), "XP-006").length, 0);
  assert.equal(by(run(), "XP-006").length, 0);
});

test("an address is dangling when Edgewatch saw it leave the entity, and only noted when nobody here ever held it", () => {
  const released = AWS_CASES["ADN-002"]();
  const f = run(released).findings.find((x) => x.checkId === "ADN-002")!;
  assert.equal(f.severity, "high");
  assert.match(f.detail, /left this entity's AWS accounts on 2026-05-20/);
  assert.equal(by(run(released), "ADN-003").length, 0, "a released address is one finding, not two");
  assert.equal(by(run(released, { related: { awsAddresses: ["198.51.100.77"] } }), "ADN-002")[0].pass, true, "another AWS account in the entity holds it now");
  assert.equal(by(run(released, { related: { unknown: ["awsAddresses"] } }), "ADN-002").length, 0, "an unscanned sibling could hold it");
  // Another account in the entity saw it leave.
  const sibling = { related: { awsReleased: [{ ip: "198.51.100.77", at: "2026-05-01T00:00:00.000Z" }] } };
  assert.equal(by(run(AWS_CASES["ADN-003"](), sibling), "ADN-002")[0].pass, false);

  // Never held here: low, and worded as a question rather than a takeover.
  const outside = run(AWS_CASES["ADN-003"]()).findings.find((x) => x.checkId === "ADN-003")!;
  assert.equal(outside.severity, "low");
  assert.equal(by(run(AWS_CASES["ADN-003"]()), "ADN-002").length, 0, "nothing is known about it, so the released check says nothing");
  // An address outside AWS's range isn't AWS's to give away.
  assert.equal(by(run({ ...AWS_CASES["ADN-003"](), ec2Prefixes: toPrefixes(["192.0.2.0/24"]) }), "ADN-003").length, 0);
  assert.equal(by(run(), "ADN-002")[0].pass, true, "the fixture's own instance address");

  // The history itself: what was held and isn't now was released; it is forgotten when held again or after six months.
  const day = 86_400_000;
  const t0 = Date.parse("2026-06-01T00:00:00Z");
  const first = addressHistory(null, ["a", "b"], t0);
  assert.deepEqual(first, { held: ["a", "b"], released: [] });
  const second = addressHistory(first, ["a"], t0 + day);
  assert.deepEqual(second.released, [{ ip: "b", at: new Date(t0 + day).toISOString() }]);
  assert.deepEqual(addressHistory(second, null, t0 + 2 * day), second, "a scan that couldn't read every region changes nothing");
  assert.deepEqual(addressHistory(second, ["a", "b"], t0 + 3 * day).released, [], "held again");
  assert.deepEqual(addressHistory(second, ["a"], t0 + 200 * day).released, [], "forgotten after six months");
  assert.equal(addressHistory(second, ["a"], t0 + 9 * day).released[0].at, second.released[0].at, "the first date is kept");

  // A missing bucket or CloudFront alias can be claimed; a load balancer's name can't.
  const lbRecord = awsInventory({
    hostedZones: [
      {
        id: "Z1",
        name: "example.com",
        private: false,
        records: [{ name: "x.example.com", type: "CNAME", targets: ["gone-1.eu-west-1.elb.amazonaws.com"], alias: false }],
      },
    ],
  });
  const lb = run(lbRecord).findings.find((x) => x.checkId === "ADN-001")!;
  assert.equal(lb.severity, "low");
  assert.match(lb.detail, /can't be reused, so this isn't a takeover/);
  assert.equal(run(AWS_CASES["ADN-001"]()).findings.find((x) => x.checkId === "ADN-001")!.severity, "high");
  // An API Gateway domain's distribution isn't in the account's list, but it is the account's.
  const gw = awsInventory({
    regions: [region({ apiDomains: ["d5gw.cloudfront.net"] })],
    hostedZones: [
      { id: "Z1", name: "example.com", private: false, records: [{ name: "api.example.com", type: "CNAME", targets: ["d5gw.cloudfront.net"], alias: false }] },
    ],
  });
  assert.equal(by(run(gw), "ADN-001")[0].pass, true);
});

test("a public bucket that CloudFront serves is reported with the way to make it private", () => {
  const b = { name: "site", region: "eu-west-1", block: null, policyPublic: true, aclPublic: [] };
  const dist = {
    ...awsInventory().distributions![0],
    origins: [{ domain: "site.s3.eu-west-1.amazonaws.com", protocolPolicy: null, s3: true, restricted: false }],
  };
  const f = run(awsInventory({ s3Block: null, buckets: [b], distributions: [dist] })).findings.find((x) => x.checkId === "AS3-002")!;
  assert.equal(f.severity, "high");
  assert.match(f.detail, /CloudFront distribution www.example.com serves it/);
  // A distribution with only S3 origins isn't asked for a web ACL.
  assert.equal(by(run(awsInventory({ distributions: [{ ...dist, waf: false }] })), "AED-003").length, 0);
});

test("address ranges and start-up scripts", () => {
  const p = toPrefixes(["198.51.100.0/24", "203.0.113.128/25", "10.0.0.0/8"]);
  for (const ip of ["198.51.100.0", "198.51.100.255", "203.0.113.200", "10.200.3.4"]) assert.ok(inPrefixes(ip, p), ip);
  for (const ip of ["198.51.101.0", "203.0.113.5", "11.0.0.1", "not-an-ip", "::1"]) assert.ok(!inPrefixes(ip, p), ip);
  const b64 = (s: string) => Buffer.from(s).toString("base64");
  assert.equal(secretInUserData(b64("#!/bin/bash\nexport AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")), "an AWS access key");
  assert.equal(secretInUserData(b64("-----BEGIN RSA PRIVATE KEY-----\nabc")), "a private key");
  assert.equal(secretInUserData(b64("#!/bin/bash\naws s3 cp s3://bucket/app . && TOKEN=$(aws ssm get-parameter --name t)\n")), null);
  assert.equal(secretInUserData(null), null);
});
