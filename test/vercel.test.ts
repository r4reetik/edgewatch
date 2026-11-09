// Vercel scans end to end against the mocked Vercel API (dev/mock/vercel.ts):
// the scanner only reads, secrets never reach storage, findings land on the right
// account, and checks that span providers compare against the entity's
// Cloudflare accounts.

import { test, describe, after, before } from "node:test";
import assert from "node:assert/strict";
import { Scanner } from "../src/scanner.ts";
import { installMockCloudflare, MOCK_ACCOUNT } from "../dev/mock/cloudflare.ts";
import { installMockVercel, MOCK_VERCEL_TEAM, MOCK_VERCEL_TOKEN, MOCK_VERCEL_USER } from "../dev/mock/vercel.ts";
import { seedAccount, seedVercel, testRepo } from "../dev/mock/accounts.ts";
import { VERCEL_CHECKS } from "../src/providers/vercel/catalog.ts";

function setup(o: { cloudflare?: boolean; personal?: boolean } = {}) {
  const { repo, vault } = testRepo();
  if (o.cloudflare) seedAccount(repo, vault);
  seedVercel(repo, vault, { entity: "Mock Group", ...(o.personal ? { personal: { entity: "Side Projects" } } : {}) });
  return { repo, vault, scanner: new Scanner(repo, vault, () => {}) };
}

describe("Vercel scan against the mocked API", () => {
  const methods = new Set<string>();
  const queries: string[] = [];
  let restore: () => void;
  before(() => {
    const cf = installMockCloudflare();
    const v = installMockVercel({
      onRequest: (u, init) => {
        methods.add(init?.method || "GET");
        queries.push(u.search);
      },
    });
    restore = () => {
      v();
      cf();
    };
  });
  after(() => restore());

  test("reads only, finds what the mock data holds, and stores no secret", async () => {
    const { repo, scanner } = setup();
    const [result] = await scanner.start("test").done;
    assert.deepEqual([...methods], ["GET"], "the Vercel scanner must only read");
    assert.ok(!queries.some((q) => /decrypt=true/.test(q)), "environment variables are never decrypted");

    const findings = repo.findings.forScan(result.scanId, repo.settings.get().slaDays);
    const ids = new Set(findings.map((f) => f.checkId));
    for (const id of [
      "VID-001",
      "VID-002",
      "VID-003",
      "VID-004",
      "VID-005",
      "VID-006",
      "VID-007",
      "VID-008",
      "VID-009",
      "VDP-001",
      "VDP-002",
      "VDP-003",
      "VDP-004",
      "VDP-005",
      "VDP-006",
      "VDP-007",
      "VDP-008",
      "VEN-001",
      "VEN-002",
      "VEN-003",
      "VEN-004",
      "VEN-005",
      "VEN-006",
      "VEN-007",
      "VEN-008",
      "VFW-001",
      "VFW-002",
      "VFW-003",
      "VFW-004",
      "VFW-005",
      "VFW-006",
      "VDM-001",
      "VDM-002",
      "VDM-003",
      "VMN-002",
      "VMN-003",
      "VMN-004",
      "VPL-001",
      "VPL-002",
      "VPL-003",
      "VPL-004",
      "VPL-005",
      "VPL-006",
    ])
      assert.ok(ids.has(id), `expected ${id}`);
    assert.ok(
      findings.every((f) => f.provider === "vercel"),
      "findings carry their provider",
    );
    // A never-configured project runs Vercel's defaults: firewall on, bot protection off.
    const marketing = (id: string) => findings.filter((f) => f.checkId === id && f.zone === "marketing");
    assert.equal(marketing("VFW-001").length, 0, "the default firewall is on");
    assert.equal(marketing("VFW-002").length, 1, "bot protection is off by default");
    assert.ok(
      findings.some((f) => f.checkId === "VEN-005" && f.zone === "Shared variables"),
      "shared variables are checked too",
    );
    assert.ok(
      findings.some((f) => f.checkId === "VID-004" && f.resource === "visitor@gmail.com"),
      "a request to join is an open request",
    );
    assert.ok(!findings.some((f) => f.checkId === "VID-003" && f.resource === "visitor@gmail.com"), "…not a member with access");
    // Integration-managed database URLs are the integration's to rotate.
    assert.ok(!findings.some((f) => f.checkId === "VEN-004" && f.resource.endsWith("POSTGRES_URL")));

    const scan = repo.scans.latest(MOCK_VERCEL_TEAM)!;
    const stored = JSON.stringify({ snapshot: scan.snapshot, findings });
    for (const secret of [
      "mock-value-for-",
      MOCK_VERCEL_TOKEN,
      "key=hidden",
      "token=hidden",
      "mock-bypass-secret",
      "mock-drain-header",
      "npm_MockMock",
      "_authToken",
    ])
      assert.ok(!stored.includes(secret), `stored data must not contain ${secret}`);

    const snap = JSON.parse(scan.snapshot as string);
    assert.equal(snap.accountName, "Mock Web");
    assert.deepEqual(
      snap.projects.map((p: { name: string }) => p.name),
      ["internal-tool", "marketing", "web"],
    );
    assert.equal(snap.projects.find((p: { name: string }) => p.name === "marketing").previews, "Public");
    assert.ok(
      snap.coverage.every((c: { ok: boolean }) => c.ok),
      JSON.stringify(snap.coverage),
    );
    assert.equal(snap.zones, undefined, "Cloudflare-only parts stay out of a Vercel snapshot");
  });

  test("a personal account is scanned without team-only reads", async () => {
    const { repo, scanner } = setup({ personal: true });
    await scanner.start("test", [MOCK_VERCEL_USER]).done;
    const scan = repo.scans.latest(MOCK_VERCEL_USER)!;
    const snap = JSON.parse(scan.snapshot as string);
    assert.deepEqual(
      snap.projects.map((p: { name: string }) => p.name),
      ["blog"],
    );
    assert.ok(!snap.coverage.some((c: { key: string }) => c.key === "members"), "a personal account has no members to read");
    const ids = new Set(repo.findings.forScan(scan.id, repo.settings.get().slaDays).map((f) => f.checkId));
    assert.ok(ids.has("VEN-005") && ids.has("VDP-001") && ids.has("VPL-001"));
    assert.ok(!ids.has("VID-001") && !ids.has("VMN-001"), "team and paid-plan checks don't apply to Hobby");
  });

  test("a source the role can't read is a coverage gap and its checks are skipped, not passed", async () => {
    restore();
    const cf = installMockCloudflare();
    const v = installMockVercel({ deny: [/\/v10\/projects\/[^/]+\/env$/] });
    restore = () => {
      v();
      cf();
    };
    const { repo, scanner } = setup();
    const [result] = await scanner.start("test").done;
    const snap = JSON.parse(repo.scans.latest(MOCK_VERCEL_TEAM)!.snapshot as string);
    const gap = snap.coverage.find((c: { key: string }) => c.key === "env");
    assert.equal(gap.ok, false);
    assert.ok(gap.skippedChecks.includes("VEN-002"));
    assert.equal(snap.checks["VEN-002"], undefined, "no pass is recorded for a skipped check");
    const ids = new Set(repo.findings.forScan(result.scanId, repo.settings.get().slaDays).map((f) => f.checkId));
    assert.ok(!ids.has("VEN-002") && ids.has("VDP-001"));
  });

  test("checks that span providers compare Cloudflare DNS with the entity's Vercel projects", async () => {
    const { repo, scanner } = setup({ cloudflare: true });
    // The first pass gives each account the other's snapshot; the second uses it.
    await scanner.start("setup").done;
    await scanner.start("manual").done;
    const cf = repo.findings.forScan(repo.scans.latest(MOCK_ACCOUNT)!.id, repo.settings.get().slaDays);
    const v = repo.findings.forScan(repo.scans.latest(MOCK_VERCEL_TEAM)!.id, repo.settings.get().slaDays);
    const dangling = cf.filter((f) => f.checkId === "XP-001").map((f) => f.resource);
    assert.deepEqual(dangling, ["launch.mock.example"], "only the record no Vercel project serves");
    assert.deepEqual(
      cf.filter((f) => f.checkId === "XP-002").map((f) => f.resource),
      ["app.mock.example"],
    );
    const bypass = v.find((f) => f.checkId === "XP-003");
    assert.equal(bypass?.resource, "web");
    assert.equal(bypass?.confidence, "likely");
    // Member emails at the Cloudflare zone's domain count as internal for the Vercel team.
    assert.ok(!v.some((f) => f.checkId === "VID-003" && f.resource.endsWith("@mock.example")));
  });

  test("checks that span providers are skipped when the entity has no account on the other provider", async () => {
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    const snap = JSON.parse(repo.scans.latest(MOCK_VERCEL_TEAM)!.snapshot as string);
    assert.equal(snap.checks["XP-003"], undefined);
  });
});

test("every Vercel check has a title, why, fix, Vercel docs and a known source", () => {
  const ids = VERCEL_CHECKS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const c of VERCEL_CHECKS) {
    assert.match(c.id, /^[A-Z]+-\d{3}$/);
    assert.ok(c.title && c.why && c.fix, c.id);
    assert.ok(!c.docs || c.docs.startsWith("https://vercel.com/"), `${c.id} links Vercel's docs`);
    assert.ok(c.requires?.length, `${c.id} names the sources it reads`);
  }
});
