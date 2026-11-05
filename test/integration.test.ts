import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { Scanner } from "../src/scanner.ts";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_ACCOUNT_2, MOCK_TOKEN_2 } from "../dev/mock/cloudflare.ts";
import { seedAccount, testRepo } from "../dev/mock/accounts.ts";
import { SOURCES, type SourceKey } from "../src/core/sources.ts";

function setup() {
  const { repo, vault } = testRepo();
  seedAccount(repo, vault);
  return { repo, vault, scanner: new Scanner(repo, vault, () => {}) };
}

describe("full scan against a mocked Cloudflare API", () => {
  test("produces the expected findings, snapshot and coverage", async () => {
    const methods = new Set<string>();
    const restore = installMockCloudflare({
      onRequest: (u, init) => {
        if (u.hostname === "api.cloudflare.com" && !u.pathname.endsWith("/graphql")) methods.add(init?.method || "GET");
      },
    });
    after(restore);
    const { repo, scanner } = setup();
    const [result] = await scanner.start("test").done;
    assert.equal(scanner.state.running, false);

    const scan = repo.scans.latest(MOCK_ACCOUNT)!;
    const findings = repo.findings.forScan(result.scanId, repo.settings.get().slaDays);
    const ids = new Set(findings.map((f) => f.checkId));
    for (const id of [
      "IAM-001",
      "IAM-005",
      "ZT-004",
      "TLS-001",
      "TLS-002",
      "TLS-004",
      "WAF-001",
      "WAF-002",
      "WAF-004",
      "DNS-005",
      "DNS-006",
      "MON-001",
      "SC:security_txt_not_enabled",
    ]) {
      assert.ok(ids.has(id), `expected ${id}`);
    }
    const snap = JSON.parse(scan.snapshot as string);
    assert.equal(snap.accountName, "Mock Co");
    assert.equal(snap.zones[0].name, "mock.example");
    assert.equal(snap.value.monthly, 25);
    assert.equal(snap.activity.events[0].destructive, true);
    assert.ok(
      snap.coverage.every((c: { ok: boolean }) => c.ok),
      JSON.stringify(snap.coverage.filter((c: { ok: boolean }) => !c.ok)),
    );
    assert.deepEqual([...methods], ["GET"], "the scanner must only read");
    assert.ok(typeof result.score === "number" && result.score > 0 && result.score < 100);
  });

  test("missing permissions are reported and their checks skipped, never passed", async () => {
    const restore = installMockCloudflare({ deny: [/\/members$/, /^\/zones\/[^/]+\/settings$/] });
    after(restore);
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    const snap = JSON.parse(repo.scans.latest(MOCK_ACCOUNT)!.snapshot as string);
    const gaps = snap.coverage
      .filter((c: { ok: boolean }) => !c.ok)
      .map((c: { label: string }) => c.label)
      .sort();
    assert.deepEqual(gaps, ["Account members", "Zone settings"]);
    assert.equal(snap.checks["IAM-001"], undefined, "member checks were skipped");
    assert.equal(snap.checks["TLS-001"], undefined, "edge checks were skipped");
  });

  test("a second concurrent start joins the running scan", async () => {
    const restore = installMockCloudflare();
    after(restore);
    const { scanner } = setup();
    const a = scanner.start("one");
    const b = scanner.start("two");
    assert.equal(b.alreadyRunning, true);
    assert.deepEqual(a.queued, [MOCK_ACCOUNT]);
    assert.deepEqual(b.queued, []);
    await a.done;
  });

  test("an invalid token fails the scan cleanly", async () => {
    const restore = installMockCloudflare();
    after(restore);
    const { repo, vault } = testRepo();
    seedAccount(repo, vault, { token: "wrong" });
    await new Scanner(repo, vault, () => {}).start("test").done;
    // Every Cloudflare source is unreadable, so the scan completes with full coverage gaps rather than crashing.
    const snap = repo.scans.latest(MOCK_ACCOUNT)!.snap;
    const cloudflare = snap.coverage!.filter((c) => !SOURCES[c.key as SourceKey]?.external);
    assert.ok(cloudflare.length > 10 && cloudflare.every((c) => !c.ok), JSON.stringify(cloudflare.filter((c) => c.ok)));
  });

  test("accounts are scanned one after another, each with its own token", async () => {
    const tokens: string[] = [];
    const restore = installMockCloudflare({
      onRequest: (u, init) => {
        if (u.pathname.endsWith("/members")) tokens.push(String((init?.headers as Record<string, string> | undefined)?.Authorization).slice(-12));
      },
    });
    after(restore);
    const { repo, vault, scanner } = setup();
    seedAccount(repo, vault, { id: MOCK_ACCOUNT_2, token: MOCK_TOKEN_2, name: "Other Ltd", entity: "Other Ltd" });
    const run = scanner.start("test");
    assert.deepEqual(run.queued, [MOCK_ACCOUNT, MOCK_ACCOUNT_2]);
    assert.equal(scanner.state.accountId, MOCK_ACCOUNT);
    assert.deepEqual(scanner.state.queued, [MOCK_ACCOUNT_2]);
    const results = await run.done;
    assert.deepEqual(
      results.map((r) => r.accountId),
      [MOCK_ACCOUNT, MOCK_ACCOUNT_2],
    );
    assert.equal(JSON.parse(repo.scans.latest(MOCK_ACCOUNT_2)!.snapshot as string).zones[0].name, "other.example");
    assert.equal(tokens.length, 2);
    assert.notEqual(tokens[0], tokens[1], "each account used its own token");
    assert.equal(scanner.state.running, false);
  });

  test("a missing token fails that account's scan and the queue moves on", async () => {
    const restore = installMockCloudflare();
    after(restore);
    const { repo, vault, scanner } = setup();
    seedAccount(repo, vault, { id: MOCK_ACCOUNT_2, token: MOCK_TOKEN_2, name: "Other Ltd" });
    vault.remove(repo.accounts.get(MOCK_ACCOUNT)!.tokenId);
    await scanner.start("test").done.catch(() => {});
    assert.match(String(repo.scans.lastFailed(MOCK_ACCOUNT)?.error), /token for this account is missing/);
    assert.ok(repo.scans.latest(MOCK_ACCOUNT_2), "the next account was still scanned");
  });

  test("email domains of sibling accounts in the same entity count as internal", async () => {
    const restore = installMockCloudflare();
    after(restore);
    const { repo, vault, scanner } = setup();
    // Account 2's members include dev@mock.example; mock.example is a zone of account 1.
    seedAccount(repo, vault, { id: MOCK_ACCOUNT_2, token: MOCK_TOKEN_2, name: "Other Ltd" });
    await scanner.start("test").done;
    const external = (id: string) =>
      repo.findings.forScan(repo.scans.latest(id)!.id as number, repo.settings.get().slaDays).filter((f) => f.checkId === "IAM-004");
    await scanner.start("again", [MOCK_ACCOUNT_2]).done;
    assert.equal(external(MOCK_ACCOUNT_2).length, 0, "same entity: mock.example is internal");
    repo.accounts.setEntity(MOCK_ACCOUNT_2, repo.entities.create("Separate Ltd").id);
    await scanner.start("again", [MOCK_ACCOUNT_2]).done;
    assert.ok(external(MOCK_ACCOUNT_2).length > 0, "different entity: mock.example members are external");
  });
});
