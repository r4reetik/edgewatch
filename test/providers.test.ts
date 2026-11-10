// Several providers in one Edgewatch, through the HTTP API: connecting a Vercel team
// next to Cloudflare accounts in the same entity, the provider filter on every
// scoped view, per-provider scores, and secrets kept out of every response.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_TOKEN } from "../dev/mock/cloudflare.ts";
import { installMockVercel, MOCK_VERCEL_TEAM, MOCK_VERCEL_TOKEN, MOCK_VERCEL_TOKEN_2, MOCK_VERCEL_USER } from "../dev/mock/vercel.ts";
import { keyForAccounts, resolveScope, splitScopeKey, withProvider } from "../src/shared/scope.ts";
import { makeApp } from "./helpers/app.ts";

describe("Cloudflare and Vercel together", () => {
  let restore: () => void;
  before(() => {
    const cf = installMockCloudflare();
    const v = installMockVercel();
    restore = () => {
      v();
      cf();
    };
  });
  after(() => restore());

  async function bothInOneEntity() {
    const t = makeApp();
    const cf = await t.json("/api/accounts", "POST", { token: MOCK_TOKEN, accountIds: [MOCK_ACCOUNT], entityName: "Mock Group" });
    const v = await t.json("/api/accounts", "POST", { provider: "vercel", token: MOCK_VERCEL_TOKEN, accountIds: [MOCK_VERCEL_TEAM], entityId: cf.entityId });
    assert.deepEqual(v.added, [MOCK_VERCEL_TEAM]);
    // Each add starts a scan; then one more pass so the checks that span providers see each other's snapshots.
    await t.scanner.start("test").done;
    await t.scanner.start("test").done;
    return { ...t, entityId: cf.entityId as number };
  }

  test("a Vercel token is verified, its teams listed and probed, and the team added to an existing entity", async () => {
    const { json, call, repo, cleanup } = makeApp();
    try {
      const v = await json("/api/accounts/verify", "POST", { provider: "vercel", token: MOCK_VERCEL_TOKEN, accountIds: [MOCK_VERCEL_TEAM] });
      assert.equal(v.token.valid, true);
      assert.deepEqual(
        v.accounts.map((a: { id: string }) => a.id),
        [MOCK_VERCEL_TEAM],
        "a team-scoped token isn't offered the personal account",
      );
      assert.ok(v.probes[MOCK_VERCEL_TEAM].every((p: { ok: boolean }) => p.ok));

      const personal = await json("/api/accounts/verify", "POST", { provider: "vercel", token: MOCK_VERCEL_TOKEN_2 });
      assert.deepEqual(
        personal.accounts.map((a: { id: string }) => a.id),
        [MOCK_VERCEL_USER],
      );

      const bad = await json("/api/accounts/verify", "POST", { provider: "vercel", token: "not-a-real-token" });
      assert.equal(bad.token.valid, false);

      // Vercel IDs keep their case; a Cloudflare-shaped request for them is refused.
      const wrong = await call("/api/accounts", { method: "POST", body: JSON.stringify({ token: MOCK_VERCEL_TOKEN, accountIds: [MOCK_VERCEL_TEAM] }) });
      assert.equal(wrong.status, 400);
      const unknown = await call("/api/accounts", { method: "POST", body: JSON.stringify({ provider: "not-a-provider", token: "x", accountIds: [] }) });
      assert.equal(unknown.status, 400);

      const saved = await json("/api/accounts", "POST", { provider: "vercel", token: MOCK_VERCEL_TOKEN, accountIds: [MOCK_VERCEL_TEAM], entityName: "Web" });
      assert.deepEqual(saved.added, [MOCK_VERCEL_TEAM]);
      assert.equal(repo.accounts.get(MOCK_VERCEL_TEAM)?.provider, "vercel");
      assert.equal(repo.accounts.get(MOCK_VERCEL_TEAM)?.name, "Mock Web");
      const tpl = await json("/api/accounts/template?provider=vercel");
      assert.equal(tpl.template, false);
      assert.match(tpl.url, /^https:\/\/vercel\.com\//);
    } finally {
      cleanup();
    }
  });

  test("the provider filter narrows every scoped view, and the Overview splits the score by provider", async () => {
    const { json, entityId, cleanup } = await bothInOneEntity();
    try {
      const scope = `e:${entityId}`;
      const all = await json(`/api/overview?scope=${scope}`);
      assert.deepEqual(
        all.byProvider.map((p: { provider: string; accounts: number }) => [p.provider, p.accounts]),
        [
          ["cloudflare", 1],
          ["vercel", 1],
        ],
      );
      assert.equal(all.accounts.length, 2);

      const vercel = await json(`/api/overview?scope=${encodeURIComponent(`${scope}@vercel`)}`);
      assert.deepEqual(
        vercel.accounts.map((a: { id: string }) => a.id),
        [MOCK_VERCEL_TEAM],
      );
      assert.deepEqual(vercel.byProvider, [], "one provider in view: no split");

      const findings = await json(`/api/findings?scope=${encodeURIComponent(`${scope}@cloudflare`)}`);
      assert.ok(findings.findings.length > 0);
      assert.ok(findings.findings.every((f: { provider: string }) => f.provider === "cloudflare"));
      const mixed = await json(`/api/findings?scope=${scope}`);
      assert.ok(mixed.findings.some((f: { provider: string }) => f.provider === "vercel"));
      assert.ok(
        mixed.findings.some((f: { checkId: string }) => f.checkId === "XP-001"),
        "the dangling Vercel record is found",
      );

      const projects = await json(`/api/projects?scope=${scope}`);
      assert.deepEqual(
        projects.projects.map((p: { name: string }) => p.name),
        ["internal-tool", "marketing", "web"],
      );
      assert.equal((await json(`/api/zones?scope=${encodeURIComponent(`${scope}@vercel`)}`)).zones, null, "no zones in a Vercel-only view");

      const checks = await json(`/api/checks?scope=${encodeURIComponent(`${scope}@vercel`)}`);
      assert.ok(checks.checks.length > 0 && checks.checks.every((c: { provider: string }) => c.provider === "vercel"));
      const coverage = (await json(`/api/scans?scope=${scope}`)).coverage as { label: string; provider: string }[];
      assert.ok(coverage.some((c) => c.provider === "vercel") && coverage.some((c) => c.provider === "cloudflare"), "coverage rows keep their provider");

      const report = await json(`/api/report?scope=${scope}`);
      assert.ok(report.projects.length === 3 && report.zones.length > 0);
    } finally {
      cleanup();
    }
  });

  test("no Vercel token or secret value reaches an API response", async () => {
    const { call, cleanup } = await bothInOneEntity();
    try {
      for (const p of [
        "/api/session",
        "/api/accounts",
        "/api/overview",
        "/api/findings",
        "/api/projects",
        "/api/scans",
        "/api/report",
        "/api/export/findings.csv",
      ]) {
        const text = await (await call(p)).text();
        for (const secret of [MOCK_VERCEL_TOKEN, "mock-value-for-", "key=hidden", "token=hidden"])
          assert.ok(!text.includes(secret), `${secret} leaked in ${p}`);
      }
    } finally {
      cleanup();
    }
  });
});

test("scope keys carry an optional provider, dropped when the view has only one", () => {
  const accounts = [
    { id: "a1", provider: "cloudflare" as const, entityId: 1, name: "CF", alias: null },
    { id: "team_x", provider: "vercel" as const, entityId: 1, name: "Web", alias: null },
    { id: "a2", provider: "cloudflare" as const, entityId: 2, name: "Other", alias: null },
  ];
  const entities = [
    { id: 1, name: "Group", includeInAll: true },
    { id: 2, name: "Other", includeInAll: true },
  ];
  assert.deepEqual(splitScopeKey("e:1@vercel"), { base: "e:1", provider: "vercel" });
  assert.deepEqual(splitScopeKey("e:1@nope"), { base: "e:1", provider: null });
  assert.equal(withProvider("e:1@vercel", null), "e:1");
  assert.equal(withProvider("all", "cloudflare"), "all@cloudflare");

  const v = resolveScope(accounts, entities, "e:1@vercel")!;
  assert.deepEqual(
    v.accounts.map((a) => a.id),
    ["team_x"],
  );
  assert.deepEqual(v.providers, ["cloudflare", "vercel"]);
  // Entity 2 has only Cloudflare: the filter would show nothing, so it's dropped.
  const two = resolveScope(accounts, entities, "e:2@vercel")!;
  assert.equal(two.provider, null);
  assert.equal(two.key, "e:2");
  assert.deepEqual(
    resolveScope(accounts, entities, "all@cloudflare")!.accounts.map((a) => a.id),
    ["a1", "a2"],
  );
});

test("a view can be any set of accounts, named by its shortest key, and separate entities are never combined", () => {
  const acc = (id: string, provider: "cloudflare" | "vercel" | "aws", entityId: number) => ({ id, provider, entityId, name: id, alias: null });
  const list = [acc("cf1", "cloudflare", 1), acc("aws1", "aws", 1), acc("aws2", "aws", 1), acc("cf2", "cloudflare", 2), acc("v3", "vercel", 3)];
  const ents = [
    { id: 1, name: "Group", includeInAll: true },
    { id: 2, name: "Sister", includeInAll: true },
    { id: 3, name: "Apart", includeInAll: false },
  ];
  const key = (...ids: string[]) => keyForAccounts(list, ents, ids);
  // The whole of something keeps its own key, so links stay short and stable.
  assert.equal(key("cf1", "aws1", "aws2", "cf2"), "all");
  assert.equal(key("cf1", "aws1", "aws2"), "e:1");
  assert.equal(key("aws2"), "a:aws2");
  assert.equal(key("aws1", "aws2"), "e:1@aws", "every account of one platform in an entity");
  assert.equal(key("cf1", "cf2"), "all@cloudflare");
  // With one entity, everything in it is that entity (and "all" resolves to the same accounts).
  assert.equal(keyForAccounts(list.slice(0, 3), ents.slice(0, 1), ["cf1", "aws1", "aws2"]), "e:1");
  // Anything else is the set itself, in a stable order.
  assert.equal(key("cf1", "aws2"), "s:aws2,cf1");
  assert.equal(key("aws2", "cf1"), "s:aws2,cf1");
  assert.equal(key(), null);
  assert.equal(key("nope"), null);

  const part = resolveScope(list, ents, "s:aws2,cf1")!;
  assert.equal(part.kind, "selection");
  assert.equal(part.label, "Group");
  assert.equal(part.entity?.id, 1);
  assert.deepEqual(
    part.accounts.map((a) => a.id),
    ["cf1", "aws2"],
  );
  assert.deepEqual(part.providers, ["cloudflare", "aws"]);
  const across = resolveScope(list, ents, "s:aws1,cf2")!;
  assert.equal(across.entity, null);
  assert.equal(across.label, "2 accounts");
  // An account that was removed drops out of an old link; a link with nothing left doesn't resolve.
  assert.deepEqual(
    resolveScope(list, ents, "s:aws1,gone,cf1")!.accounts.map((a) => a.id),
    ["cf1", "aws1"],
  );
  assert.equal(resolveScope(list, ents, "s:gone"), null);
  // An entity kept out of All accounts is never shown together with another.
  assert.equal(resolveScope(list, ents, "s:cf1,v3"), null);
  assert.equal(key("cf1", "v3"), null);
  assert.equal(key("v3"), "a:v3");
});
