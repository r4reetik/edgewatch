import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.ts";
import { Repo } from "../src/store/repo.ts";
import { TokenVault } from "../src/config.ts";
import { importLegacy } from "../src/store/legacy.ts";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_ACCOUNT_2, MOCK_ACCOUNT_3, MOCK_TOKEN, MOCK_TOKEN_2 } from "../dev/mock/cloudflare.ts";

import { makeApp, PASSWORD } from "./helpers/app.ts";

describe("loopback mode (no password)", () => {
  let restore: () => void;
  before(() => {
    restore = installMockCloudflare();
  });
  after(() => restore());

  test("health and session are public; setup state is reported", async () => {
    const { call, cleanup } = makeApp();
    assert.equal((await call("/api/health")).status, 200);
    const s = (await (await call("/api/session")).json()) as any;
    assert.equal(s.configured, false);
    assert.equal(s.authRequired, false);
    cleanup();
  });

  test("rejects non-loopback Host headers (DNS rebinding)", async () => {
    const { call, cleanup } = makeApp();
    assert.equal((await call("/api/session", { host: "evil.example:4317" })).status, 403);
    assert.equal((await call("/api/session", { host: "localhost:4317" })).status, 200);
    cleanup();
  });

  test("blocks cross-site and non-JSON state changes (CSRF)", async () => {
    const { call, cleanup } = makeApp({ configured: true });
    const form = await call("/api/scan", { method: "POST", body: "x", headers: { "content-type": "text/plain" } });
    assert.equal(form.status, 415);
    const cross = await call("/api/scan", { method: "POST", body: "{}", headers: { origin: "https://evil.example" } });
    assert.equal(cross.status, 403);
    const site = await call("/api/scan", { method: "POST", body: "{}", headers: { "sec-fetch-site": "cross-site" } });
    assert.equal(site.status, 403);
    cleanup();
  });

  test("adding an account verifies the token, stores it apart from the database, and scans", async () => {
    const { call, json, repo, scanner, dataDir, cleanup } = makeApp();
    const v = await json("/api/accounts/verify", "POST", { token: MOCK_TOKEN, accountIds: [MOCK_ACCOUNT] });
    assert.equal(v.token.valid, true);
    assert.deepEqual(
      v.accounts.map((a: { name: string; added: boolean }) => [a.name, a.added]),
      [
        ["Mock Co", false],
        ["Mock Co Staging", false],
      ],
    );
    assert.ok(v.probes[MOCK_ACCOUNT].length > 10);
    const bad = await json("/api/accounts/verify", "POST", { token: "nope" });
    assert.equal(bad.token.valid, false);
    const unseen = await call("/api/accounts", { method: "POST", body: JSON.stringify({ token: MOCK_TOKEN, accountIds: [MOCK_ACCOUNT_2] }) });
    assert.equal(unseen.status, 400, "a token can only add accounts it can read");
    const saved = await json("/api/accounts", "POST", { token: MOCK_TOKEN, accountIds: [MOCK_ACCOUNT], entityName: "Mock Group" });
    assert.deepEqual(saved.added, [MOCK_ACCOUNT]);
    await scanner.start("join").done;
    assert.ok(repo.scans.latest(MOCK_ACCOUNT));
    assert.equal(repo.entities.list()[0].name, "Mock Group");
    const { readFileSync, statSync } = await import("node:fs");
    assert.equal(statSync(join(dataDir, "credentials.json")).mode & 0o777, 0o600);
    assert.match(readFileSync(join(dataDir, "credentials.json"), "utf8"), /SECRET-VALUE/);
    const tokenId = repo.accounts.get(MOCK_ACCOUNT)!.tokenId;
    assert.ok(!JSON.stringify(repo.store.all("SELECT * FROM accounts")).includes(MOCK_TOKEN), "the database holds only a token ID");
    assert.match(tokenId, /^[0-9a-f]{16}$/);
    cleanup();
  });

  test("the token never appears in any API response", async () => {
    const { call, scanner, cleanup } = makeApp({ configured: true });
    await scanner.start("test").done;
    const paths = [
      "/api/session",
      "/api/overview",
      "/api/findings",
      "/api/zones",
      "/api/value",
      "/api/activity",
      "/api/checks",
      "/api/scans",
      "/api/settings",
      "/api/report",
      "/api/scan/status",
      "/api/export/findings.csv",
      "/api/export/findings.json",
    ];
    for (const p of paths) {
      const res = await call(p);
      assert.equal(res.status, 200, p);
      assert.ok(!(await res.text()).includes(MOCK_TOKEN), `token leaked in ${p}`);
    }
    cleanup();
  });

  test("entity webhook URLs are write-only and must be https", async () => {
    const { call, json, repo, cleanup } = makeApp({ configured: true });
    const id = repo.entities.list()[0].id;
    const url = "https://hooks.slack.com/services/T000/B000/SECRETSECRET";
    const http = await call(`/api/entities/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ notifications: { slackWebhookUrl: "http://example.com/hook" } }),
    });
    assert.equal(http.status, 400);
    const res = await json(`/api/entities/${id}`, "PATCH", { notifications: { slackWebhookUrl: url } });
    assert.equal(res.entity.notifications.slackConfigured, true);
    for (const p of ["/api/accounts", "/api/session", "/api/settings"]) assert.ok(!(await (await call(p)).text()).includes("SECRETSECRET"), p);
    cleanup();
  });

  test("triage validates input and is applied in bulk", async () => {
    const { call, scanner, cleanup } = makeApp({ configured: true });
    await scanner.start("test").done;
    const { findings } = (await (await call("/api/findings")).json()) as any;
    const fps = findings.slice(0, 3).map((f: { fingerprint: string }) => f.fingerprint);
    assert.equal((await call("/api/triage", { method: "POST", body: JSON.stringify({ fingerprints: fps, status: "bogus" }) })).status, 400);
    assert.equal((await call("/api/triage", { method: "POST", body: JSON.stringify({ fingerprints: ["../etc"], status: "open" }) })).status, 400);
    const ok = await call("/api/triage", {
      method: "POST",
      body: JSON.stringify({ fingerprints: fps, status: "accepted", owner: "sec@mock.example", acceptUntil: "2999-12-31" }),
    });
    assert.equal(ok.status, 200);
    const o = (await (await call("/api/overview")).json()) as any;
    assert.equal(o.triage.accepted, 3);
    cleanup();
  });

  test("CSV export neutralizes formula injection", async () => {
    const { call, scanner, cleanup } = makeApp({ configured: true });
    await scanner.start("test").done;
    const { findings } = (await (await call("/api/findings")).json()) as any;
    await call(`/api/triage/${findings[0].fingerprint}`, { method: "PUT", body: JSON.stringify({ status: "open", owner: '=HYPERLINK("x")' }) });
    const csv = await (await call("/api/export/findings.csv")).text();
    assert.ok(csv.includes(`"'=HYPERLINK(""x"")"`));
    cleanup();
  });

  test("static files: SPA fallback, no path traversal, security headers", async () => {
    const { call, cleanup } = makeApp();
    const page = await call("/findings");
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Edgewatch/);
    assert.match(page.headers.get("content-security-policy") || "", /default-src 'self'/);
    assert.equal(page.headers.get("x-frame-options"), "DENY");
    assert.equal((await call("/assets/app.js")).headers.get("cache-control"), "public, max-age=31536000, immutable");
    for (const p of ["/../secret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt"]) {
      const r = await call(p);
      assert.ok(!(await r.text()).includes("do not serve"), p);
    }
    assert.equal((await call("/assets/missing.js")).status, 404);
    cleanup();
  });
});

describe("several accounts and entities", () => {
  let restore: () => void;
  before(() => {
    restore = installMockCloudflare();
  });
  after(() => restore());

  /** Two accounts in two entities, both scanned. */
  async function twoEntities() {
    const t = makeApp({ configured: true });
    const added = await t.json("/api/accounts", "POST", { token: MOCK_TOKEN_2, accountIds: [MOCK_ACCOUNT_2], entityName: "Other Ltd" });
    await t.scanner.start("test").done;
    return { ...t, mock: t.repo.accounts.get(MOCK_ACCOUNT)!.entityId, other: added.entityId as number };
  }

  test("a scope shows one account, one entity, or every included account", async () => {
    const { json, other, mock, cleanup } = await twoEntities();
    const accountsIn = async (scope: string) =>
      [...new Set((await json(`/api/findings?scope=${scope}`)).findings.map((f: { accountId: string }) => f.accountId))].sort();
    assert.deepEqual(await accountsIn("all"), [MOCK_ACCOUNT, MOCK_ACCOUNT_2].sort());
    assert.deepEqual(await accountsIn(`a:${MOCK_ACCOUNT_2}`), [MOCK_ACCOUNT_2]);
    assert.deepEqual(await accountsIn(`e:${mock}`), [MOCK_ACCOUNT]);
    const o = await json("/api/overview?scope=all");
    assert.equal(o.accounts.length, 2);
    assert.equal(o.score, Math.round(((o.accounts[0].score + o.accounts[1].score) / 2) * 10) / 10, "the combined score averages the accounts");
    assert.equal(o.scan.accounts, 2);
    assert.equal(o.trend.length, 1, "the combined trend starts once both accounts are scanned");
    assert.equal(o.trend[0].counts.high, o.accounts[0].counts.high + o.accounts[1].counts.high);
    const zones = await json("/api/zones?scope=all");
    assert.deepEqual(zones.zones.map((z: { name: string; account: string }) => `${z.name} ${z.account}`).sort(), [
      "mock.example Mock Co",
      "other.example Other Ltd",
    ]);

    // An entity kept out of combined views disappears from "all" but stays reachable on its own.
    await json(`/api/entities/${other}`, "PATCH", { includeInAll: false });
    assert.deepEqual(await accountsIn("all"), [MOCK_ACCOUNT]);
    assert.deepEqual(await accountsIn(`e:${other}`), [MOCK_ACCOUNT_2]);
    const report = await json("/api/report?scope=all");
    assert.ok(!JSON.stringify(report).includes("Other Ltd"), "the combined report leaves the excluded entity out");
    cleanup();
  });

  test("unknown scopes are rejected; scans and exports follow the scope", async () => {
    const { call, json, cleanup } = await twoEntities();
    assert.equal((await call("/api/overview?scope=a:ffffffffffffffffffffffffffffffff")).status, 404);
    assert.equal((await call("/api/overview?scope=bogus")).status, 404);
    const csv = await (await call(`/api/export/findings.csv?scope=a:${MOCK_ACCOUNT_2}`)).text();
    assert.ok(csv.includes("Other Ltd") && !csv.includes("Mock Co"));
    assert.match((await call(`/api/export/findings.csv?scope=a:${MOCK_ACCOUNT_2}`)).headers.get("content-disposition") || "", /edgewatch-findings-other-ltd-/);
    const scans = await json(`/api/scans?scope=a:${MOCK_ACCOUNT}`);
    assert.ok(scans.scans.every((s: { accountId: string }) => s.accountId === MOCK_ACCOUNT));
    const started = await json("/api/scan", "POST", { scope: `a:${MOCK_ACCOUNT_2}` });
    assert.deepEqual(started.queued, [MOCK_ACCOUNT_2]);
    cleanup();
  });

  test("accounts can be renamed, moved, paused and removed with their data", async () => {
    const { call, json, repo, vault, scanner, other, mock, cleanup } = await twoEntities();
    await json(`/api/accounts/${MOCK_ACCOUNT}`, "PATCH", { alias: "Production", scheduled: false });
    assert.equal(repo.accounts.get(MOCK_ACCOUNT)!.alias, "Production");
    assert.equal(repo.accounts.get(MOCK_ACCOUNT)!.scheduled, false);
    assert.equal((await json(`/api/findings?scope=a:${MOCK_ACCOUNT}`)).findings[0].account, "Production");
    assert.equal((await call(`/api/entities/${mock}`, { method: "DELETE", body: "{}" })).status, 409, "an entity with accounts can't be deleted");
    await json(`/api/accounts/${MOCK_ACCOUNT}`, "PATCH", { entityId: other });
    assert.equal((await call(`/api/entities/${mock}`, { method: "DELETE", body: "{}" })).status, 200);
    const tokenId = repo.accounts.get(MOCK_ACCOUNT_2)!.tokenId;
    const fp = (await json(`/api/findings?scope=a:${MOCK_ACCOUNT_2}`)).findings[0].fingerprint;
    await json(`/api/triage/${fp}`, "PUT", { status: "in_progress", owner: "x" });
    await scanner.start("idle").done;
    assert.equal((await call(`/api/accounts/${MOCK_ACCOUNT_2}`, { method: "DELETE", body: "{}" })).status, 200);
    assert.equal(repo.accounts.get(MOCK_ACCOUNT_2), null);
    assert.equal(repo.scans.latest(MOCK_ACCOUNT_2), null);
    assert.equal(repo.store.all("SELECT * FROM triage WHERE fingerprint = ?", fp).length, 0, "triage goes with the account");
    assert.equal(vault.get(tokenId), null, "an unused token is deleted");
    cleanup();
  });

  test("one token can add several accounts at once", async () => {
    const { json, repo, vault, scanner, cleanup } = await twoEntities();
    const r = await json("/api/accounts", "POST", {
      token: MOCK_TOKEN,
      accountIds: [MOCK_ACCOUNT, MOCK_ACCOUNT_3],
      entityId: repo.accounts.get(MOCK_ACCOUNT)!.entityId,
    });
    assert.deepEqual(r.added, [MOCK_ACCOUNT_3]);
    assert.deepEqual(r.updated, [MOCK_ACCOUNT]);
    assert.equal(repo.accounts.get(MOCK_ACCOUNT_3)!.tokenId, repo.accounts.get(MOCK_ACCOUNT)!.tokenId, "both accounts share one stored token");
    assert.ok(vault.get(repo.accounts.get(MOCK_ACCOUNT_3)!.tokenId));
    await scanner.start("idle").done;
    const e = await json(`/api/overview?scope=e:${repo.accounts.get(MOCK_ACCOUNT)!.entityId}`);
    assert.deepEqual(e.accounts.map((a: { name: string }) => a.name).sort(), ["Mock Co", "Mock Co Staging"]);
    cleanup();
  });

  test("replacing a token checks it can read the account", async () => {
    const { call, json, repo, cleanup } = await twoEntities();
    const wrong = await call(`/api/accounts/${MOCK_ACCOUNT}/token`, { method: "PUT", body: JSON.stringify({ token: MOCK_TOKEN_2 }) });
    assert.equal(wrong.status, 400);
    const before = repo.accounts.get(MOCK_ACCOUNT)!.tokenId;
    assert.equal((await json(`/api/accounts/${MOCK_ACCOUNT}/token`, "PUT", { token: MOCK_TOKEN })).ok, true);
    assert.equal(repo.accounts.get(MOCK_ACCOUNT)!.tokenId, before, "the same token keeps its ID");
    cleanup();
  });

  test("neither token appears in any response", async () => {
    const { call, cleanup } = await twoEntities();
    for (const p of ["/api/session", "/api/accounts", "/api/overview", "/api/findings", "/api/scans", "/api/report", "/api/export/findings.json"]) {
      const text = await (await call(p)).text();
      assert.ok(!text.includes(MOCK_TOKEN) && !text.includes(MOCK_TOKEN_2), p);
    }
    cleanup();
  });
});

describe("upgrade from a single-account install", () => {
  test("config.json becomes the first account and global alerts move to its entity", () => {
    const dir = mkdtempSync(join(tmpdir(), "edgewatch-legacy-"));
    writeFileSync(join(dir, "config.json"), JSON.stringify({ token: MOCK_TOKEN, accountId: MOCK_ACCOUNT, accountName: "Mock Co", tokenKind: "user" }), {
      mode: 0o600,
    });
    const repo = new Repo(new Store(":memory:"));
    repo.store.run(
      "INSERT INTO settings (key, value) VALUES ('orgDomains', ?), ('notifications', ?)",
      JSON.stringify(["corp.example"]),
      JSON.stringify({ slackWebhookUrl: "https://hooks.slack.com/x", webhookUrl: "", minSeverity: "critical", baseUrl: "https://ew.example" }),
    );
    const vault = new TokenVault(dir);
    importLegacy(dir, repo, vault, () => {});
    const [e] = repo.entities.list();
    assert.equal(e.name, "Mock Co");
    assert.deepEqual(e.orgDomains, ["corp.example"]);
    assert.equal(e.notifications.minSeverity, "critical");
    assert.equal(e.notifications.slackWebhookUrl, "https://hooks.slack.com/x");
    assert.equal(repo.settings.get().baseUrl, "https://ew.example");
    assert.equal(vault.get(repo.accounts.get(MOCK_ACCOUNT)!.tokenId)?.token, MOCK_TOKEN);
    assert.equal(repo.settings.raw("notifications"), undefined);
    assert.equal(existsSync(join(dir, "config.json")), false);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("password mode", () => {
  test("requires login, rate-limits guesses, and issues a strict session cookie", async () => {
    const { call, cleanup } = makeApp({ password: PASSWORD, configured: true });
    assert.equal((await call("/api/overview")).status, 401);
    const s = (await (await call("/api/session")).json()) as any;
    assert.equal(s.authRequired, true);
    assert.equal(s.accounts, undefined, "no account details before login");

    const wrong = await call("/api/login", { method: "POST", body: JSON.stringify({ password: "nope" }) });
    assert.equal(wrong.status, 401);
    const right = await call("/api/login", { method: "POST", body: JSON.stringify({ password: PASSWORD }) });
    assert.equal(right.status, 200);
    const cookie = right.headers.get("set-cookie") || "";
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/);
    const session = cookie.split(";")[0];
    assert.equal((await call("/api/overview", { headers: { cookie: session } })).status, 200);

    for (let i = 0; i < 10; i++) await call("/api/login", { method: "POST", body: JSON.stringify({ password: "x" }) });
    const limited = (await (await call("/api/login", { method: "POST", body: JSON.stringify({ password: PASSWORD }) })).json()) as any;
    assert.match(limited.error, /Too many/);
    cleanup();
  });
});
