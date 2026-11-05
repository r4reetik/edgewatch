// Limits for an instance reachable over a network: request sizes, login rate
// limits behind a proxy, malformed paths, and requests that are rejected
// without changing anything.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_TOKEN } from "../dev/mock/cloudflare.ts";
import { makeApp } from "./helpers/app.ts";
import { Store } from "../src/store/db.ts";
import { Repo } from "../src/store/repo.ts";
import { deleteOrphans } from "../src/store/findings.ts";

const PASSWORD = "correct horse battery staple";
let restore: () => void;
before(() => {
  restore = installMockCloudflare();
});
after(() => restore());

describe("requests", () => {
  test("oversized bodies are refused before they're parsed, even unauthenticated", async () => {
    const { call, cleanup } = makeApp({ password: PASSWORD });
    const big = JSON.stringify({ password: "x".repeat(10_000) });
    assert.equal((await call("/api/login", { method: "POST", body: big })).status, 413);
    const huge = JSON.stringify({ name: "x".repeat(1_100_000) });
    assert.equal((await call("/api/entities", { method: "POST", body: huge })).status, 413);
    cleanup();
  });

  test("a malformed percent-encoded path is a 404, not a server error", async () => {
    const { call, cleanup } = makeApp();
    assert.equal((await call("/%E0%A4%A")).status === 500, false);
    assert.equal((await call("/assets/%2e%2e/%2e%2e/secret.txt")).status, 404);
    cleanup();
  });
});

describe("login behind a proxy", () => {
  test("the limit applies to the address the proxy saw, not one the client wrote into X-Forwarded-For", async () => {
    const { call, cleanup } = makeApp({ password: PASSWORD, trustProxy: true });
    const login = (forged: string) =>
      call("/api/login", { method: "POST", body: JSON.stringify({ password: "wrong" }), headers: { "x-forwarded-for": `${forged}, 203.0.113.9` } });
    for (let i = 0; i < 10; i++) assert.equal((await login(`198.51.100.${i}`)).status, 401);
    const limited = (await (await login("198.51.100.99")).json()) as { error: string };
    assert.match(limited.error, /Too many attempts/);
    cleanup();
  });
});

describe("rejected requests change nothing", () => {
  test("an account update with one invalid field saves none of it", async () => {
    const { call, json, cleanup } = makeApp({ configured: true });
    const res = await call(`/api/accounts/${MOCK_ACCOUNT}`, { method: "PATCH", body: JSON.stringify({ alias: "Renamed", scheduled: "yes" }) });
    assert.equal(res.status, 400);
    const acc = (await json("/api/accounts")).entities
      .flatMap((e: { accounts: { id: string; alias: string | null }[] }) => e.accounts)
      .find((a: { id: string }) => a.id === MOCK_ACCOUNT);
    assert.equal(acc.alias, null);
    cleanup();
  });

  test("re-adding accounts that already exist doesn't leave an empty entity behind", async () => {
    const { json, cleanup } = makeApp({ configured: true });
    const before = (await json("/api/accounts")).entities.length;
    const res = await json("/api/accounts", "POST", { token: MOCK_TOKEN, accountIds: [MOCK_ACCOUNT], entityName: "Another" });
    assert.equal(res.updated[0], MOCK_ACCOUNT);
    assert.equal((await json("/api/accounts")).entities.length, before);
    cleanup();
  });
});

describe("retention", () => {
  test("triage of a finding no stored scan reports any more goes with it", () => {
    const repo = new Repo(new Store(":memory:"));
    const fp = "0000000000000000000a";
    repo.findings.setTriage([fp], { status: "accepted", note: "kept forever?" }, "admin");
    assert.ok(repo.findings.triageOf(fp));
    deleteOrphans(repo.store);
    assert.equal(repo.findings.triageOf(fp), null);
    assert.equal(repo.store.all("SELECT * FROM triage_events WHERE fingerprint = ?", fp).length, 0);
  });
});
