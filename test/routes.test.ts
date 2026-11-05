// API routes beyond the core flows in server.test.ts: settings and checks,
// entities, triage patches and history, the triaged list, finding permalinks,
// filtered exports.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_ACCOUNT_2, MOCK_TOKEN_2 } from "../dev/mock/cloudflare.ts";
import { seedAccount } from "../dev/mock/accounts.ts";
import { makeApp } from "./helpers/app.ts";

let restore: () => void;
before(() => {
  restore = installMockCloudflare();
});
after(() => restore());

async function scanned() {
  const app = makeApp({ configured: true });
  seedAccount(app.repo, app.vault, { id: MOCK_ACCOUNT_2, token: MOCK_TOKEN_2, name: "Other Ltd", entity: "Other Ltd" });
  await app.scanner.start("test").done;
  return app;
}

describe("settings and checks", () => {
  test("settings updates are validated and partial", async () => {
    const { call, json, cleanup } = makeApp();
    const bad = await call("/api/settings", { method: "PUT", body: JSON.stringify({ retentionDays: 2 }) });
    assert.equal(bad.status, 400);
    assert.match(((await bad.json()) as { error: string }).error, /between 7 and 3650/);
    const next = await json("/api/settings", "PUT", { schedule: { hourUtc: 5 } });
    assert.equal(next.schedule.hourUtc, 5);
    assert.equal(next.schedule.enabled, true, "fields left out keep their value");
    cleanup();
  });

  test("a check can be turned off and its severity changed", async () => {
    const { call, json, cleanup } = makeApp({ configured: true });
    assert.equal((await call("/api/checks/NOPE-001", { method: "PUT", body: JSON.stringify({ disabled: true }) })).status, 404);
    assert.equal((await call("/api/checks/TLS-001", { method: "PUT", body: JSON.stringify({ severity: "urgent" }) })).status, 400);
    await json("/api/checks/TLS-001", "PUT", { disabled: true, severity: "low" });
    const row = (await json("/api/checks")).checks.find((c: { id: string }) => c.id === "TLS-001");
    assert.equal(row.disabled, true);
    assert.equal(row.severityOverride, "low");
    assert.ok(row.docs.startsWith("https://developers.cloudflare.com/"));
    cleanup();
  });

  test("template link and sign-out work without an account", async () => {
    const { call, json, cleanup } = makeApp();
    assert.match((await json(`/api/accounts/template?accountId=${MOCK_ACCOUNT}`)).url, /permissionGroupKeys=/);
    assert.equal((await call("/api/logout", { method: "POST", body: "{}" })).status, 200);
    cleanup();
  });
});

describe("entities", () => {
  test("create, rename, keep separate, and refuse to delete while it has accounts", async () => {
    const { call, json, repo, cleanup } = makeApp({ configured: true });
    assert.equal((await call("/api/entities", { method: "POST", body: JSON.stringify({ name: "  " }) })).status, 400);
    const { entity } = await json("/api/entities", "POST", { name: "Acme" });
    const patched = await json(`/api/entities/${entity.id}`, "PATCH", { name: "Acme Ltd", includeInAll: false, orgDomains: ["acme.example"] });
    assert.equal(patched.entity.name, "Acme Ltd");
    assert.equal(patched.entity.includeInAll, false);
    assert.equal((await call(`/api/entities/${entity.id}/test-notification`, { method: "POST", body: "{}" })).status, 400, "no destination yet");
    const busy = repo.accounts.list()[0].entityId;
    assert.equal((await call(`/api/entities/${busy}`, { method: "DELETE", body: "{}" })).status, 409);
    assert.equal((await call(`/api/entities/${entity.id}`, { method: "DELETE", body: "{}" })).status, 200);
    cleanup();
  });
});

describe("triage", () => {
  test("a patch changes only the fields it names, appends notes, and every change is in the timeline", async () => {
    const { json, call, cleanup } = await scanned();
    const [a, b] = (await json(`/api/findings?scope=a:${MOCK_ACCOUNT}`)).findings;
    await json(`/api/triage/${a.fingerprint}`, "PUT", { status: "in_progress", owner: "sam", note: "ticket 1", dueDate: "2030-01-01" });
    await json("/api/triage", "POST", { fingerprints: [a.fingerprint, b.fingerprint], owner: "alex", appendNote: "bulk" });
    const after = (await json(`/api/findings?scope=a:${MOCK_ACCOUNT}`)).findings;
    const ta = after.find((f: { fingerprint: string }) => f.fingerprint === a.fingerprint).triage;
    assert.equal(ta.owner, "alex");
    assert.equal(ta.status, "in_progress", "status kept");
    assert.equal(ta.dueDate, "2030-01-01", "due date kept");
    assert.equal(ta.note, "ticket 1\n\nbulk");
    assert.equal((await call("/api/triage", { method: "POST", body: JSON.stringify({ fingerprints: [a.fingerprint] }) })).status, 400, "nothing to change");

    const detail = await json(`/api/finding/${a.fingerprint}`);
    const triage = detail.events.filter((e: { kind: string }) => e.kind === "triage");
    assert.equal(triage.length, 2);
    assert.deepEqual(triage[1].changes.owner, { from: "sam", to: "alex" });
    assert.equal(detail.events[0].kind, "first_seen");
    cleanup();
  });
});

describe("triaged", () => {
  test("lists triaged findings in scope, newest change first, and follows them after a scan stops finding them", async () => {
    const { json, repo, cleanup } = await scanned();
    const [a, b] = (await json(`/api/findings?scope=a:${MOCK_ACCOUNT}`)).findings;
    const other = (await json(`/api/findings?scope=a:${MOCK_ACCOUNT_2}`)).findings[0];
    await json(`/api/triage/${a.fingerprint}`, "PUT", { status: "in_progress" });
    await json(`/api/triage/${other.fingerprint}`, "PUT", { status: "false_positive" });
    await new Promise((r) => setTimeout(r, 5)); // so the last change is strictly newest
    await json(`/api/triage/${b.fingerprint}`, "PUT", { owner: "sam" });

    let list = (await json(`/api/triaged?scope=a:${MOCK_ACCOUNT}`)).findings;
    assert.deepEqual(
      list.map((f: { fingerprint: string }) => f.fingerprint),
      [b.fingerprint, a.fingerprint],
      "only this account, most recent change first",
    );
    assert.ok(list.every((f: { present: boolean; resolvedAt: unknown }) => f.present && f.resolvedAt === null));
    assert.deepEqual(
      list[1].events.map((e: { kind: string }) => e.kind),
      ["first_seen", "triage"],
    );
    assert.equal((await json("/api/triaged?scope=all")).findings.length, 3);

    // A later scan of the account that no longer reports `a`.
    const db = repo.store.db;
    const latest = repo.scans.latestSummary(MOCK_ACCOUNT)!.id;
    const columns = (t: string) => (db.prepare(`PRAGMA table_info(${t})`).all() as { name: string }[]).map((c) => c.name);
    const scanCols = columns("scans").filter((c) => c !== "id");
    const next = Number(db.prepare(`INSERT INTO scans (${scanCols}) SELECT ${scanCols} FROM scans WHERE id = ?`).run(latest).lastInsertRowid);
    db.prepare("UPDATE scans SET finished_at = ? WHERE id = ?").run(new Date(Date.now() + 1000).toISOString(), next);
    const findingCols = columns("findings").filter((c) => c !== "scan_id");
    db.prepare(`INSERT INTO findings (scan_id, ${findingCols}) SELECT ?, ${findingCols} FROM findings WHERE scan_id = ? AND fingerprint != ?`).run(
      next,
      latest,
      a.fingerprint,
    );

    list = (await json(`/api/triaged?scope=a:${MOCK_ACCOUNT}`)).findings;
    const gone = list.find((f: { fingerprint: string }) => f.fingerprint === a.fingerprint);
    assert.equal(gone.present, false);
    assert.ok(gone.resolvedAt);
    assert.equal(gone.status, "in_progress", "triage is kept");
    assert.equal(gone.events.at(-1).kind, "resolved");
    assert.equal(list.find((f: { fingerprint: string }) => f.fingerprint === b.fingerprint).present, true);
    cleanup();
  });
});

describe("finding permalinks", () => {
  test("resolve from any scope, and say where the finding lives", async () => {
    const { json, call, cleanup } = await scanned();
    const f = (await json(`/api/findings?scope=a:${MOCK_ACCOUNT_2}`)).findings[0];
    const d = await json(`/api/finding/${f.fingerprint}`);
    assert.equal(d.finding.fingerprint, f.fingerprint);
    assert.equal(d.accountId, MOCK_ACCOUNT_2);
    assert.equal(d.account, "Other Ltd");
    assert.equal((await call("/api/finding/0000000000000000000a")).status, 404);
    assert.equal((await call("/api/finding/not-a-fingerprint")).status, 404);
    cleanup();
  });
});

describe("exports", () => {
  test("take the Findings page filters, or an explicit selection", async () => {
    const { json, call, cleanup } = await scanned();
    const all = (await json(`/api/findings?scope=all`)).findings;
    const high = all.filter((f: { severity: string; settled: boolean }) => f.severity === "high");
    const filtered = (await (await call("/api/export/findings.json?scope=all&severity=high&status=all")).json()) as { findings: unknown[] };
    assert.equal(filtered.findings.length, high.length);
    const picked = (await (await call(`/api/export/findings.json?scope=all&fp=${all[0].fingerprint}&fp=${all[1].fingerprint}`)).json()) as {
      findings: { fingerprint: string }[];
    };
    assert.deepEqual(picked.findings.map((f: { fingerprint: string }) => f.fingerprint).sort(), [all[0].fingerprint, all[1].fingerprint].sort());
    const csv = await (await call(`/api/export/findings.csv?scope=all&check=${all[0].checkId}`)).text();
    assert.ok(csv.split("\r\n")[0].includes("checkId"));
    assert.ok(
      csv
        .split("\r\n")
        .slice(1)
        .every((l) => l.includes(all[0].checkId)),
    );
    cleanup();
  });
});
