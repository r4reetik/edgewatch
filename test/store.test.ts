// Store migrations and finding history.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprint } from "../src/core/engine.ts";
import { Store, MIGRATIONS } from "../src/store/db.ts";
import { Repo, DEFAULT_SETTINGS } from "../src/store/repo.ts";
import { ACCOUNT } from "./fixtures/inventory.ts";
import type { Result } from "../src/core/types.ts";

describe("store: migration 2 and reopen tracking", () => {
  test("a v1 database migrates in place and keeps its data", () => {
    const dir = mkdtempSync(join(tmpdir(), "edgewatch-mig-"));
    const path = join(dir, "edgewatch.db");
    const db = new DatabaseSync(path);
    db.exec("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
    db.exec(MIGRATIONS[0]);
    db.prepare("INSERT INTO schema_migrations VALUES (1, 'x')").run();
    db.prepare("INSERT INTO scans (account_id, started_at, trigger, status) VALUES (?, ?, 'old', 'done')").run(ACCOUNT, "2026-01-01T00:00:00Z");
    db.close();
    const store = new Store(path);
    const cols = store.all<{ name: string }>("PRAGMA table_info(finding_history)").map((c) => c.name);
    assert.ok(cols.includes("reopen_count") && cols.includes("reopened_at"));
    assert.equal(store.all("SELECT * FROM scans").length, 1);
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("a finding that disappears and comes back is marked reopened", () => {
    const repo = new Repo(new Store(":memory:"));
    const f: Result = {
      checkId: "IAM-001",
      source: "custom",
      category: "Identity & access",
      title: "t",
      zone: null,
      resource: "a@x",
      pass: false,
      severity: "high",
      detail: "",
      evidence: null,
      link: null,
    };
    f.fingerprint = fingerprint(ACCOUNT, f);
    const scan = (items: Result[]) => {
      const { id } = repo.scans.create(ACCOUNT, "t");
      repo.scans.complete(id, { findings: items, score: 1, counts: {}, categories: {}, snapshot: {}, calls: 1 });
      return id;
    };
    const first = scan([f]);
    assert.equal(repo.findings.forScan(first, DEFAULT_SETTINGS.slaDays)[0].reopened, false);
    scan([]);
    const third = scan([f]);
    assert.equal(repo.findings.forScan(third, DEFAULT_SETTINGS.slaDays)[0].reopened, true);
  });
});
