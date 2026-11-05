// Upgrades must be safe: shipped migrations never change, an existing database
// is backed up before it's migrated, and a database from a newer Edgewatch is
// refused instead of being misread.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { MIGRATIONS, NewerDatabaseError, Store } from "../src/store/db.ts";

/**
 * Fingerprints of every released migration. Append a line when you add a
 * migration; never change an existing one. Users' databases already ran them,
 * so a fix needs a new migration instead.
 */
const SHIPPED = ["1d4e7bd803fb7be7", "03a85dfc75f3fd2a", "1526ed8c910c6781", "ce02ff70a5bd33c7"];

const hash = (sql: string) => createHash("sha256").update(sql).digest("hex").slice(0, 16);

describe("migrations", () => {
  test("released migrations are unchanged, and new ones are listed", () => {
    assert.deepEqual(MIGRATIONS.slice(0, SHIPPED.length).map(hash), SHIPPED, "a shipped migration was edited: add a new migration instead");
    assert.equal(MIGRATIONS.length, SHIPPED.length, `add the new migration's fingerprint to SHIPPED: ${MIGRATIONS.slice(SHIPPED.length).map(hash).join(", ")}`);
  });

  test("an older database is backed up before it's migrated, and only the newest backups are kept", () => {
    const dir = mkdtempSync(join(tmpdir(), "edgewatch-migrate-"));
    const path = join(dir, "edgewatch.db");
    try {
      // A database left at schema 2 by an older version.
      const old = new DatabaseSync(path);
      old.exec("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
      for (const [i, sql] of MIGRATIONS.slice(0, 2).entries()) {
        old.exec(sql);
        old.prepare("INSERT INTO schema_migrations VALUES (?, ?)").run(i + 1, "2026-01-01");
      }
      old.close();

      // Three backups from earlier upgrades; the oldest goes when a fourth is made.
      mkdirSync(join(dir, "backups"));
      for (const d of ["20250101", "20250201", "20250301"]) writeFileSync(join(dir, "backups", `edgewatch-${d}T000000-schema1.db`), "");

      const logs: string[] = [];
      new Store(path, { log: (m) => logs.push(m) }).close();
      const all = readdirSync(join(dir, "backups")).sort();
      assert.equal(all.length, 3);
      assert.ok(!all.includes("edgewatch-20250101T000000-schema1.db"), "the oldest backup was removed");
      const backups = all.filter((f) => !f.startsWith("edgewatch-2025"));
      assert.equal(backups.length, 1);
      assert.match(backups[0], /^edgewatch-\d{8}T\d{6}-schema2\.db$/);
      assert.equal(statSync(join(dir, "backups", backups[0])).mode & 0o777, 0o600, "owner-only, like the database");
      const copy = new DatabaseSync(join(dir, "backups", backups[0]));
      assert.equal((copy.prepare("SELECT MAX(version) AS v FROM schema_migrations").get() as { v: number }).v, 2, "the backup is the pre-upgrade database");
      copy.close();
      assert.match(logs[0], /schema 2 → \d+; backed up/);

      // Opening an up-to-date database makes no copy.
      new Store(path).close();
      assert.equal(readdirSync(join(dir, "backups")).length, 3);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a database from a newer Edgewatch is refused", () => {
    const dir = mkdtempSync(join(tmpdir(), "edgewatch-newer-"));
    const path = join(dir, "edgewatch.db");
    try {
      new Store(path).close();
      const db = new DatabaseSync(path);
      db.prepare("INSERT INTO schema_migrations VALUES (?, ?)").run(MIGRATIONS.length + 1, "2027-01-01");
      db.close();
      assert.throws(() => new Store(path), NewerDatabaseError);
      assert.throws(() => new Store(path), /newer Edgewatch .*Run that version or newer\.$/);
      // With backups, it names the one from before the upgrade (the newest this version can read).
      mkdirSync(join(dir, "backups"));
      for (const f of [`edgewatch-20260101T000000-schema${MIGRATIONS.length}.db`, `edgewatch-20270101T000000-schema${MIGRATIONS.length + 1}.db`])
        writeFileSync(join(dir, "backups", f), "");
      assert.throws(() => new Store(path), new RegExp(`restore .*edgewatch-20260101T000000-schema${MIGRATIONS.length}\\.db`));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
