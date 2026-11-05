// SQLite storage (node:sqlite, no native dependencies). Migrations are applied
// in order on open and recorded in `schema_migrations`.

import { DatabaseSync } from "node:sqlite";
import { mkdirSync, existsSync, chmodSync } from "node:fs";
import { dirname } from "node:path";

export const MIGRATIONS: string[] = [
  `
  CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    trigger TEXT NOT NULL,
    status TEXT NOT NULL,                -- running | done | failed
    score REAL,
    counts TEXT,                         -- JSON: open findings by severity at scan time
    category_totals TEXT,                -- JSON: per-category weight totals for re-scoring
    snapshot TEXT,                       -- JSON: ScanSnapshot (src/shared/api.ts)
    api_calls INTEGER,
    error TEXT
  );
  CREATE INDEX scans_account ON scans(account_id, id);

  CREATE TABLE findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    check_id TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    zone TEXT,
    resource TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    evidence TEXT,
    link TEXT,
    PRIMARY KEY (scan_id, fingerprint)
  );
  CREATE INDEX findings_fp ON findings(fingerprint);

  CREATE TABLE finding_history (
    fingerprint TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT
  );

  CREATE TABLE triage (
    fingerprint TEXT PRIMARY KEY,
    status TEXT NOT NULL,                -- open | in_progress | accepted | false_positive
    owner TEXT,
    note TEXT,
    due_date TEXT,
    accept_until TEXT,                   -- accepted risk lapses back to open after this date
    updated_at TEXT NOT NULL,
    updated_by TEXT
  );

  CREATE TABLE check_overrides (
    check_id TEXT PRIMARY KEY,
    disabled INTEGER NOT NULL DEFAULT 0,
    severity TEXT
  );

  CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  `,
  `
  ALTER TABLE findings ADD COLUMN confidence TEXT;
  ALTER TABLE finding_history ADD COLUMN reopen_count INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE finding_history ADD COLUMN reopened_at TEXT;
  `,
  `
  -- An entity is a legal entity or team that owns accounts. It decides whether its
  -- accounts appear in combined views, and holds its own email domains and alerts.
  CREATE TABLE entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    include_in_all INTEGER NOT NULL DEFAULT 1,
    org_domains TEXT NOT NULL DEFAULT '[]',   -- JSON list
    notifications TEXT NOT NULL DEFAULT '{}', -- JSON: slackWebhookUrl, webhookUrl, minSeverity
    position INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE accounts (
    id TEXT PRIMARY KEY,                 -- Cloudflare account ID
    name TEXT,                           -- name in Cloudflare
    alias TEXT,                          -- display name set in Edgewatch
    entity_id INTEGER NOT NULL REFERENCES entities(id),
    token_id TEXT NOT NULL,              -- key into credentials.json, never the token
    token_kind TEXT,
    scheduled INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL DEFAULT 0,
    added_at TEXT NOT NULL
  );
  CREATE INDEX accounts_entity ON accounts(entity_id, position);
  `,
  `
  -- Every triage change, for each finding's timeline.
  CREATE TABLE triage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    at TEXT NOT NULL,
    by TEXT,
    changes TEXT NOT NULL                -- JSON: { field: { from, to } }
  );
  CREATE INDEX triage_events_fp ON triage_events(fingerprint, id);
  `,
];

export class Store {
  readonly db: DatabaseSync;

  constructor(path: string) {
    // The database holds member emails and account configuration: owner-only access.
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
    if (path !== ":memory:") for (const f of [path, `${path}-wal`, `${path}-shm`]) if (existsSync(f)) chmodSync(f, 0o600);
    this.#migrate();
  }

  #migrate(): void {
    this.db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
    const row = this.db.prepare("SELECT MAX(version) AS v FROM schema_migrations").get() as { v: number | null };
    for (let v = (row.v ?? 0) + 1; v <= MIGRATIONS.length; v++) {
      this.tx(() => {
        this.db.exec(MIGRATIONS[v - 1]);
        this.db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v, new Date().toISOString());
      });
    }
  }

  all<T>(sql: string, ...params: (string | number | null)[]): T[] {
    return this.db.prepare(sql).all(...params) as T[];
  }

  get<T>(sql: string, ...params: (string | number | null)[]): T | undefined {
    return this.db.prepare(sql).get(...params) as T | undefined;
  }

  run(sql: string, ...params: (string | number | null)[]) {
    return this.db.prepare(sql).run(...params);
  }

  tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      this.db.exec("COMMIT");
      return out;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  close(): void {
    this.db.close();
  }
}
