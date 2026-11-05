// Scan records: lifecycle, history for trends, and retention.

import type { Store } from "./db.ts";
import { deleteOrphans } from "./findings.ts";
import type { ScanRecord, ScanSummaryRecord } from "./rows.ts";
import type { Result, CategoryTotals } from "../core/types.ts";
import type { ScanSnapshot } from "../shared/api.ts";
import { DAY_MS } from "../shared/time.ts";

const SUMMARY_COLUMNS = "id, account_id, started_at, finished_at, trigger, status, score, counts, api_calls, error";

/** A completed scan with its snapshot parsed. */
export interface DoneScan extends ScanRecord {
  finished_at: string;
  snap: Partial<ScanSnapshot>;
}

export class ScanRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  /** Marks scans left "running" by a crash or restart as failed. */
  recoverInterrupted(): void {
    this.#s.run(
      "UPDATE scans SET status = 'failed', finished_at = ?, error = 'Interrupted: the server stopped during the scan.' WHERE status = 'running'",
      new Date().toISOString(),
    );
  }

  create(accountId: string, trigger: string): { id: number; started: string } {
    const started = new Date().toISOString();
    const r = this.#s.run("INSERT INTO scans (account_id, started_at, trigger, status) VALUES (?, ?, ?, 'running')", accountId, started, trigger);
    return { id: Number(r.lastInsertRowid), started };
  }

  fail(id: number, error: string, calls: number): void {
    this.#s.run(
      "UPDATE scans SET finished_at = ?, status = 'failed', error = ?, api_calls = ? WHERE id = ?",
      new Date().toISOString(),
      error.slice(0, 2000),
      calls,
      id,
    );
  }

  /** Stores a finished scan's findings and snapshot, and updates each finding's history. */
  complete(
    id: number,
    data: {
      findings: Result[];
      score: number | null;
      counts: Record<string, number>;
      categories: CategoryTotals;
      snapshot: Partial<ScanSnapshot>;
      calls: number;
    },
  ): void {
    const now = new Date().toISOString();
    this.#s.tx(() => {
      const insert = this.#s.db.prepare(
        "INSERT OR REPLACE INTO findings (scan_id, fingerprint, check_id, source, severity, category, zone, resource, title, detail, evidence, link, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      );
      const reopen = this.#s.db.prepare(
        "UPDATE finding_history SET reopen_count = reopen_count + 1, reopened_at = ? WHERE fingerprint = ? AND resolved_at IS NOT NULL",
      );
      const seen = this.#s.db.prepare(
        "INSERT INTO finding_history (fingerprint, first_seen, last_seen) VALUES (?, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen, resolved_at = NULL",
      );
      for (const f of data.findings) {
        const evidence = { ...(f.evidence || {}), ...(f.corroborated ? { securityCenter: f.corroborated } : {}) };
        insert.run(
          id,
          f.fingerprint!,
          f.checkId,
          f.source,
          f.severity,
          f.category,
          f.zone,
          f.resource,
          f.title,
          f.detail || "",
          Object.keys(evidence).length ? JSON.stringify(evidence) : null,
          f.link,
          f.confidence ?? null,
        );
        reopen.run(now, f.fingerprint!);
        seen.run(f.fingerprint!, now, now);
      }
      // Anything in the account's previous scan that this scan no longer reports is resolved.
      this.#s.run(
        `UPDATE finding_history SET resolved_at = ? WHERE resolved_at IS NULL
         AND fingerprint IN (SELECT fingerprint FROM findings WHERE scan_id = (
           SELECT p.id FROM scans p, scans c WHERE c.id = ? AND p.account_id = c.account_id AND p.status = 'done' AND p.id < c.id ORDER BY p.id DESC LIMIT 1))
         AND fingerprint NOT IN (SELECT fingerprint FROM findings WHERE scan_id = ?)`,
        now,
        id,
        id,
      );
      this.#s.run(
        "UPDATE scans SET finished_at = ?, status = 'done', score = ?, counts = ?, category_totals = ?, snapshot = ?, api_calls = ? WHERE id = ?",
        now,
        data.score,
        JSON.stringify(data.counts),
        JSON.stringify(data.categories),
        JSON.stringify(data.snapshot),
        data.calls,
        id,
      );
    });
  }

  /** The account's latest completed scan, with its snapshot. */
  latest(accountId: string): DoneScan | null {
    const r = this.#s.get<ScanRecord>("SELECT * FROM scans WHERE account_id = ? AND status = 'done' ORDER BY id DESC LIMIT 1", accountId);
    return r ? { ...r, finished_at: r.finished_at!, snap: JSON.parse(r.snapshot || "{}") } : null;
  }

  /** The latest completed scan without its snapshot: cheap enough for status polling. */
  latestSummary(accountId: string): ScanSummaryRecord | null {
    return (
      this.#s.get<ScanSummaryRecord>(`SELECT ${SUMMARY_COLUMNS} FROM scans WHERE account_id = ? AND status = 'done' ORDER BY id DESC LIMIT 1`, accountId) ??
      null
    );
  }

  previous(accountId: string, beforeId: number): Pick<ScanRecord, "id" | "finished_at"> | null {
    return (
      this.#s.get<Pick<ScanRecord, "id" | "finished_at">>(
        "SELECT id, finished_at FROM scans WHERE account_id = ? AND status = 'done' AND id < ? ORDER BY id DESC LIMIT 1",
        accountId,
        beforeId,
      ) ?? null
    );
  }

  lastFailed(accountId: string): Pick<ScanRecord, "id" | "finished_at" | "error"> | null {
    return (
      this.#s.get<Pick<ScanRecord, "id" | "finished_at" | "error">>(
        "SELECT id, finished_at, error FROM scans WHERE account_id = ? AND status = 'failed' ORDER BY id DESC LIMIT 1",
        accountId,
      ) ?? null
    );
  }

  list(accountIds: string[], limit = 100): ScanSummaryRecord[] {
    if (!accountIds.length) return [];
    return this.#s.all<ScanSummaryRecord>(
      `SELECT ${SUMMARY_COLUMNS} FROM scans WHERE account_id IN (${accountIds.map(() => "?").join(",")}) ORDER BY id DESC LIMIT ?`,
      ...accountIds,
      limit,
    );
  }

  /** When the account's last scan started (0 if never), for the scheduler. */
  lastStarted(accountId: string): number {
    const r = this.#s.get<{ started_at: string }>("SELECT started_at FROM scans WHERE account_id = ? ORDER BY id DESC LIMIT 1", accountId);
    return r ? Date.parse(r.started_at) : 0;
  }

  /** Completed scans, oldest first, for the score trend. */
  trend(accountId: string, limit = 90): Pick<ScanRecord, "id" | "finished_at" | "score" | "counts">[] {
    return this.#s
      .all<Pick<ScanRecord, "id" | "finished_at" | "score" | "counts">>(
        "SELECT id, finished_at, score, counts FROM scans WHERE account_id = ? AND status = 'done' ORDER BY id DESC LIMIT ?",
        accountId,
        limit,
      )
      .reverse();
  }

  /** Short records of a scan's findings, for "new and resolved since the last scan". */
  fingerprints(scanId: number): {
    fingerprint: string;
    check_id: string;
    title: string;
    resource: string;
    severity: string;
    zone: string | null;
    category: string;
    confidence: string | null;
  }[] {
    return this.#s.all("SELECT fingerprint, check_id, title, resource, severity, zone, category, confidence FROM findings WHERE scan_id = ?", scanId);
  }

  /** Deletes scans (and their findings) older than the retention window, always keeping the latest, and the triage of findings that leaves behind. */
  prune(accountId: string, retentionDays: number): void {
    const latest = this.latestSummary(accountId);
    const { changes } = this.#s.run(
      "DELETE FROM scans WHERE account_id = ? AND started_at < ? AND id != ?",
      accountId,
      new Date(Date.now() - retentionDays * DAY_MS).toISOString(),
      latest?.id ?? -1,
    );
    if (Number(changes) > 0) deleteOrphans(this.#s);
  }
}
