// Findings as the dashboard sees them: stored results joined with their history
// and triage, plus triage updates, each finding's timeline, and everything triaged.

import type { Store } from "./db.ts";
import type { FindingRecord, TriageRecord } from "./rows.ts";
import { CHECK_BY_ID } from "../providers/catalog.ts";
import { isProvider, type ProviderId } from "../shared/providers.ts";
import { SEVERITY_WEIGHT, type Severity } from "../shared/severity.ts";
import { dueDate, effectiveStatus, isSettled, type SlaDays, type Triage, type TriageStatus } from "../shared/triage.ts";
import { isoDate } from "../shared/time.ts";
import { groupBy } from "../shared/collections.ts";
import type { Confidence, Finding, FindingBrief, FindingEvent, FindingSource } from "../shared/api.ts";

/** A finding before it's tagged with its account's display name and entity. */
export type StoredFinding = Omit<Finding, "account" | "entity">;

/** A triage change. Fields left undefined keep their current value. */
export type TriagePatch = Partial<Pick<Triage, "status" | "owner" | "note" | "dueDate" | "acceptUntil">>;

type Joined = FindingRecord & { account_id: string; provider: string | null; first_seen: string | null; reopen_count: number | null } & Partial<
    Record<`t_${keyof Omit<TriageRecord, "fingerprint">}`, string | null>
  >;

const TRIAGE_COLUMNS =
  "t.status AS t_status, t.owner AS t_owner, t.note AS t_note, t.due_date AS t_due_date, t.accept_until AS t_accept_until, t.updated_at AS t_updated_at, t.updated_by AS t_updated_by";

/**
 * Deletes triage and history of findings that no stored scan reports any more: those whose scans were
 * pruned by retention, or whose account was removed. Retention then covers triage too, and removing an
 * account leaves nothing of it behind (apart from upgrade backups).
 */
export function deleteOrphans(store: Store): void {
  for (const table of ["triage_events", "triage", "finding_history"]) {
    store.run(`DELETE FROM ${table} WHERE fingerprint NOT IN (SELECT DISTINCT fingerprint FROM findings)`);
  }
}

export const byImportance = (a: Pick<Finding, "severity" | "category" | "resource">, b: Pick<Finding, "severity" | "category" | "resource">) =>
  SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] || a.category.localeCompare(b.category) || a.resource.localeCompare(b.resource);

export class FindingRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  /** A scan's findings with current triage, most important first. */
  forScan(scanId: number, sla: SlaDays): StoredFinding[] {
    const rows = this.#s.all<Joined>(
      `SELECT f.*, s.account_id, (SELECT a.provider FROM accounts a WHERE a.id = s.account_id) AS provider, h.first_seen, h.reopen_count, ${TRIAGE_COLUMNS}
       FROM findings f JOIN scans s ON s.id = f.scan_id LEFT JOIN finding_history h ON h.fingerprint = f.fingerprint LEFT JOIN triage t ON t.fingerprint = f.fingerprint
       WHERE f.scan_id = ?`,
      scanId,
    );
    const today = isoDate();
    return rows.map((r) => toFinding(r, sla, today)).sort(byImportance);
  }

  triageOf(fingerprint: string): Triage | null {
    const r = this.#s.get<TriageRecord>("SELECT * FROM triage WHERE fingerprint = ?", fingerprint);
    return r ? toTriage(r) : null;
  }

  /** Applies a triage patch to each finding, recording what changed. */
  setTriage(fingerprints: string[], patch: TriagePatch, user: string, opts: { appendNote?: string } = {}): void {
    const now = new Date().toISOString();
    this.#s.tx(() => {
      const upsert = this.#s.db.prepare(
        `INSERT INTO triage (fingerprint, status, owner, note, due_date, accept_until, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(fingerprint) DO UPDATE SET status = excluded.status, owner = excluded.owner, note = excluded.note,
         due_date = excluded.due_date, accept_until = excluded.accept_until, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
      );
      const event = this.#s.db.prepare("INSERT INTO triage_events (fingerprint, at, by, changes) VALUES (?, ?, ?, ?)");
      for (const fp of fingerprints) {
        const cur = this.triageOf(fp) ?? { status: "open" as TriageStatus, owner: null, note: null, dueDate: null, acceptUntil: null };
        const next = { ...cur, ...Object.fromEntries(Object.entries(patch).filter(([, v]) => v !== undefined)) } as Triage;
        if (opts.appendNote) next.note = [cur.note, opts.appendNote].filter(Boolean).join("\n\n").slice(0, 4000);
        // Accepted risk is the only status with an expiry.
        if (next.status !== "accepted") next.acceptUntil = null;
        const changes: FindingEvent["changes"] = {};
        for (const k of ["status", "owner", "note", "dueDate", "acceptUntil"] as const) {
          if ((cur[k] ?? null) !== (next[k] ?? null)) changes[k] = { from: cur[k] ?? null, to: next[k] ?? null };
        }
        if (!Object.keys(changes).length) continue;
        upsert.run(fp, next.status, next.owner, next.note, next.dueDate, next.acceptUntil, now, user);
        event.run(fp, now, user, JSON.stringify(changes));
      }
    });
  }

  /**
   * Owners already assigned to findings in these accounts, most recently assigned first.
   * Spellings that differ only in case count as one, written as last used.
   */
  owners(accountIds: string[]): string[] {
    if (!accountIds.length) return [];
    const marks = accountIds.map(() => "?").join(", ");
    const rows = this.#s.all<{ owner: string }>(
      `SELECT t.owner FROM triage t
       WHERE t.owner IS NOT NULL AND t.owner <> ''
         AND EXISTS (SELECT 1 FROM findings f JOIN scans s ON s.id = f.scan_id WHERE f.fingerprint = t.fingerprint AND s.account_id IN (${marks}))
       ORDER BY t.updated_at DESC`,
      ...accountIds,
    );
    const seen = new Map<string, string>();
    for (const { owner } of rows) if (!seen.has(owner.toLowerCase())) seen.set(owner.toLowerCase(), owner);
    return [...seen.values()];
  }

  /** Fingerprints whose triage takes them out of the score (accepted and unexpired, or false positive). */
  settled(): Set<string> {
    const today = isoDate();
    return new Set(
      this.#s
        .all<TriageRecord>("SELECT * FROM triage")
        .filter((r) => isSettled(effectiveStatus(toTriage(r), today)))
        .map((r) => r.fingerprint),
    );
  }

  /** Where a fingerprint was last reported (any account), for permalinks. */
  locate(fingerprint: string): { accountId: string; scanId: number; latestScanId: number } | null {
    const r = this.#s.get<{ account_id: string; scan_id: number; latest: number }>(
      `SELECT s.account_id, f.scan_id, (SELECT MAX(id) FROM scans x WHERE x.account_id = s.account_id AND x.status = 'done') AS latest
       FROM findings f JOIN scans s ON s.id = f.scan_id WHERE f.fingerprint = ? ORDER BY f.scan_id DESC LIMIT 1`,
      fingerprint,
    );
    return r ? { accountId: r.account_id, scanId: r.scan_id, latestScanId: r.latest } : null;
  }

  /** The last stored version of a finding, for resolved permalinks. */
  lastBrief(fingerprint: string, scanId: number, account: string): FindingBrief | null {
    const r = this.#s.get<FindingRecord & { account_id: string; provider: string | null }>(
      "SELECT f.*, s.account_id, (SELECT a.provider FROM accounts a WHERE a.id = s.account_id) AS provider FROM findings f JOIN scans s ON s.id = f.scan_id WHERE f.fingerprint = ? AND f.scan_id = ?",
      fingerprint,
      scanId,
    );
    return r
      ? {
          fingerprint,
          checkId: r.check_id,
          title: r.title,
          resource: r.resource,
          severity: r.severity as Severity,
          zone: r.zone,
          category: r.category,
          accountId: r.account_id,
          provider: providerOr(r.provider),
          account,
          confidence: (r.confidence as Confidence) || null,
        }
      : null;
  }

  /** First seen, each scan's outcome (seen, resolved, reopened) and every triage change, oldest first. */
  timeline(fingerprint: string, accountId: string): FindingEvent[] {
    const scans = this.#s.all<ScanPoint>("SELECT id, finished_at FROM scans WHERE account_id = ? AND status = 'done' ORDER BY id", accountId);
    const seen = new Set(this.#s.all<{ scan_id: number }>("SELECT scan_id FROM findings WHERE fingerprint = ?", fingerprint).map((r) => r.scan_id));
    const triage = this.#s.all<EventRow>("SELECT fingerprint, at, by, changes FROM triage_events WHERE fingerprint = ? ORDER BY id", fingerprint);
    return buildTimeline(scans, seen, triage);
  }

  /**
   * Every triaged finding in these accounts, as last reported, with its timeline.
   * Includes findings a later scan no longer reports, so triage can be followed to the end.
   * Built with one query per table rather than one per finding.
   */
  triaged(accountIds: string[], sla: SlaDays): (StoredFinding & { present: boolean; events: FindingEvent[] })[] {
    if (!accountIds.length) return [];
    const marks = accountIds.map(() => "?").join(", ");
    const rows = this.#s.all<Joined & { latest: number | null }>(
      `SELECT f.*, s.account_id, (SELECT a.provider FROM accounts a WHERE a.id = s.account_id) AS provider, h.first_seen, h.reopen_count, ${TRIAGE_COLUMNS},
         (SELECT MAX(x.id) FROM scans x WHERE x.account_id = s.account_id AND x.status = 'done') AS latest
       FROM triage t
       JOIN findings f ON f.fingerprint = t.fingerprint AND f.scan_id = (SELECT MAX(g.scan_id) FROM findings g WHERE g.fingerprint = t.fingerprint)
       JOIN scans s ON s.id = f.scan_id
       LEFT JOIN finding_history h ON h.fingerprint = t.fingerprint
       WHERE s.account_id IN (${marks})`,
      ...accountIds,
    );
    if (!rows.length) return [];
    const scans = groupBy(
      this.#s.all<ScanPoint & { account_id: string }>(
        `SELECT id, finished_at, account_id FROM scans WHERE account_id IN (${marks}) AND status = 'done' ORDER BY id`,
        ...accountIds,
      ),
      (r) => r.account_id,
    );
    const seen = new Map<string, Set<number>>();
    for (const r of this.#s.all<{ fingerprint: string; scan_id: number }>(
      "SELECT f.fingerprint, f.scan_id FROM findings f JOIN triage t ON t.fingerprint = f.fingerprint",
    )) {
      if (!seen.has(r.fingerprint)) seen.set(r.fingerprint, new Set());
      seen.get(r.fingerprint)!.add(r.scan_id);
    }
    const triage = groupBy(
      this.#s.all<EventRow>("SELECT e.fingerprint, e.at, e.by, e.changes FROM triage_events e JOIN triage t ON t.fingerprint = e.fingerprint ORDER BY e.id"),
      (r) => r.fingerprint,
    );
    const today = isoDate();
    return rows.map((r) => ({
      ...toFinding(r, sla, today),
      present: r.scan_id === r.latest,
      events: buildTimeline(scans.get(r.account_id) ?? [], seen.get(r.fingerprint) ?? new Set(), triage.get(r.fingerprint) ?? []),
    }));
  }
}

type ScanPoint = { id: number; finished_at: string };
type EventRow = { fingerprint: string; at: string; by: string | null; changes: string };

/** A finding's history from its account's scans (oldest first), the scans that reported it, and its triage changes. */
function buildTimeline(scans: ScanPoint[], seen: Set<number>, triage: EventRow[]): FindingEvent[] {
  const events: FindingEvent[] = [];
  let present = false;
  for (const s of scans) {
    const has = seen.has(s.id);
    if (has && !events.length) events.push({ at: s.finished_at, kind: "first_seen", scanId: s.id });
    else if (has && !present && events.length) events.push({ at: s.finished_at, kind: "reopened", scanId: s.id });
    else if (!has && present) events.push({ at: s.finished_at, kind: "resolved", scanId: s.id });
    present = has;
  }
  for (const t of triage) events.push({ at: t.at, kind: "triage", by: t.by, changes: JSON.parse(t.changes) });
  return events.sort((a, b) => a.at.localeCompare(b.at));
}

function toTriage(r: Pick<TriageRecord, "status" | "owner" | "note" | "due_date" | "accept_until" | "updated_at" | "updated_by">): Triage {
  return {
    status: r.status as TriageStatus,
    owner: r.owner,
    note: r.note,
    dueDate: r.due_date,
    acceptUntil: r.accept_until,
    updatedAt: r.updated_at,
    updatedBy: r.updated_by,
  };
}

/** Findings of an account removed mid-request have no provider row; they were Cloudflare's before providers existed. */
const providerOr = (p: string | null | undefined): ProviderId => (isProvider(p) ? p : "cloudflare");

function toFinding(r: Joined, sla: SlaDays, today: string): StoredFinding {
  const check = CHECK_BY_ID[r.check_id];
  const triage = r.t_status
    ? toTriage({
        status: r.t_status,
        owner: r.t_owner ?? null,
        note: r.t_note ?? null,
        due_date: r.t_due_date ?? null,
        accept_until: r.t_accept_until ?? null,
        updated_at: r.t_updated_at!,
        updated_by: r.t_updated_by ?? null,
      })
    : null;
  const status = effectiveStatus(triage, today);
  const settled = isSettled(status);
  const severity = r.severity as Severity;
  const due = dueDate(severity, r.first_seen, triage, sla);
  return {
    fingerprint: r.fingerprint,
    accountId: r.account_id,
    provider: providerOr(r.provider),
    checkId: r.check_id,
    source: r.source as FindingSource,
    severity,
    category: r.category,
    zone: r.zone,
    resource: r.resource,
    title: r.title,
    detail: r.detail || "",
    link: r.link,
    evidence: r.evidence ? JSON.parse(r.evidence) : null,
    firstSeen: r.first_seen,
    why: check?.why || null,
    fix: check?.fix || null,
    docs: check?.docs || null,
    triage,
    status,
    settled,
    due,
    overdue: !settled && !!due && due < today,
    confidence: (r.confidence as Confidence) || null,
    reopened: Number(r.reopen_count || 0) > 0,
  };
}
