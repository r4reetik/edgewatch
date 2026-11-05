// Combines the latest scan of every account in a scope into one view. A scope
// with one account returns that account's data unchanged; with several, lists
// are concatenated and tagged with their account, counts are summed, and scores
// are the average of the accounts' scores, so a large account doesn't hide a
// small one.

import { computeScore } from "../core/engine.ts";
import { CHECK_BY_ID } from "../core/catalog.ts";
import { displayName, type Account, type DoneScan, type Entity, type Repo, type Scope } from "../store/repo.ts";
import { byImportance } from "../store/findings.ts";
import { groupBy } from "../shared/collections.ts";
import { countBySeverity, SEVERITY_WEIGHT, type SeverityCounts } from "../shared/severity.ts";
import type {
  AccountSummary,
  ActivityView,
  Coverage,
  Finding,
  FindingBrief,
  FindingGroup,
  ScanMeta,
  Settings,
  TrendPoint,
  ValueView,
  ZoneRow,
} from "../shared/api.ts";

export interface AccountScan {
  account: Account;
  entity: Entity | null;
  scan: DoneScan;
}

export function latestScans(repo: Repo, scope: Scope): AccountScan[] {
  const entities = new Map(repo.entities.list().map((e) => [e.id, e]));
  const out: AccountScan[] = [];
  for (const account of scope.accounts) {
    const scan = repo.scans.latest(account.id);
    if (scan) out.push({ account, entity: entities.get(account.entityId) ?? null, scan });
  }
  return out;
}

export function scopeFindings(repo: Repo, scans: AccountScan[], settings: Settings): Finding[] {
  const all = scans.flatMap(({ account, entity, scan }) =>
    repo.findings.forScan(scan.id, settings.slaDays).map((f): Finding => ({ ...f, account: displayName(account), entity: entity?.name ?? null })),
  );
  return scans.length > 1 ? all.sort(byImportance) : all;
}

export const brief = (f: Finding): FindingBrief => ({
  fingerprint: f.fingerprint,
  checkId: f.checkId,
  title: f.title,
  resource: f.resource,
  severity: f.severity,
  zone: f.zone,
  category: f.category,
  accountId: f.accountId,
  account: f.account,
  confidence: f.confidence,
});

/** When the scope was last scanned, and with how many calls. */
export function scanMeta(scans: AccountScan[]): ScanMeta | null {
  if (!scans.length) return null;
  const latest = scans.reduce((a, b) => (a.scan.finished_at > b.scan.finished_at ? a : b)).scan;
  const oldest = scans.reduce((a, b) => (a.scan.finished_at < b.scan.finished_at ? a : b)).scan;
  return {
    id: latest.id,
    startedAt: latest.started_at,
    finishedAt: latest.finished_at,
    trigger: latest.trigger,
    oldestFinishedAt: oldest.finished_at,
    accounts: scans.length,
    apiCalls: scans.reduce((s, x) => s + Number(x.scan.api_calls || 0), 0),
  };
}

/** Per-account scores recomputed with current triage, plus the combined score. */
export function scores(scans: AccountScan[], findings: Finding[]) {
  const byAccount = groupBy(findings, (f) => f.accountId);
  const accounts: AccountSummary[] = scans.map(({ account, entity, scan }) => {
    const mine = byAccount.get(account.id) || [];
    const s = computeScore(JSON.parse(scan.category_totals || "{}"), mine);
    return {
      id: account.id,
      name: displayName(account),
      entity: entity?.name ?? null,
      score: s.overall,
      categoryScores: s.byCategory,
      counts: countBySeverity(mine.filter((f) => !f.settled)),
      finishedAt: scan.finished_at,
    };
  });
  const categoryScores: Record<string, number | null> = {};
  for (const cat of new Set(accounts.flatMap((a) => Object.keys(a.categoryScores)))) {
    categoryScores[cat] = mean(accounts.map((a) => a.categoryScores[cat]));
  }
  return { overall: mean(accounts.map((a) => a.score)), byCategory: categoryScores, accounts };
}

function mean(xs: (number | null | undefined)[]): number | null {
  const v = xs.filter((x): x is number => x != null);
  return v.length ? Math.round((v.reduce((a, b) => a + b, 0) / v.length) * 10) / 10 : null;
}

/**
 * Open critical and high findings grouped by check, so one problem in three
 * accounts is one row. Ranked by severity, then confirmed before likely, then
 * overdue, then how many places it appears.
 */
export function fixFirst(open: Finding[], limit = 8): FindingGroup[] {
  const groups = groupBy(
    open.filter((f) => f.severity === "critical" || f.severity === "high"),
    (f) => f.checkId,
  );
  const confidenceRank = (c: Finding["confidence"]) => (c === "confirmed" ? 2 : c === null ? 1 : 0);
  return [...groups.entries()]
    .map(([checkId, fs]): FindingGroup => {
      const worst = fs.reduce((a, b) => (SEVERITY_WEIGHT[b.severity] > SEVERITY_WEIGHT[a.severity] ? b : a));
      return {
        checkId,
        title: CHECK_BY_ID[checkId]?.title || worst.title,
        severity: worst.severity,
        category: worst.category,
        confidence: fs.some((f) => f.confidence === "confirmed") ? "confirmed" : fs.some((f) => f.confidence === null) ? null : "likely",
        count: fs.length,
        accounts: [...new Set(fs.map((f) => f.account))],
        zones: [...new Set(fs.map((f) => f.zone).filter((z): z is string => !!z))],
        overdue: fs.filter((f) => f.overdue).length,
        fingerprint: fs.length === 1 ? fs[0].fingerprint : null,
      };
    })
    .sort(
      (a, b) =>
        SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] ||
        confidenceRank(b.confidence) - confidenceRank(a.confidence) ||
        b.overdue - a.overdue ||
        b.count - a.count,
    )
    .slice(0, limit);
}

/**
 * Score history: a point per scan. With several accounts, each point carries
 * every account's latest score forward, averages the scores and sums the counts.
 * It starts once every account has been scanned, so an account joining the view
 * doesn't look like a jump in findings.
 */
export function trend(repo: Repo, accounts: Account[]): TrendPoint[] {
  const series = accounts
    .map((a) => repo.scans.trend(a.id).map((t): TrendPoint => ({ at: t.finished_at!, score: t.score, counts: JSON.parse(t.counts || "{}") })))
    .filter((s) => s.length);
  if (series.length === 1) return series[0];
  // biome-ignore lint/complexity/useMathMinMax: these are ISO timestamps (strings); Math.max would turn them into NaN.
  const start = series.reduce((m, s) => (s[0].at > m ? s[0].at : m), "");
  const times = [...new Set(series.flat().map((p) => p.at))]
    .filter((t) => t >= start)
    .sort()
    .slice(-180);
  return times.map((at) => {
    const latest = series.map((s) => s.filter((p) => p.at <= at).at(-1)).filter((p) => p != null);
    const counts: Partial<SeverityCounts> = {};
    for (const p of latest) for (const [k, v] of Object.entries(p.counts) as [keyof SeverityCounts, number][]) counts[k] = (counts[k] || 0) + v;
    return { at, score: mean(latest.map((p) => p.score)), counts };
  });
}

/** One row per data source; with several accounts, which accounts can't read it. */
export function coverage(scans: AccountScan[]): Coverage[] {
  if (scans.length === 1) return scans[0].scan.snap.coverage || [];
  const by = new Map<string, Coverage>();
  for (const { account, scan } of scans) {
    for (const c of scan.snap.coverage || []) {
      let cur = by.get(c.label);
      if (!cur) by.set(c.label, (cur = { label: c.label, ok: true, permission: c.permission, notReadableIn: [], skippedChecks: [] }));
      if (!c.ok) {
        cur.ok = false;
        cur.notReadableIn!.push({ id: account.id, name: displayName(account) });
        cur.status ??= c.status;
        cur.message ??= c.message;
        cur.skippedChecks = [...new Set([...(cur.skippedChecks || []), ...(c.skippedChecks || [])])];
      }
    }
  }
  return [...by.values()];
}

const tag = <T extends object>(rows: T[] | undefined, a: Account) => (rows || []).map((r) => ({ ...r, account: displayName(a), accountId: a.id }));

export function zones(scans: AccountScan[]): ZoneRow[] | null {
  if (!scans.some((s) => s.scan.snap.zones)) return null;
  return scans.flatMap(({ account, scan }) => tag(scan.snap.zones, account));
}

export function value(scans: AccountScan[]): ValueView | null {
  const views = scans.filter((s) => s.scan.snap.value).map((s) => ({ account: s.account, v: s.scan.snap.value! }));
  if (!views.length) return null;
  if (views.length === 1)
    return { ...views[0].v, subscriptions: tag(views[0].v.subscriptions, views[0].account), zones: tag(views[0].v.zones, views[0].account) };
  const counts = { ...views[0].v.counts };
  for (const { v } of views.slice(1)) {
    for (const [k, n] of Object.entries(v.counts) as [keyof typeof counts, number | null][]) {
      counts[k] = (n == null ? counts[k] : (counts[k] || 0) + n) as never;
    }
  }
  return {
    subscriptions: views.flatMap(({ account, v }) => tag(v.subscriptions, account)),
    monthly: Math.round(views.reduce((s, x) => s + Number(x.v.monthly || 0), 0) * 100) / 100,
    zones: views.flatMap(({ account, v }) => tag(v.zones, account)),
    counts,
  };
}

export function activity(scans: AccountScan[]): ActivityView | null {
  const views = scans.filter((s) => s.scan.snap.activity).map((s) => ({ account: s.account, v: s.scan.snap.activity! }));
  if (!views.length) return null;
  const sum = (key: "byCategory" | "byActor") => {
    const out: Record<string, number> = {};
    for (const { v } of views) for (const [k, n] of Object.entries(v[key])) out[k] = (out[k] || 0) + n;
    return out;
  };
  return {
    available: views.some((x) => x.v.available),
    since: views.map((x) => x.v.since).sort()[0],
    total: views.reduce((s, x) => s + Number(x.v.total || 0), 0),
    byCategory: sum("byCategory"),
    byActor: sum("byActor"),
    events: views
      .flatMap(({ account, v }) => tag(v.events, account))
      .sort((a, b) => String(b.when).localeCompare(String(a.when)))
      .slice(0, 2000),
  };
}

export function checkStats(scans: AccountScan[]): Record<string, { evaluated: number; failed: number }> {
  const out: Record<string, { evaluated: number; failed: number }> = {};
  for (const { scan } of scans) {
    for (const [id, s] of Object.entries(scan.snap.checks || {})) {
      const cur = (out[id] ||= { evaluated: 0, failed: 0 });
      cur.evaluated += s.evaluated;
      cur.failed += s.failed;
    }
  }
  return out;
}

export function securityCenter(scans: AccountScan[]) {
  const sc = scans.map((s) => s.scan.snap.securityCenter).filter((x) => x != null);
  if (!sc.length) return { imported: 0, corroborated: 0, total: null };
  return {
    imported: sc.reduce((s, x) => s + (x.imported || 0), 0),
    corroborated: sc.reduce((s, x) => s + (x.corroborated || 0), 0),
    total: sc.some((x) => x.total != null) ? sc.reduce((s, x) => s + (x.total || 0), 0) : null,
  };
}
