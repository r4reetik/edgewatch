// Scoped dashboard data (?scope=all | e:<id> | a:<id>) and scans.

import type { AppContext } from "../env.ts";
import type { Routes } from "../router.ts";
import { displayName, type Repo, type Scope } from "../../store/repo.ts";
import { CHECK_BY_ID } from "../../core/catalog.ts";
import { countBySeverity, emptyCounts, type SeverityCounts } from "../../shared/severity.ts";
import { badRequest, notFound } from "../errors.ts";
import { FINGERPRINT, param } from "../validate.ts";
import {
  activity,
  brief,
  checkStats,
  coverage,
  fixFirst,
  latestScans,
  scanMeta,
  scopeFindings,
  scores,
  securityCenter,
  trend,
  value,
  zones,
  type AccountScan,
} from "../scope.ts";
import type {
  ActivityResponse,
  AttackPath,
  Finding,
  FindingBrief,
  FindingDetail,
  FindingsResponse,
  Overview,
  Report,
  ScanRow,
  ScansResponse,
  ScanStatus,
  TriagedFinding,
  TriagedResponse,
  ValueResponse,
  ZonesResponse,
} from "../../shared/api.ts";

const NEW_SINCE_SHOWN = 15;
const ATTACK_PATHS_SHOWN = 8;

/** Correlated findings that describe a concrete way in, surfaced first on the Overview. */
const isAttackPath = (f: Finding) =>
  !!CHECK_BY_ID[f.checkId]?.attackPath && (f.severity === "critical" || f.severity === "high" || f.checkId.startsWith("CHG"));

/** Findings new since, and resolved since, each account's previous scan. */
function sinceLastScan(repo: Repo, scans: AccountScan[], findings: Finding[]) {
  const added: Finding[] = [],
    resolved: FindingBrief[] = [];
  let previousAt: string | null = null;
  for (const { account, scan } of scans) {
    const prev = repo.scans.previous(account.id, scan.id);
    if (!prev) continue;
    if (!previousAt || String(prev.finished_at) > previousAt) previousAt = prev.finished_at;
    const mine = findings.filter((f) => f.accountId === account.id);
    const before = repo.scans.fingerprints(prev.id);
    const beforeSet = new Set(before.map((r) => r.fingerprint));
    const now = new Set(mine.map((f) => f.fingerprint));
    added.push(...mine.filter((f) => !beforeSet.has(f.fingerprint)));
    resolved.push(
      ...before
        .filter((r) => !now.has(r.fingerprint))
        .map(
          (r): FindingBrief => ({
            fingerprint: r.fingerprint,
            checkId: r.check_id,
            title: r.title,
            resource: r.resource,
            severity: r.severity as FindingBrief["severity"],
            zone: r.zone,
            category: r.category,
            accountId: account.id,
            account: displayName(account),
            confidence: (r.confidence as FindingBrief["confidence"]) || null,
          }),
        ),
    );
  }
  return { added, resolved, previousAt };
}

export function dashboardRoutes(r: Routes, { repo, scanner, version }: AppContext) {
  const load = (scope: Scope) => {
    const scans = latestScans(repo, scope);
    return { scans, findings: scopeFindings(repo, scans, repo.settings.get()) };
  };

  r.post("/api/scan", (c) => {
    const scope = c.get("scope");
    if (!scope.accounts.length) throw badRequest("No accounts in this view.");
    const s = scanner.start(
      "manual",
      scope.accounts.map((a) => a.id),
    );
    return c.json({ queued: s.queued, alreadyRunning: s.alreadyRunning }, 202);
  });

  r.get("/api/scan/status", (c) => {
    const scope = c.get("scope");
    let lastScanAt: string | null = null;
    let lastFailed: ScanStatus["lastFailed"] = null;
    for (const a of scope.accounts) {
      const l = repo.scans.latestSummary(a.id);
      const f = repo.scans.lastFailed(a.id);
      if (l?.finished_at && (!lastScanAt || l.finished_at > lastScanAt)) lastScanAt = l.finished_at;
      if (f && (!l || f.id > l.id) && (!lastFailed || String(f.finished_at) > lastFailed.finishedAt)) {
        lastFailed = { id: f.id, finishedAt: f.finished_at!, error: f.error || "", account: displayName(a) };
      }
    }
    const inScope = new Set(scope.accounts.map((a) => a.id));
    const s = scanner.state;
    return c.json({
      ...s,
      inScope: !!(s.accountId && inScope.has(s.accountId)) || s.queued.some((id) => inScope.has(id)),
      lastScanAt,
      lastFailed,
    } satisfies ScanStatus);
  });

  r.get("/api/overview", (c) => {
    const scope = c.get("scope");
    const { scans, findings } = load(scope);
    const unscanned = scope.accounts.filter((a) => !scans.some((s) => s.account.id === a.id)).map((a) => ({ id: a.id, name: displayName(a) }));
    if (!scans.length) return c.json({ scan: null, unscanned } satisfies Overview);
    const score = scores(scans, findings);
    const open = findings.filter((f) => !f.settled);
    const since = sinceLastScan(repo, scans, findings);
    const categoryCounts: Record<string, SeverityCounts> = {};
    for (const f of open) (categoryCounts[f.category] ||= emptyCounts())[f.severity]++;
    const points = trend(
      repo,
      scans.map((s) => s.account),
    );
    // The last point reflects current triage, like the score above it.
    if (points.length) points[points.length - 1] = { ...points[points.length - 1], score: score.overall, counts: countBySeverity(open) };
    const paths = open.filter(isAttackPath);
    return c.json({
      scan: scanMeta(scans),
      unscanned,
      score: score.overall,
      categoryScores: score.byCategory,
      categoryCounts,
      accounts: score.accounts,
      counts: countBySeverity(open),
      triage: {
        open: findings.filter((f) => f.status === "open").length,
        inProgress: findings.filter((f) => f.status === "in_progress").length,
        accepted: findings.filter((f) => f.status === "accepted").length,
        falsePositive: findings.filter((f) => f.status === "false_positive").length,
        unowned: open.filter((f) => !f.triage?.owner && (f.severity === "critical" || f.severity === "high")).length,
        overdue: open.filter((f) => f.overdue).length,
        reopened: open.filter((f) => f.reopened).length,
      },
      trend: points,
      previousAt: since.previousAt,
      fixFirst: fixFirst(open),
      attackPaths: paths.slice(0, ATTACK_PATHS_SHOWN).map((f): AttackPath => ({ ...brief(f), detail: f.detail })),
      attackPathCount: paths.length,
      newSince: since.added.slice(0, NEW_SINCE_SHOWN).map(brief),
      newSinceCount: since.added.length,
      resolvedSince: since.resolved.slice(0, NEW_SINCE_SHOWN),
      coverage: coverage(scans),
      securityCenter: securityCenter(scans),
      valueCounts: value(scans)?.counts,
    } satisfies Overview);
  });

  r.get("/api/findings", (c) => {
    const { scans, findings } = load(c.get("scope"));
    const { added } = sinceLastScan(repo, scans, findings);
    return c.json({ scan: scanMeta(scans), findings, newFingerprints: added.map((f) => f.fingerprint) } satisfies FindingsResponse);
  });

  r.get("/api/triaged", (c) => {
    const scope = c.get("scope");
    const entities = new Map(repo.entities.list().map((e) => [e.id, e.name]));
    const accounts = new Map(scope.accounts.map((a) => [a.id, a]));
    const lastChange = (f: { events: { kind: string; at: string }[] }) => f.events.findLast((e) => e.kind === "triage")?.at ?? "";
    const findings = repo.findings
      .triaged([...accounts.keys()], repo.settings.get().slaDays)
      .map((f): TriagedFinding => {
        const account = accounts.get(f.accountId)!;
        return {
          ...f,
          account: displayName(account),
          entity: entities.get(account.entityId) ?? null,
          resolvedAt: f.present ? null : (f.events.findLast((e) => e.kind === "resolved")?.at ?? null),
        };
      })
      .sort((a, b) => (lastChange(b) || b.triage?.updatedAt || "").localeCompare(lastChange(a) || a.triage?.updatedAt || ""));
    return c.json({ scan: scanMeta(latestScans(repo, scope)), findings } satisfies TriagedResponse);
  });

  r.get("/api/zones", (c) => {
    const s = latestScans(repo, c.get("scope"));
    return c.json({ scan: scanMeta(s), zones: zones(s), coverage: coverage(s) } satisfies ZonesResponse);
  });
  r.get("/api/value", (c) => {
    const s = latestScans(repo, c.get("scope"));
    return c.json({ scan: scanMeta(s), value: value(s), coverage: coverage(s) } satisfies ValueResponse);
  });
  r.get("/api/activity", (c) => {
    const s = latestScans(repo, c.get("scope"));
    return c.json({ scan: scanMeta(s), activity: activity(s), coverage: coverage(s) } satisfies ActivityResponse);
  });

  r.get("/api/scans", (c) => {
    const scope = c.get("scope");
    const names = new Map(scope.accounts.map((a) => [a.id, displayName(a)]));
    return c.json({
      scans: repo.scans
        .list(
          scope.accounts.map((a) => a.id),
          200,
        )
        .map(
          (s): ScanRow => ({
            id: s.id,
            accountId: s.account_id,
            account: names.get(s.account_id) ?? s.account_id,
            startedAt: s.started_at,
            finishedAt: s.finished_at,
            trigger: s.trigger,
            status: s.status,
            score: s.score,
            counts: s.counts ? JSON.parse(s.counts) : null,
            apiCalls: s.api_calls,
            error: s.error,
          }),
        ),
      coverage: coverage(latestScans(repo, scope)),
    } satisfies ScansResponse);
  });

  r.get("/api/report", (c) => {
    const scope = c.get("scope");
    const { scans, findings } = load(scope);
    if (!scans.length) return c.json({ scan: null } satisfies Report);
    const score = scores(scans, findings);
    return c.json({
      scan: scanMeta(scans),
      scope: { kind: scope.kind, label: scope.label, entity: scope.entity?.name ?? null },
      accountId: scope.accounts.length === 1 ? scope.accounts[0].id : null,
      accounts: score.accounts,
      generatedAt: new Date().toISOString(),
      version,
      score: score.overall,
      categoryScores: score.byCategory,
      counts: countBySeverity(findings.filter((f) => !f.settled)),
      findings,
      coverage: coverage(scans),
      zones: zones(scans),
      valueCounts: value(scans)?.counts,
      checks: checkStats(scans),
    } satisfies Report);
  });
}

/** A finding by fingerprint, in whichever account it lives: permalinks work from any scope. */
export function findingRoutes(r: Routes, { repo }: AppContext) {
  r.get("/api/finding/:fp", (c) => {
    const fp = param(c, "fp");
    if (!FINGERPRINT.test(fp)) throw notFound("Unknown finding");
    const where = repo.findings.locate(fp);
    const account = where && repo.accounts.get(where.accountId);
    if (!where || !account) throw notFound("This finding no longer exists.");
    const entity = repo.entities.get(account.entityId);
    const current =
      where.scanId === where.latestScanId ? (repo.findings.forScan(where.scanId, repo.settings.get().slaDays).find((f) => f.fingerprint === fp) ?? null) : null;
    const events = repo.findings.timeline(fp, account.id);
    return c.json({
      finding: current ? { ...current, account: displayName(account), entity: entity?.name ?? null } : null,
      resolvedAt: current ? null : (events.findLast((e) => e.kind === "resolved")?.at ?? null),
      accountId: account.id,
      account: displayName(account),
      entityId: entity?.id ?? null,
      last: current ? null : repo.findings.lastBrief(fp, where.scanId, displayName(account)),
      events,
    } satisfies FindingDetail);
  });
}
