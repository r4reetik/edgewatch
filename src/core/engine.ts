// Turns an inventory into evaluations, findings and scores. Pure: no I/O.

import { createHash } from "node:crypto";
import { CATEGORIES, CHECK_BY_ID } from "./catalog.ts";
import { MODULES } from "./checks/index.ts";
import { Evaluator } from "./checks/define.ts";
import { securityCenterFindings } from "./checks/securitycenter.ts";
import { SEVERITY_WEIGHT } from "../shared/severity.ts";
import type { CheckMeta, CheckModule } from "./checks/define.ts";
import type { CategoryTotals, EngineOptions, Inventory, Result, Severity } from "./types.ts";

export interface Evaluation {
  /** Every custom-check evaluation, passing and failing. */
  results: Result[];
  /** Failing custom evaluations plus Security Center insights, de-duplicated by fingerprint. */
  findings: Result[];
  categories: CategoryTotals;
  checkStats: Record<string, { evaluated: number; failed: number }>;
  securityCenter: { imported: number; corroborated: number; total: number | null };
}

export function evaluate(inv: Inventory, opts: EngineOptions): Evaluation {
  const ev = new Evaluator(opts);
  for (const m of MODULES as readonly CheckModule[]) ev.run(m, inv);
  const out = summarize(inv.accountId, ev.results, opts, CHECK_BY_ID, (failures) =>
    securityCenterFindings(inv, failures, opts.disabledChecks).map((f) => ({ ...f, severity: opts.severityOverrides[f.checkId] || f.severity })),
  );
  return { ...out, securityCenter: { ...out.securityCenter, total: inv.insights?.length ?? null } };
}

/**
 * The provider-neutral half of an evaluation: one result per resource, fingerprints,
 * category totals for the score, and per-check counts. `extra` adds findings that come
 * from the provider rather than from checks (Cloudflare's Security Center).
 */
export function summarize(
  accountId: string,
  raw: Result[],
  opts: EngineOptions | Pick<EngineOptions, "severityOverrides">,
  checkById: Record<string, Pick<CheckMeta<string>, "severity">>,
  extra: (failures: Result[]) => Result[] = () => [],
): Evaluation {
  // One evaluation per resource: two records reported under the same name would otherwise count twice in the
  // score while appearing once as a finding. A failure wins over a pass.
  const unique = new Map<string, Result>();
  for (const r of raw) {
    const fp = fingerprint(accountId, r);
    const prev = unique.get(fp);
    if (!prev || (prev.pass && !r.pass)) unique.set(fp, r);
  }
  const results = [...unique.values()];

  const failures = results.filter((r) => !r.pass);
  const sc = extra(failures);

  const byFp = new Map<string, Result>();
  for (const f of [...failures, ...sc]) {
    f.fingerprint = fingerprint(accountId, f);
    if (!byFp.has(f.fingerprint)) byFp.set(f.fingerprint, f);
  }

  const categories: CategoryTotals = Object.fromEntries(CATEGORIES.map((c) => [c, { total: 0, evaluated: 0 }]));
  const checkStats: Evaluation["checkStats"] = {};
  for (const r of results) {
    const def = checkById[r.checkId];
    const w = SEVERITY_WEIGHT[r.pass ? opts.severityOverrides[r.checkId] || def.severity : r.severity] || 0;
    categories[r.category].total += w;
    categories[r.category].evaluated++;
    const s = (checkStats[r.checkId] ||= { evaluated: 0, failed: 0 });
    s.evaluated++;
    if (!r.pass) s.failed++;
  }

  return {
    results,
    findings: [...byFp.values()],
    categories,
    checkStats,
    securityCenter: { imported: sc.length, corroborated: failures.filter((f) => f.corroborated).length, total: null },
  };
}

/** Stable identity of a finding across scans: account + check + zone + resource. */
export function fingerprint(accountId: string, f: Pick<Result, "checkId" | "zone" | "resource">): string {
  return createHash("sha256")
    .update(`${accountId}|${f.checkId}|${f.zone || ""}|${f.resource}`.toLowerCase())
    .digest("hex")
    .slice(0, 20);
}

export interface ScoredFinding {
  source: string;
  category: string;
  severity: Severity;
  settled: boolean;
}

/**
 * Each category scores the weighted share of its evaluations that pass; the
 * overall score is the plain average of categories, so a category with many
 * resources (DNS) can't drown out one with few (Monitoring). Security Center
 * only reports failures, so it is shown beside the score rather than inside it.
 */
export function computeScore(categories: CategoryTotals, findings: ScoredFinding[]) {
  const failWeight: Record<string, number> = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  for (const f of findings) {
    if (f.source !== "custom" || f.settled) continue;
    failWeight[f.category] = (failWeight[f.category] || 0) + (SEVERITY_WEIGHT[f.severity] || 0);
  }
  const byCategory: Record<string, number | null> = {};
  for (const c of CATEGORIES) {
    const t = categories[c]?.total || 0;
    byCategory[c] = t ? Math.round(1000 * Math.max(0, 1 - failWeight[c] / t)) / 10 : null;
  }
  const scored = Object.values(byCategory).filter((v): v is number => v != null);
  return {
    overall: scored.length ? Math.round((10 * scored.reduce((a, b) => a + b, 0)) / scored.length) / 10 : null,
    byCategory,
  };
}

export { countBySeverity as severityCounts } from "../shared/severity.ts";
