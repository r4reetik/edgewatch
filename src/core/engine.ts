// Turns an inventory into evaluations, findings and scores. Pure: no I/O.

import { createHash } from "node:crypto";
import { CATEGORIES, CHECK_BY_ID } from "./catalog.ts";
import { MODULES } from "./checks/index.ts";
import { Evaluator } from "./checks/define.ts";
import { securityCenterFindings } from "./checks/securitycenter.ts";
import { SEVERITY_WEIGHT } from "../shared/severity.ts";
import type { CheckModule } from "./checks/define.ts";
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

  const failures = ev.results.filter((r) => !r.pass);
  const sc = securityCenterFindings(inv, failures, opts.disabledChecks).map((f) => ({ ...f, severity: opts.severityOverrides[f.checkId] || f.severity }));

  const byFp = new Map<string, Result>();
  for (const f of [...failures, ...sc]) {
    f.fingerprint = fingerprint(inv.accountId, f);
    if (!byFp.has(f.fingerprint)) byFp.set(f.fingerprint, f);
  }

  const categories: CategoryTotals = Object.fromEntries(CATEGORIES.map((c) => [c, { total: 0, evaluated: 0 }]));
  const checkStats: Evaluation["checkStats"] = {};
  for (const r of ev.results) {
    const def = CHECK_BY_ID[r.checkId];
    const w = SEVERITY_WEIGHT[r.pass ? opts.severityOverrides[r.checkId] || def.severity : r.severity] || 0;
    categories[r.category].total += w;
    categories[r.category].evaluated++;
    const s = (checkStats[r.checkId] ||= { evaluated: 0, failed: 0 });
    s.evaluated++;
    if (!r.pass) s.failed++;
  }

  return {
    results: ev.results,
    findings: [...byFp.values()],
    categories,
    checkStats,
    securityCenter: { imported: sc.length, corroborated: failures.filter((f) => f.corroborated).length, total: inv.insights?.length ?? null },
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
