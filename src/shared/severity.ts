export type Severity = "critical" | "high" | "medium" | "low" | "info";
/** Every severity, most severe first. */
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
/** Severities that count towards scores, SLAs and the dashboard (info is informational only). */
export const SCORED_SEVERITIES = ["critical", "high", "medium", "low"] as const satisfies readonly Severity[];
export type ScoredSeverity = (typeof SCORED_SEVERITIES)[number];

export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
export const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

export type SeverityCounts = Record<Severity, number>;
export const emptyCounts = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

export function countBySeverity(items: readonly { severity: Severity }[]): SeverityCounts {
  const out = emptyCounts();
  for (const i of items) out[i.severity]++;
  return out;
}

/** Findings that count: every scored severity. */
export const totalScored = (c: Partial<SeverityCounts> | null | undefined): number => SCORED_SEVERITIES.reduce((s, k) => s + (c?.[k] || 0), 0);

export const isSeverity = (v: unknown): v is Severity => typeof v === "string" && (SEVERITIES as readonly string[]).includes(v);
