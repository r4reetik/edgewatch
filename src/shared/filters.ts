// Finding filters as they appear in the Findings page URL. The same function
// filters the table in the browser and the export on the server.

import type { Finding } from "./api.ts";

/** Status tabs on the Findings page. */
export const STATUS_VIEWS = ["active", "overdue", "unowned", "new", "accepted", "false_positive", "all"] as const;
export type StatusView = (typeof STATUS_VIEWS)[number];
export const STATUS_VIEW_LABEL: Record<StatusView, string> = {
  active: "Open",
  overdue: "Overdue",
  unowned: "No owner",
  new: "New",
  accepted: "Accepted risk",
  false_positive: "False positive",
  all: "All",
};

export interface FindingFilters {
  status?: StatusView;
  /** One severity, or several separated by commas ("critical,high"). */
  severity?: string;
  category?: string;
  zone?: string;
  accountId?: string;
  checkId?: string;
  source?: Finding["source"];
  confidence?: "confirmed" | "likely" | "config";
  q?: string;
}

/** URL parameter names, so links and the export use the same spelling. */
export const FILTER_PARAMS = {
  status: "status",
  severity: "severity",
  category: "category",
  zone: "zone",
  accountId: "account",
  checkId: "check",
  source: "source",
  confidence: "confidence",
  q: "q",
} as const satisfies Record<keyof FindingFilters, string>;

export function filtersFromParams(get: (name: string) => string | null | undefined): FindingFilters {
  const out: FindingFilters = {};
  for (const [key, param] of Object.entries(FILTER_PARAMS) as [keyof FindingFilters, string][]) {
    const v = get(param);
    if (v) (out as Record<string, string>)[key] = v;
  }
  return out;
}

export function matchesStatus(f: Finding, view: StatusView, isNew?: (fp: string) => boolean): boolean {
  switch (view) {
    case "active":
      return !f.settled;
    case "overdue":
      return f.overdue;
    case "unowned":
      return !f.settled && !f.triage?.owner;
    case "new":
      return !!isNew?.(f.fingerprint);
    case "accepted":
      return f.status === "accepted";
    case "false_positive":
      return f.status === "false_positive";
    case "all":
      return true;
  }
}

export function filterFindings(findings: Finding[], f: FindingFilters, isNew?: (fp: string) => boolean): Finding[] {
  const words = (f.q || "").toLowerCase().split(/\s+/).filter(Boolean);
  return findings.filter(
    (x) =>
      matchesStatus(x, f.status || "active", isNew) &&
      (!f.severity || f.severity.split(",").includes(x.severity)) &&
      (!f.category || x.category === f.category) &&
      (!f.zone || (x.zone || "account") === f.zone) &&
      (!f.accountId || x.accountId === f.accountId) &&
      (!f.checkId || x.checkId === f.checkId) &&
      (!f.source || x.source === f.source) &&
      (!f.confidence || (f.confidence === "config" ? x.confidence === null : x.confidence === f.confidence)) &&
      (!words.length || matchesWords(x, words)),
  );
}

function matchesWords(x: Finding, words: string[]): boolean {
  const hay = `${x.title} ${x.resource} ${x.zone || ""} ${x.checkId} ${x.detail} ${x.account} ${x.triage?.owner || ""} ${x.triage?.note || ""}`.toLowerCase();
  return words.every((w) => hay.includes(w));
}
