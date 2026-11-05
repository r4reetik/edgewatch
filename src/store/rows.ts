// Row shapes as SQLite returns them (snake_case columns). Repositories convert
// them to the camelCase domain types in ../shared/api.ts.

export interface ScanRecord {
  id: number;
  account_id: string;
  started_at: string;
  finished_at: string | null;
  trigger: string;
  status: "running" | "done" | "failed";
  score: number | null;
  /** JSON: open findings by severity at scan time. */
  counts: string | null;
  /** JSON: per-category weight totals, for re-scoring with current triage. */
  category_totals: string | null;
  /** JSON: ScanSnapshot. */
  snapshot: string | null;
  api_calls: number | null;
  error: string | null;
}

/** A scan without its (large) snapshot and totals. */
export type ScanSummaryRecord = Omit<ScanRecord, "snapshot" | "category_totals">;

export interface FindingRecord {
  scan_id: number;
  fingerprint: string;
  check_id: string;
  source: string;
  severity: string;
  category: string;
  zone: string | null;
  resource: string;
  title: string;
  detail: string | null;
  evidence: string | null;
  link: string | null;
  confidence: string | null;
}

export interface TriageRecord {
  fingerprint: string;
  status: string;
  owner: string | null;
  note: string | null;
  due_date: string | null;
  accept_until: string | null;
  updated_at: string;
  updated_by: string | null;
}

export interface EntityRecord {
  id: number;
  name: string;
  include_in_all: number;
  org_domains: string;
  notifications: string;
  position: number;
  created_at: string;
}

export interface AccountRecord {
  id: string;
  name: string | null;
  alias: string | null;
  entity_id: number;
  token_id: string;
  token_kind: string | null;
  scheduled: number;
  position: number;
  added_at: string;
}
