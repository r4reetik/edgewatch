// The JSON contract between the server and the web app. Server handlers return
// these shapes (`satisfies`), and the web imports them as types. Keys are camelCase.

import type { Severity, SeverityCounts } from "./severity.ts";
import type { Triage, TriageStatus, SlaDays } from "./triage.ts";
import type { ScopeKind } from "./scope.ts";

export type Confidence = "confirmed" | "likely";
export type FindingSource = "custom" | "security_center";

/** One step of a finding's evidence, shown as a numbered list. */
export interface EvidenceStep {
  label: string;
  value: string;
}

export interface Evidence {
  /** How the finding was reached, step by step (correlated checks). */
  chain?: EvidenceStep[];
  /** Security Center insight classes that report the same problem. */
  securityCenter?: string[];
  [key: string]: unknown;
}

export interface Finding {
  fingerprint: string;
  accountId: string;
  /** Display name of the account. */
  account: string;
  entity: string | null;
  checkId: string;
  source: FindingSource;
  severity: Severity;
  category: string;
  zone: string | null;
  resource: string;
  title: string;
  detail: string;
  /** Where to fix it in the Cloudflare dashboard. */
  link: string | null;
  evidence: Evidence | null;
  firstSeen: string | null;
  why: string | null;
  fix: string | null;
  /** Cloudflare documentation for the setting. */
  docs: string | null;
  triage: Triage | null;
  /** "confirmed": verified by a probe. "likely": a heuristic or observed traffic. null: read from configuration. */
  confidence: Confidence | null;
  /** The finding was resolved once and came back. */
  reopened: boolean;
  /** Effective status: accepted risk past its expiry reads as open. */
  status: TriageStatus;
  /** Accepted risk or false positive: out of the score and the open counts. */
  settled: boolean;
  overdue: boolean;
  due: string | null;
}

/** A finding in a short list (Overview, notifications). */
export type FindingBrief = Pick<
  Finding,
  "fingerprint" | "checkId" | "title" | "resource" | "severity" | "zone" | "category" | "accountId" | "account" | "confidence"
>;

/** The same check failing in several places, for "Fix these first". */
export interface FindingGroup {
  checkId: string;
  title: string;
  severity: Severity;
  category: string;
  confidence: Confidence | null;
  count: number;
  accounts: string[];
  zones: string[];
  overdue: number;
  /** The single finding when count is 1, so the row can open it directly. */
  fingerprint: string | null;
}

export interface ScanMeta {
  id: number;
  startedAt: string;
  finishedAt: string;
  trigger: string;
  apiCalls: number;
  /** Accounts combined in this view. */
  accounts: number;
  /** The least recent of the combined scans. */
  oldestFinishedAt: string;
}

export interface Coverage {
  /** Data source key (see src/core/sources.ts). */
  key?: string;
  label: string;
  ok: boolean;
  status?: number;
  message?: string;
  /** Token permission that grants this source. */
  permission?: string;
  /** Checks that couldn't run because this source wasn't readable. */
  skippedChecks?: string[];
  /** With several accounts: which ones can't read it. */
  notReadableIn?: { id: string; name: string }[];
}

export interface AccountSummary {
  id: string;
  name: string;
  entity: string | null;
  score: number | null;
  categoryScores: Record<string, number | null>;
  counts: SeverityCounts;
  finishedAt: string | null;
}

export interface TrendPoint {
  at: string;
  score: number | null;
  counts: Partial<SeverityCounts>;
}

// ---- session and accounts

export type TokenKind = "user" | "account";

export interface SessionAccount {
  id: string;
  name: string | null;
  alias: string | null;
  display: string;
  entityId: number;
  scheduled: boolean;
  tokenHint: string | null;
  tokenKind: TokenKind | null;
  tokenMissing: boolean;
}

export interface SessionEntity {
  id: number;
  name: string;
  includeInAll: boolean;
}

export interface Session {
  version: string;
  authRequired: boolean;
  authenticated: boolean;
  configured: boolean;
  accounts?: SessionAccount[];
  entities?: SessionEntity[];
}

export interface EntityNotificationsView {
  minSeverity: Severity;
  slackConfigured: boolean;
  slackHint: string;
  webhookConfigured: boolean;
  webhookHint: string;
}

export interface EntityView extends SessionEntity {
  orgDomains: string[];
  position: number;
  notifications: EntityNotificationsView;
}

export interface AccountRow extends SessionAccount {
  busy: boolean;
  lastScan: { finishedAt: string; score: number | null; counts: Partial<SeverityCounts> } | null;
  lastFailed: { finishedAt: string; error: string } | null;
}

export interface AccountsResponse {
  entities: (EntityView & { accounts: AccountRow[] })[];
}

export interface PermissionProbe {
  source: string;
  permission: string;
  powers: string;
  ok: boolean;
  status?: number;
  message?: string;
}
export interface VisibleAccount {
  id: string;
  name: string;
  added: boolean;
  entityId: number | null;
}
export interface TokenInfo {
  valid: boolean;
  kind: TokenKind | null;
  message?: string;
  status?: string;
  expiresOn?: string | null;
}

export interface VerifyResponse {
  token: TokenInfo;
  accounts: VisibleAccount[];
  probes: Record<string, PermissionProbe[]>;
  /** Accounts whose permissions were probed (the rest are assumed alike). */
  probeLimit: number;
  templateUrl?: string;
}

export interface AddAccountsResponse {
  ok: true;
  added: string[];
  updated: string[];
  entityId: number;
}
export interface TemplateResponse {
  url: string;
  readAllUrl: string;
}

// ---- settings and checks

export interface Settings {
  schedule: { enabled: boolean; hourUtc: number; minuteUtc: number };
  retentionDays: number;
  /** Days a finding may stay open before it is flagged overdue (when no due date is set). */
  slaDays: SlaDays;
  /** Live checks that send requests outside Cloudflare's API. */
  probes: { takeover: boolean };
  /** Address people use to open Edgewatch, for links in notifications. */
  baseUrl: string;
}

export interface CheckRow {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  why: string;
  fix: string;
  docs: string | null;
  /** Data sources the check reads. */
  requires: string[];
  evaluated: number;
  failed: number;
  disabled: boolean;
  severityOverride: Severity | null;
}

export interface ChecksResponse {
  scan: ScanMeta | null;
  checks: CheckRow[];
}

// ---- dashboard

export interface Unscanned {
  id: string;
  name: string;
}

export interface TriageCounts {
  open: number;
  inProgress: number;
  accepted: number;
  falsePositive: number;
  /** Critical and high findings with no owner. */
  unowned: number;
  overdue: number;
  reopened: number;
}

export interface AttackPath extends FindingBrief {
  detail: string;
}

/** Before the first scan finishes, only `scan: null` and the accounts waiting for one. */
export type Overview = { scan: null; unscanned: Unscanned[] } | OverviewData;

export interface OverviewData {
  scan: ScanMeta;
  unscanned: Unscanned[];
  score: number | null;
  categoryScores: Record<string, number | null>;
  categoryCounts: Record<string, SeverityCounts>;
  accounts: AccountSummary[];
  counts: SeverityCounts;
  triage: TriageCounts;
  trend: TrendPoint[];
  previousAt: string | null;
  /** Open critical and high findings grouped by check, most urgent first. */
  fixFirst: FindingGroup[];
  attackPaths: AttackPath[];
  attackPathCount: number;
  newSince: FindingBrief[];
  newSinceCount: number;
  resolvedSince: FindingBrief[];
  coverage: Coverage[];
  securityCenter: { imported: number; corroborated: number; total: number | null };
  valueCounts: ValueCounts | undefined;
}

export interface FindingsResponse {
  scan: ScanMeta | null;
  findings: Finding[];
  /** Fingerprints that weren't in each account's previous scan. */
  newFingerprints: string[];
}

export interface FindingEvent {
  at: string;
  kind: "first_seen" | "seen" | "resolved" | "reopened" | "triage";
  by?: string | null;
  /** For triage events: what changed. */
  changes?: Partial<Record<"status" | "owner" | "note" | "dueDate" | "acceptUntil", { from: string | null; to: string | null }>>;
  scanId?: number;
}

/** A finding that has been triaged, as last reported, with its whole history. */
export interface TriagedFinding extends Finding {
  /** Still reported by its account's latest scan. */
  present: boolean;
  /** When a scan stopped finding it, while it's gone. */
  resolvedAt: string | null;
  /** First seen, scan outcomes and every triage change, oldest first. */
  events: FindingEvent[];
}

/** Everything triaged in the scope, most recently changed first. */
export interface TriagedResponse {
  scan: ScanMeta | null;
  findings: TriagedFinding[];
}

/** One finding wherever it lives, with its history. 404 when it never existed. */
export interface FindingDetail {
  finding: Finding | null;
  /** When the finding is no longer reported. */
  resolvedAt: string | null;
  /** Where the finding lives, so the web can switch scope. */
  accountId: string;
  account: string;
  entityId: number | null;
  /** Its last known shape, when it's resolved. */
  last: FindingBrief | null;
  events: FindingEvent[];
}

export interface ZoneRow {
  name: string;
  account?: string;
  accountId?: string;
  plan: string;
  planName: string;
  status: string;
  paused: boolean;
  proxiedZone: boolean;
  records: number;
  proxied: number;
  ssl: string | null;
  minTls: string | null;
  alwaysHttps: string | null;
  hsts: boolean | null;
  tls13: string | null;
  dnssec: string | null;
  wafManaged: boolean | "n/a" | null;
  owasp: boolean | "n/a" | null;
  rateLimitRules: number | null;
  botProtection: boolean | null;
  aiBots: string | null;
  securityLevel: string | null;
  pageShield: boolean | null;
  leakedCredentials: boolean | null;
  caa: boolean | null;
  traffic: { requests: number; cachedRequests: number; threats: number; bytes: number } | null;
  findings: SeverityCounts;
}

export interface ZonesResponse {
  scan: ScanMeta | null;
  zones: ZoneRow[] | null;
  coverage: Coverage[];
}

export interface Subscription {
  name: string;
  scope: string;
  zone: string | null;
  price: number;
  currency: string;
  frequency: string;
  state: string;
  account?: string;
  accountId?: string;
}

export interface ValueZone {
  name: string;
  account?: string;
  accountId?: string;
  plan: string;
  paid: boolean;
  price: number;
  requests: number | null;
  threats: number | null;
  cached: number | null;
  features: Record<string, boolean | null>;
}

export interface ValueCounts {
  zones: number;
  paidZones: number;
  members: number | null;
  accessApps: number | null;
  serviceTokens: number | null;
  tunnels: number | null;
  healthyTunnels: number;
  workers: number;
  r2Buckets: number;
  ztDevices: number | null;
  gatewayRules: number | null;
  notifications: number | null;
  requests30d: number;
  cachedRequests30d: number;
  threats30d: number;
}

export interface ValueView {
  subscriptions: Subscription[];
  monthly: number;
  zones: ValueZone[];
  counts: ValueCounts;
}
export interface ValueResponse {
  scan: ScanMeta | null;
  value: ValueView | null;
  coverage: Coverage[];
}

export interface ActivityEvent {
  when: string;
  account?: string;
  accountId?: string;
  actor: string;
  actorType: string | null;
  ip: string | null;
  type: string;
  info: string;
  ok: boolean;
  resource: string;
  zone: string | null;
  category: string;
  routine: boolean;
  destructive: boolean;
}

export interface ActivityView {
  available: boolean;
  since: string;
  total: number;
  byCategory: Record<string, number>;
  byActor: Record<string, number>;
  events: ActivityEvent[];
}
export interface ActivityResponse {
  scan: ScanMeta | null;
  activity: ActivityView | null;
  coverage: Coverage[];
}

export interface ScanRow {
  id: number;
  accountId: string;
  account: string;
  startedAt: string;
  finishedAt: string | null;
  trigger: string;
  status: "running" | "done" | "failed";
  score: number | null;
  counts: Partial<SeverityCounts> | null;
  apiCalls: number | null;
  error: string | null;
}

export interface ScansResponse {
  scans: ScanRow[];
  coverage: Coverage[];
}

export interface ScanStatus {
  running: boolean;
  accountId: string | null;
  scanId: number | null;
  trigger: string | null;
  startedAt: string | null;
  phase: string | null;
  done: number | null;
  total: number | null;
  queued: string[];
  /** The running or queued scans include an account in the current view. */
  inScope: boolean;
  lastScanAt: string | null;
  lastFailed: { id: number; finishedAt: string; error: string; account: string } | null;
}

export type Report = { scan: null } | ReportData;

export interface ReportData {
  scan: ScanMeta;
  scope: { kind: ScopeKind; label: string; entity: string | null };
  accountId: string | null;
  accounts: AccountSummary[];
  generatedAt: string;
  version: string;
  score: number | null;
  categoryScores: Record<string, number | null>;
  counts: SeverityCounts;
  findings: Finding[];
  coverage: Coverage[];
  zones: ZoneRow[] | null;
  valueCounts: ValueCounts | undefined;
  checks: Record<string, { evaluated: number; failed: number }>;
}

/** What a finished scan stores besides its findings. */
export interface ScanSnapshot {
  accountName: string | null;
  zones: ZoneRow[];
  value: ValueView;
  activity: ActivityView;
  coverage: Coverage[];
  checks: Record<string, { evaluated: number; failed: number }>;
  securityCenter: { imported: number; corroborated: number; total: number | null };
  probes: { takeover: { probed: number; unclaimed: number } | null };
}

/** Error bodies: `code` tells the web app what to do about it. */
export interface ApiError {
  error: string;
  code?: "setup" | "scope" | "auth";
}
