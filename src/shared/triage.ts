// How a finding's triage turns into its effective status, due date and whether
// it still counts. Used by the store (server) and for optimistic updates (web).

import { DAY_MS, isoDate } from "./time.ts";
import type { ScoredSeverity, Severity } from "./severity.ts";

export type TriageStatus = "open" | "in_progress" | "accepted" | "false_positive";
export const TRIAGE_STATUSES: readonly TriageStatus[] = ["open", "in_progress", "accepted", "false_positive"];
export const STATUS_LABEL: Record<TriageStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  accepted: "Accepted risk",
  false_positive: "False positive",
};

export interface Triage {
  status: TriageStatus;
  owner: string | null;
  note: string | null;
  dueDate: string | null;
  /** Accepted risk expires on this date and the finding reads as open again. */
  acceptUntil: string | null;
  updatedAt?: string;
  updatedBy?: string | null;
}

export type SlaDays = Record<ScoredSeverity, number>;

/** Accepted risk past its expiry reads as open. */
export function effectiveStatus(t: Pick<Triage, "status" | "acceptUntil"> | null, today = isoDate()): TriageStatus {
  const status = t?.status || "open";
  return status === "accepted" && t?.acceptUntil && t.acceptUntil < today ? "open" : status;
}

/** Settled findings (accepted risk, false positive) leave the score and the open counts. */
export const isSettled = (status: TriageStatus): boolean => status === "accepted" || status === "false_positive";

/** The triage due date, or first seen plus the severity's SLA. */
export function dueDate(severity: Severity, firstSeen: string | null, t: Pick<Triage, "dueDate"> | null, sla: SlaDays): string | null {
  if (t?.dueDate) return t.dueDate;
  const days = severity in sla ? sla[severity as ScoredSeverity] : null;
  return days != null && firstSeen ? isoDate(Date.parse(firstSeen) + days * DAY_MS) : null;
}
