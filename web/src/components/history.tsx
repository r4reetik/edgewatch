// A finding's history: the event list on its page, and the status lane on the
// Triaged page, which draws how its state moved over time on a shared axis.

import { Tooltip } from "@cloudflare/kumo";
import { dateOnly, dateTime, STATUS_LABEL, useMode, type FindingEvent, type TriagedFinding, type TriageStatus } from "../lib.ts";

const FIELD_LABEL: Record<string, string> = { status: "Status", owner: "Owner", note: "Note", dueDate: "Due date", acceptUntil: "Accepted until" };

const showValue = (field: string, v: string | null) =>
  v == null ? "none" : field === "status" ? STATUS_LABEL[v as TriageStatus] || v : field === "note" ? `"${v.length > 60 ? `${v.slice(0, 60)}…` : v}"` : v;

/** One line for an event: "Status: Open → In progress; Owner: none → sam@…". */
export function describeEvent(e: FindingEvent): string {
  switch (e.kind) {
    case "first_seen":
      return "First found";
    case "seen":
      return "Still present";
    case "resolved":
      return "No longer found";
    case "reopened":
      return "Found again after being resolved";
    case "triage":
      return (
        Object.entries(e.changes || {})
          .map(([k, c]) => `${FIELD_LABEL[k] || k}: ${showValue(k, c.from)} → ${showValue(k, c.to)}`)
          .join("; ") || "Triage updated"
      );
  }
}

export function Timeline({ events }: { events: FindingEvent[] }) {
  if (!events.length) return <p className="text-sm text-kumo-subtle">No history yet.</p>;
  return (
    <ol className="flex flex-col gap-3 text-sm">
      {[...events].reverse().map((e, i) => (
        <li key={i} className="flex gap-3">
          <span
            className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${e.kind === "resolved" ? "bg-kumo-success" : e.kind === "reopened" ? "bg-kumo-danger" : e.kind === "triage" ? "bg-kumo-brand" : "bg-kumo-badge-neutral"}`}
            aria-hidden
          />
          <div className="min-w-0">
            <div className="text-kumo-default">{describeEvent(e)}</div>
            <div className="text-xs text-kumo-subtle">
              {dateTime(e.at)}
              {e.by ? ` · ${e.by}` : ""}
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

/** What the lane shows at a moment: the triage status, or that scans stopped finding it. */
export type LaneState = TriageStatus | "gone";
export const LANE_STATES: readonly LaneState[] = ["open", "in_progress", "accepted", "false_positive", "gone"];
export const LANE_LABEL: Record<LaneState, string> = { ...STATUS_LABEL, gone: "No longer found" };

/**
 * Lane colors, checked with the dataviz palette validator on every pair in each
 * mode. False positive is a hatched neutral, since it means "not a problem".
 * Every segment also has a tooltip, the legend names each state, and the row
 * shows the current status as text, so color is never the only signal.
 */
const LANE_COLOR = {
  light: { open: "#d64545", in_progress: "#2f6fdf", accepted: "#c99a06", gone: "#2a9d8f", fp: ["#a3a29c", "#d4d3cd"] },
  dark: { open: "#e5484d", in_progress: "#4c8dff", accepted: "#c08a00", gone: "#16a08f", fp: ["#7a7a76", "#4a4a47"] },
} as const;

function laneFill(state: LaneState, dark: boolean): string {
  const c = LANE_COLOR[dark ? "dark" : "light"];
  if (state === "false_positive") return `repeating-linear-gradient(135deg, ${c.fp[0]} 0 3px, ${c.fp[1]} 3px 6px)`;
  return c[state];
}

export interface Segment {
  state: LaneState;
  from: number;
  to: number;
}

const startOfDay = (d: string) => Date.parse(`${d}T00:00:00`);

/**
 * The finding's states from first seen until now. Status comes from triage
 * changes; scans that stop or start finding it switch it to and from "gone";
 * accepted risk turns back to open on its expiry date. Triage set before
 * Edgewatch kept history starts at its last update.
 */
export function laneSegments(f: TriagedFinding, now = Date.now()): Segment[] {
  type Point = { at: number; apply: (s: { status: TriageStatus; gone: boolean; until: string | null }) => void };
  const points: Point[] = [];
  let recorded = false;
  for (const e of f.events) {
    const at = Date.parse(e.at);
    if (e.kind === "resolved") points.push({ at, apply: (s) => void (s.gone = true) });
    if (e.kind === "reopened") points.push({ at, apply: (s) => void (s.gone = false) });
    const status = e.changes?.status?.to as TriageStatus | undefined;
    const until = e.changes?.acceptUntil;
    if (status || until) {
      recorded ||= !!status;
      points.push({
        at,
        apply: (s) => {
          if (status) s.status = status;
          if (until) s.until = until.to;
          if (s.status !== "accepted") s.until = null;
        },
      });
    }
  }
  if (!recorded && f.triage && f.triage.status !== "open" && f.triage.updatedAt) {
    const t = f.triage;
    points.push({ at: Date.parse(t.updatedAt!), apply: (s) => Object.assign(s, { status: t.status, until: t.acceptUntil }) });
  }
  points.sort((a, b) => a.at - b.at);

  const firstSeen = f.events.find((e) => e.kind === "first_seen")?.at ?? f.firstSeen ?? f.events[0]?.at;
  const start = Math.min(firstSeen ? Date.parse(firstSeen) : now, points[0]?.at ?? now);
  const s = { status: "open" as TriageStatus, gone: false, until: null as string | null };
  const out: Segment[] = [];
  const visible = (at: number): LaneState =>
    s.gone ? "gone" : s.status === "accepted" && s.until && at >= startOfDay(s.until) + 86_400_000 ? "open" : s.status;
  const push = (state: LaneState, at: number) => {
    const last = out[out.length - 1];
    if (last && last.state === state) return;
    if (last) last.to = at;
    out.push({ state, from: at, to: now });
  };
  push(visible(start), start);
  for (const p of points) {
    p.apply(s);
    push(visible(p.at), p.at);
    // An acceptance that runs out before the next change: show it lapsing on its date.
    if (s.status === "accepted" && s.until && !s.gone) {
      const lapse = startOfDay(s.until) + 86_400_000;
      const next = points.find((q) => q.at > p.at)?.at ?? now;
      if (lapse > p.at && lapse < next) push("open", lapse);
    }
  }
  return out.filter((x) => x.to > x.from || out.length === 1);
}

/** The lane for one finding, clipped to the shared axis [from, to]. */
export function StatusLane({ segments, from, to, marks }: { segments: Segment[]; from: number; to: number; marks?: number[] }) {
  const [mode] = useMode();
  const dark = mode === "dark";
  const span = Math.max(to - from, 1);
  const x = (t: number) => (Math.min(Math.max(t, from), to) - from) / span;
  const shown = segments.filter((s) => s.to > from && s.from < to);
  return (
    <div className="relative h-4 w-full">
      {/* Recessive track, so the empty time before a finding appeared still reads as the axis. */}
      <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-kumo-line" aria-hidden />
      {shown.map((s, i) => {
        const left = x(s.from),
          width = x(s.to) - left;
        return (
          <Tooltip
            key={i}
            content={`${LANE_LABEL[s.state]}: ${dateOnly(new Date(s.from).toISOString())} – ${s.to >= to ? "now" : dateOnly(new Date(s.to).toISOString())}`}
          >
            <span
              role="img"
              aria-label={`${LANE_LABEL[s.state]} from ${dateOnly(new Date(s.from).toISOString())}`}
              className="absolute top-1/2 h-2.5 -translate-y-1/2 rounded-[4px]"
              // A 2px surface gap between neighbours keeps adjacent states apart.
              style={{ left: `${left * 100}%`, width: `max(4px, calc(${width * 100}% - 2px))`, background: laneFill(s.state, dark) }}
            />
          </Tooltip>
        );
      })}
      {marks
        ?.filter((t) => t >= from && t <= to)
        .map((t, i) => (
          <span key={`m${i}`} aria-hidden className="absolute -bottom-0.5 h-1.5 w-px bg-kumo-contrast/60" style={{ left: `calc(${x(t) * 100}% - 0.5px)` }} />
        ))}
    </div>
  );
}

export function LaneLegend() {
  const [mode] = useMode();
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-kumo-subtle">
      {LANE_STATES.map((s) => (
        <span key={s} className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-4 rounded-[3px]" style={{ background: laneFill(s, mode === "dark") }} aria-hidden />
          {LANE_LABEL[s]}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5">
        <span className="h-2 w-px bg-kumo-contrast/60" aria-hidden />
        Triage change
      </span>
    </div>
  );
}
