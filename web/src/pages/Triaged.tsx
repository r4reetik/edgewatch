// Everything triaged in the current view: where each finding stands now and how
// it got there. "By finding" draws each finding's state over time on one shared
// axis; "All changes" lists every triage change and scan outcome, newest first.

import { useMemo, useState } from "react";
import { Badge, Button, Empty, Input, Pagination, Select, Tabs } from "@cloudflare/kumo";
import { CaretRightIcon, ClipboardTextIcon } from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import { ago, clampPage, dateOnly, link, navigate, num, setParams, useLocation, type FindingEvent, type TriagedFinding, type TriagedResponse } from "../lib.ts";
import { ListCard, NoRows, Page, PageState, PlatformMark, Row, SeverityBadge, Stat, StatusBadge } from "../components/ui.tsx";
import { FindingDialog } from "../components/triage.tsx";
import { describeEvent, LANE_LABEL, LaneLegend, laneSegments, StatusLane, Timeline, type LaneState } from "../components/history.tsx";

const TITLE = "Triaged";
const DESCRIPTION = "Every finding you've triaged, where it stands now, and how it got there.";
const ALL = "all";
const DAY = 86_400_000;
const PER_PAGE = 25;
const FEED_PER_PAGE = 50;
const PERIODS: Record<string, string> = { "7": "Changed in 7 days", "30": "Changed in 30 days", "90": "Changed in 90 days", [ALL]: "Any time" };
const STATES: Record<string, string> = { [ALL]: "Any state", ...LANE_LABEL };
const VIEWS = { findings: "By finding", changes: "All changes" } as const;
/** The finding cell, current state, history lane and last change, from md up. */
const GRID = "md:grid md:grid-cols-[minmax(0,2fr)_9.5rem_minmax(12rem,2fr)_minmax(9rem,1fr)] md:items-center md:gap-4";

const stateOf = (f: TriagedFinding): LaneState => (f.present ? f.status : "gone");
const triageEvents = (f: TriagedFinding) => f.events.filter((e) => e.kind === "triage");
const lastChangeAt = (f: TriagedFinding) => triageEvents(f).at(-1)?.at ?? f.triage?.updatedAt ?? "";

export function TriagedPage() {
  const { multi } = useShell();
  const { data, error, loading, reload } = useScopedApi<TriagedResponse>("/api/triaged");
  // Filters live in the URL, so a filtered view can be shared.
  const { params } = useLocation();
  const view = (params.get("view") as keyof typeof VIEWS) || "findings";
  const state = params.get("state") || ALL,
    period = params.get("period") || ALL,
    account = params.get("account") || ALL,
    q = params.get("q") || "";
  const param = (k: string, def: string) => (v: string) => setParams({ [k]: v === def ? null : v });
  const [open, setOpen] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const filterKey = [view, state, period, account, q].join("|");
  const [paging, setPaging] = useState({ key: filterKey, page: 1 });
  const pageState = paging.key === filterKey ? paging.page : 1;
  const setPage = (p: number) => setPaging({ key: filterKey, page: p });

  // "Now" for the shared axis moves on each reload, not on every render.
  const now = useMemo(() => (data ? Date.now() : 0), [data]);
  const since = period === ALL ? null : now - Number(period) * DAY;
  const all = data?.findings ?? [];
  // Everything but the state filter, so the tiles count what the other filters show.
  const base = useMemo(
    () =>
      all.filter((f) => {
        if (since != null && Date.parse(lastChangeAt(f)) < since) return false;
        if (account !== ALL && f.accountId !== account) return false;
        if (q) {
          const hay = `${f.title} ${f.resource} ${f.zone ?? ""} ${f.checkId} ${f.account} ${f.triage?.owner ?? ""} ${f.triage?.note ?? ""}`.toLowerCase();
          if (!hay.includes(q.toLowerCase())) return false;
        }
        return true;
      }),
    [all, since, account, q],
  );
  const rows = useMemo(() => (state === ALL ? base : base.filter((f) => stateOf(f) === state)), [base, state]);
  const lanes = useMemo(() => new Map(rows.map((f) => [f.fingerprint, laneSegments(f, now)])), [rows, now]);
  const axisFrom = since ?? Math.min(now - DAY, ...[...lanes.values()].map((s) => s[0]?.from ?? now));
  const feed = useMemo(
    () =>
      rows
        .flatMap((f) => f.events.filter((e) => e.kind === "triage" || e.kind === "resolved" || e.kind === "reopened").map((e) => ({ f, e })))
        .filter(({ e }) => since == null || Date.parse(e.at) >= since)
        .sort((a, b) => b.e.at.localeCompare(a.e.at)),
    [rows, since],
  );
  const page = clampPage(pageState, view === "changes" ? feed.length : rows.length, view === "changes" ? FEED_PER_PAGE : PER_PAGE);

  if (error || !data) return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={!data && loading} empty={false} retry={reload} />;

  const count = (s: LaneState) => base.filter((f) => stateOf(f) === s).length;
  const accounts = [...new Map(all.map((f) => [f.accountId, f.account])).entries()].sort((a, b) => a[1].localeCompare(b[1]));
  const openable = rows.filter((f) => f.present);
  const openFinding = open ? openable.find((f) => f.fingerprint === open) : undefined;
  const index = openFinding ? openable.indexOf(openFinding) : -1;
  const go = (i: number) => (i >= 0 && i < openable.length ? () => setOpen(openable[i].fingerprint) : undefined);
  const onOpen = (f: TriagedFinding) => (f.present ? setOpen(f.fingerprint) : navigate(`/findings/${f.fingerprint}`));
  const pick = (s: LaneState) => () => param("state", ALL)(state === s ? ALL : s);

  if (!all.length) {
    return (
      <Page title={TITLE} description={DESCRIPTION}>
        <ListCard>
          <Empty
            className="py-12"
            icon={<ClipboardTextIcon size={40} className="text-kumo-subtle" />}
            title="Nothing triaged yet"
            description="Set a status, owner or due date on a finding and it shows up here, with its history."
            contents={
              <Button variant="secondary" onClick={() => navigate("/findings")}>
                Go to findings
              </Button>
            }
          />
        </ListCard>
      </Page>
    );
  }

  const toolbar = (
    <div className="flex w-full flex-wrap items-center gap-2">
      <Input
        className="w-full min-w-48 sm:w-auto sm:flex-1"
        aria-label="Search triaged findings"
        placeholder="Search findings, hosts, owners, notes"
        value={q}
        onChange={(e) => param("q", "")(e.target.value)}
      />
      <Select
        aria-label="Current state"
        className="min-w-36 flex-1 sm:w-44 sm:flex-none"
        value={state}
        onValueChange={(v) => param("state", ALL)(String(v))}
        items={STATES}
      />
      <Select
        aria-label="Changed"
        className="min-w-36 flex-1 sm:w-48 sm:flex-none"
        value={period}
        onValueChange={(v) => param("period", ALL)(String(v))}
        items={PERIODS}
      />
      {multi && accounts.length > 1 && (
        <Select
          aria-label="Account"
          className="min-w-36 flex-1 sm:w-44 sm:flex-none"
          value={account}
          onValueChange={(v) => param("account", ALL)(String(v))}
          items={{ [ALL]: "All accounts", ...Object.fromEntries(accounts) }}
        />
      )}
    </div>
  );

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <Row>
        <Stat label="Triaged" value={num(base.length)} note={period === ALL ? "Findings with any triage" : PERIODS[period]} />
        <Stat label="In progress" value={num(count("in_progress"))} note="Someone is working on them" onClick={pick("in_progress")} />
        <Stat label="Accepted or false positive" value={num(count("accepted") + count("false_positive"))} note="Out of the score" />
        <Stat label="No longer found" value={num(count("gone"))} note="A later scan stopped finding them" onClick={pick("gone")} />
      </Row>

      <div className="-mb-2 overflow-x-auto">
        <Tabs
          value={view}
          onValueChange={(v) => param("view", "findings")(String(v))}
          tabs={[
            { value: "findings", label: `${VIEWS.findings} ${num(rows.length)}` },
            { value: "changes", label: `${VIEWS.changes} ${num(feed.length)}` },
          ]}
        />
      </div>

      {view === "findings" ? (
        <ListCard toolbar={toolbar} footer={rows.length > PER_PAGE && <Pagination page={page} setPage={setPage} perPage={PER_PAGE} totalCount={rows.length} />}>
          {rows.length === 0 ? (
            <NoRows>No triaged findings match. Try another state or period.</NoRows>
          ) : (
            <>
              <div className={`hidden border-b border-kumo-line py-2.5 pr-4 pl-12 text-sm font-medium text-kumo-subtle ${GRID}`}>
                <span>Finding</span>
                <span>Now</span>
                <span className="flex justify-between text-xs font-normal">
                  <span>{dateOnly(new Date(axisFrom).toISOString())}</span>
                  <span>Today</span>
                </span>
                <span>Last change</span>
              </div>
              <ul className="divide-y divide-kumo-line">
                {rows.slice((page - 1) * PER_PAGE, page * PER_PAGE).map((f) => (
                  <TriagedRow
                    key={f.fingerprint}
                    f={f}
                    multi={multi}
                    lane={lanes.get(f.fingerprint) ?? []}
                    from={axisFrom}
                    to={now}
                    expanded={expanded.has(f.fingerprint)}
                    onToggle={() =>
                      setExpanded((s) => {
                        const n = new Set(s);
                        if (!n.delete(f.fingerprint)) n.add(f.fingerprint);
                        return n;
                      })
                    }
                    onOpen={onOpen}
                  />
                ))}
              </ul>
              <div className="border-t border-kumo-line px-4 py-3">
                <LaneLegend />
              </div>
            </>
          )}
        </ListCard>
      ) : (
        <ListCard
          toolbar={toolbar}
          footer={feed.length > FEED_PER_PAGE && <Pagination page={page} setPage={setPage} perPage={FEED_PER_PAGE} totalCount={feed.length} />}
        >
          {feed.length === 0 ? (
            <NoRows>No changes match. Try another state or period.</NoRows>
          ) : (
            <Feed items={feed.slice((page - 1) * FEED_PER_PAGE, page * FEED_PER_PAGE)} multi={multi} onOpen={onOpen} />
          )}
        </ListCard>
      )}

      {openFinding && (
        <FindingDialog
          finding={openFinding}
          onClose={() => setOpen(null)}
          nav={{ onPrev: go(index - 1), onNext: go(index + 1), position: `${index + 1} of ${openable.length}` }}
          onSaved={() => void reload()}
        />
      )}
    </Page>
  );
}

/** The finding title as a real link: a click opens the dialog (or the page once it's gone), a modifier click opens the page. */
function TitleLink({ f, onOpen }: { f: TriagedFinding; onOpen: (f: TriagedFinding) => void }) {
  const l = link(`/findings/${f.fingerprint}`);
  return (
    <a
      href={l.href}
      className="text-kumo-default hover:text-kumo-link focus-visible:rounded-sm focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        onOpen(f);
      }}
    >
      {f.title}
    </a>
  );
}

function NowBadge({ f }: { f: TriagedFinding }) {
  if (!f.present)
    return (
      <Badge variant="success" appearance="dot">
        No longer found
      </Badge>
    );
  return <StatusBadge status={f.status} overdue={f.overdue} />;
}

/** The status part of the last change if there is one ("Open → In progress"), else the whole change. */
function lastChangeText(e: FindingEvent | undefined): string {
  if (!e) return "Triaged before history was kept";
  const s = e.changes?.status;
  return s ? describeEvent({ ...e, changes: { status: s } }).replace(/^Status: /, "") : describeEvent(e);
}

function TriagedRow({
  f,
  multi,
  lane,
  from,
  to,
  expanded,
  onToggle,
  onOpen,
}: {
  f: TriagedFinding;
  multi: boolean;
  lane: ReturnType<typeof laneSegments>;
  from: number;
  to: number;
  expanded: boolean;
  onToggle: () => void;
  onOpen: (f: TriagedFinding) => void;
}) {
  const changes = triageEvents(f);
  const last = changes.at(-1);
  const at = last?.at ?? f.triage?.updatedAt ?? null;
  return (
    <li className="py-3 pr-4 pl-3">
      <div className="flex items-start gap-2">
        <button
          type="button"
          aria-expanded={expanded}
          aria-label={expanded ? "Hide history" : "Show history"}
          onClick={onToggle}
          className="mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-kumo-subtle hover:bg-kumo-tint focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
        >
          <CaretRightIcon className={`transition-transform ${expanded ? "rotate-90" : ""}`} />
        </button>
        <div className={`flex min-w-0 flex-1 flex-col gap-2 ${GRID}`}>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <SeverityBadge severity={f.severity} />
              <PlatformMark provider={f.provider} spans={f.spans} />
              <TitleLink f={f} onOpen={onOpen} />
            </div>
            <div className="mt-0.5 truncate text-xs text-kumo-subtle">
              {f.resource}
              {multi ? ` · ${f.account}` : ""}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 md:flex-col md:items-start">
            <NowBadge f={f} />
            {f.triage?.owner && <span className="truncate text-xs text-kumo-subtle">{f.triage.owner}</span>}
          </div>
          <StatusLane segments={lane} from={from} to={to} marks={changes.map((e) => Date.parse(e.at))} />
          <div className="min-w-0 text-sm">
            <div className="line-clamp-2 text-kumo-default">{lastChangeText(last)}</div>
            <div className="text-xs text-kumo-subtle">
              {ago(at)}
              {changes.length > 1 ? ` · ${changes.length} changes` : ""}
            </div>
          </div>
        </div>
      </div>
      {expanded && (
        <div className="mt-3 ml-9 rounded-lg bg-kumo-elevated p-4 ring ring-kumo-line">
          <Timeline events={f.events} />
          <div className="mt-4">
            <a {...link(`/findings/${f.fingerprint}`)} className="text-sm text-kumo-link">
              Open the finding page
            </a>
          </div>
        </div>
      )}
    </li>
  );
}

const KIND_DOT: Partial<Record<FindingEvent["kind"], string>> = { triage: "bg-kumo-brand", resolved: "bg-kumo-success", reopened: "bg-kumo-danger" };

/** Changes grouped by day, newest first. */
function Feed({ items, multi, onOpen }: { items: { f: TriagedFinding; e: FindingEvent }[]; multi: boolean; onOpen: (f: TriagedFinding) => void }) {
  const days = new Map<string, typeof items>();
  for (const it of items) {
    const d = dateOnly(it.e.at);
    if (!days.has(d)) days.set(d, []);
    days.get(d)!.push(it);
  }
  return (
    <div>
      {[...days.entries()].map(([day, list]) => (
        <section key={day}>
          <h3 className="sticky top-0 border-b border-kumo-line bg-kumo-base px-4 py-2 text-xs font-medium text-kumo-subtle">{day}</h3>
          <ol className="divide-y divide-kumo-line">
            {list.map(({ f, e }, i) => (
              <li key={i} className="flex gap-3 px-4 py-3 text-sm">
                <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${KIND_DOT[e.kind] ?? "bg-kumo-badge-neutral"}`} aria-hidden />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <SeverityBadge severity={f.severity} />
                    <TitleLink f={f} onOpen={onOpen} />
                  </div>
                  <div className="mt-1 text-kumo-default">{describeEvent(e)}</div>
                  <div className="mt-0.5 truncate text-xs text-kumo-subtle">
                    {new Date(e.at).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}
                    {e.by ? ` · ${e.by}` : e.kind !== "triage" ? " · scan" : ""}
                    {` · ${f.resource}`}
                    {multi ? ` · ${f.account}` : ""}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}
