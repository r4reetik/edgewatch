// Every finding in the current scope. Filters live in the URL (shared with the
// export), status tabs show counts, rows group by check, zone or account, and
// the flat list sorts by severity, age or due date. Selection survives filter
// changes, so a search can narrow what to triage without losing the rest.

import { Fragment, useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Button, Checkbox, DropdownMenu, Input, Pagination, Select, Table, Tabs, Empty, useKumoToastManager } from "@cloudflare/kumo";
import {
  CaretDownIcon,
  CaretRightIcon,
  DownloadSimpleIcon,
  FunnelSimpleIcon,
  ShieldCheckIcon,
  SortAscendingIcon,
  SortDescendingIcon,
  XIcon,
} from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import {
  clampPage,
  dateOnly,
  filterFindings,
  filtersFromParams,
  link,
  num,
  openFor,
  plural,
  PROVIDER_INFO,
  setParams,
  useLocation,
  withScope,
  FILTER_PARAMS,
  SEVERITY_WEIGHT,
  STATUS_VIEWS,
  STATUS_VIEW_LABEL,
  type Finding,
  type FindingFilters,
  type FindingsResponse,
  type Severity,
  type StatusView,
  type Triage,
  zoneWord,
} from "../lib.ts";
import { AccountName, ConfidenceBadge, ListCard, Page, PageState, PlatformMark, ReopenedBadge, SeverityBadge, StatusBadge, Tag } from "../components/ui.tsx";
import { BulkTriageDialog, FindingDialog } from "../components/triage.tsx";
import { isSettled, effectiveStatus } from "../../../src/shared/triage.ts";
import { groupBy } from "../../../src/shared/collections.ts";

const PER_PAGE = 50;
const ALL = "all";
const TITLE = "Findings";
const DESCRIPTION =
  "Every open problem from Edgewatch's checks, and from the insights a platform reports itself. A finding is one resource failing one check. Assign owners, set due dates, or accept a risk until a date.";

type GroupBy = "check" | "zone" | "account" | "platform" | "none";
type SortKey = "severity" | "age" | "due";
/** The groupings on offer. Grouping by platform only makes sense when the view has more than one. */
const groupLabels = (zone: string, mixed: boolean): Partial<Record<GroupBy, string>> => ({
  check: "Group by check",
  zone: `Group by ${zone.toLowerCase()}`,
  account: "Group by account",
  ...(mixed ? { platform: "Group by platform" } : {}),
  none: "No grouping",
});

const SEVERITY_FILTERS: Record<string, string> = {
  [ALL]: "All severities",
  "critical,high": "Critical and high",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};
const SOURCE_LABEL: Record<string, string> = { custom: "Edgewatch checks", security_center: "Security Center" };
const CONFIDENCE_LABEL: Record<string, string> = { confirmed: "Confirmed", likely: "Likely", config: "From configuration" };
const SPANS_LABEL: Record<string, string> = { "1": "Compares platforms" };

const sorters: Record<SortKey, (a: Finding, b: Finding) => number> = {
  severity: (a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] || String(a.firstSeen).localeCompare(String(b.firstSeen)),
  age: (a, b) => String(a.firstSeen).localeCompare(String(b.firstSeen)),
  due: (a, b) => (a.due && !a.settled ? a.due : "9999").localeCompare(b.due && !b.settled ? b.due : "9999"),
};

export function FindingsPage() {
  const { multi, view } = useShell();
  const zoneLabel = zoneWord(view.accounts.map((a) => a.provider));
  const mixed = new Set(view.accounts.map((a) => a.provider)).size > 1;
  const { data, error, loading, reload, setData } = useScopedApi<FindingsResponse>("/api/findings");
  const { params } = useLocation();
  const toasts = useKumoToastManager();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [open, setOpen] = useState<string | null>(null);
  const [bulk, setBulk] = useState(false);
  // A selection belongs to the view it was made in.
  // biome-ignore lint/correctness/useExhaustiveDependencies: clears on every change of view
  useEffect(() => setSelected(new Set()), [view.key]);
  const [pageState, setPage] = useState(1);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const query = params.toString();
  const filters = useMemo<FindingFilters>(() => {
    const p = new URLSearchParams(query);
    // Old links used ?new=1.
    return { status: p.get("new") === "1" ? "new" : "active", ...filtersFromParams((k) => p.get(k)) };
  }, [query]);
  const groupBy = (params.get("group") as GroupBy) || "check";
  const sort = (params.get("sort") as SortKey) || "severity";
  const desc = params.get("dir") === "desc";

  const findings = useMemo(() => data?.findings ?? [], [data]);
  const newSet = useMemo(() => new Set(data?.newFingerprints ?? []), [data]);
  const isNew = useCallback((fp: string) => newSet.has(fp), [newSet]);
  // Counts per status tab, with every other filter applied.
  const tabCounts = useMemo(
    () => Object.fromEntries(STATUS_VIEWS.map((s) => [s, filterFindings(findings, { ...filters, status: s }, isNew).length])) as Record<StatusView, number>,
    [findings, filters, isNew],
  );
  const rows = useMemo(() => {
    const out = filterFindings(findings, filters, isNew).sort(sorters[sort]);
    return desc ? out.reverse() : out;
  }, [findings, filters, sort, desc, isNew]);

  // A link to one finding (?finding=) opens its dialog.
  const deepLink = params.get("finding");
  useEffect(() => {
    if (deepLink) setOpen(deepLink);
  }, [deepLink]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: any change to the URL's filters goes back to page 1
  useEffect(() => {
    setPage(1);
  }, [query]);

  if (error || !data?.scan)
    return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={!data && loading} empty={!!data && !data.scan} retry={reload} />;

  const exportUrl = (fmt: "csv" | "json", fps?: string[]) => {
    const q = new URLSearchParams();
    if (fps) for (const fp of fps) q.append("fp", fp);
    else
      for (const [k, p] of Object.entries(FILTER_PARAMS)) {
        const v = filters[k as keyof FindingFilters];
        if (v) q.set(p, String(v));
      }
    return withScope(`/api/export/findings.${fmt}?${q}`, view.key);
  };
  /** Downloads an export; an error shows as a toast instead of replacing the page with the server's answer. */
  const download = async (url: string) => {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(((await res.json().catch(() => null)) as { error?: string } | null)?.error || `HTTP ${res.status}`);
      const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") || "")?.[1] || "findings";
      const a = document.createElement("a");
      a.href = URL.createObjectURL(await res.blob());
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) {
      toasts.add({ title: "Couldn't export", description: (e as Error).message, variant: "error" });
    }
  };

  const applyTriage = (fps: string[], t: Triage) => {
    const set = new Set(fps);
    setData(
      (d) =>
        d && {
          ...d,
          findings: d.findings.map((x) => {
            if (!set.has(x.fingerprint)) return x;
            const status = effectiveStatus(t);
            return { ...x, triage: t, status, settled: isSettled(status) };
          }),
        },
    );
  };
  const toggle = (fps: string[], on: boolean) =>
    setSelected((s) => {
      const n = new Set(s);
      for (const fp of fps) {
        if (on) n.add(fp);
        else n.delete(fp);
      }
      return n;
    });
  const hiddenSelected = [...selected].filter((fp) => !rows.some((r) => r.fingerprint === fp)).length;
  const selectedFindings = findings.filter((f) => selected.has(f.fingerprint));

  const categories = [...new Set(findings.map((x) => x.category))].sort();
  const zones = [...new Set(findings.map((x) => x.zone || "account"))].sort();
  // With several platforms in view an account's name alone doesn't say what it is.
  const accounts = [...new Map(findings.map((x) => [x.accountId, mixed ? `${x.account} · ${PROVIDER_INFO[x.provider].label}` : x.account])).entries()].sort(
    (a, b) => a[1].localeCompare(b[1]),
  );
  const anySpans = findings.some((x) => x.spans.length > 0);
  const anyInsights = findings.some((x) => x.source === "security_center");
  const setFilter = (key: keyof FindingFilters, v: string | null) =>
    setParams({ [FILTER_PARAMS[key]]: v === ALL ? null : v, ...(key === "status" ? { new: null } : {}) });

  // Filters behind "Filters" show as removable chips, each named after what it filters.
  const chips: { label: string; clear: () => void }[] = [
    filters.category && { label: `Category: ${filters.category}`, clear: () => setFilter("category", null) },
    filters.confidence && { label: `Confidence: ${CONFIDENCE_LABEL[filters.confidence]}`, clear: () => setFilter("confidence", null) },
    filters.source && { label: `Reported by: ${SOURCE_LABEL[filters.source]}`, clear: () => setFilter("source", null) },
    filters.spans && { label: SPANS_LABEL[filters.spans], clear: () => setFilter("spans", null) },
    filters.checkId && { label: `Check: ${filters.checkId}`, clear: () => setFilter("checkId", null) },
    filters.zone && { label: `${zoneLabel}: ${filters.zone === "account" ? "Account-wide" : filters.zone}`, clear: () => setFilter("zone", null) },
  ].filter((c): c is { label: string; clear: () => void } => !!c);
  const anyFilter = !!(filters.q || filters.severity || (multi && filters.accountId) || chips.length);

  const actions = (
    <DropdownMenu>
      <DropdownMenu.Trigger
        render={
          <Button variant="secondary" icon={<DownloadSimpleIcon />}>
            Export
          </Button>
        }
      />
      <DropdownMenu.Content>
        {/* A menu label only works inside a group: outside one, opening the menu throws. */}
        <DropdownMenu.Group>
          <DropdownMenu.Label>What's shown ({num(rows.length)})</DropdownMenu.Label>
          <DropdownMenu.Item
            onClick={() => {
              void download(exportUrl("csv"));
            }}
          >
            CSV (spreadsheets)
          </DropdownMenu.Item>
          <DropdownMenu.Item
            onClick={() => {
              void download(exportUrl("json"));
            }}
          >
            JSON (automation)
          </DropdownMenu.Item>
        </DropdownMenu.Group>
      </DropdownMenu.Content>
    </DropdownMenu>
  );

  const toolbar =
    selected.size > 0 ? (
      <>
        <span className="px-1 text-sm font-medium text-kumo-default">
          {plural(selected.size, "finding")} selected{hiddenSelected ? ` (${num(hiddenSelected)} hidden by filters)` : ""}
        </span>
        <Button variant="primary" onClick={() => setBulk(true)}>
          Triage selected
        </Button>
        <DropdownMenu>
          <DropdownMenu.Trigger
            render={
              <Button variant="secondary" icon={<DownloadSimpleIcon />}>
                Export selected
              </Button>
            }
          />
          <DropdownMenu.Content>
            <DropdownMenu.Item
              onClick={() => {
                void download(exportUrl("csv", [...selected]));
              }}
            >
              CSV
            </DropdownMenu.Item>
            <DropdownMenu.Item
              onClick={() => {
                void download(exportUrl("json", [...selected]));
              }}
            >
              JSON
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu>
        <Button variant="ghost" onClick={() => setSelected(new Set())}>
          Clear selection
        </Button>
      </>
    ) : (
      <div className="flex w-full flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Input
            className="w-full min-w-48 sm:w-auto sm:flex-1"
            aria-label="Search findings"
            placeholder="Search findings, hosts, owners, notes"
            value={filters.q || ""}
            onChange={(e) => setFilter("q", e.target.value || null)}
          />
          <Select
            aria-label="Severity"
            className="min-w-36 flex-1 sm:w-40 sm:flex-none"
            value={filters.severity || ALL}
            onValueChange={(v) => setFilter("severity", String(v))}
            items={SEVERITY_FILTERS}
          />
          {multi && (
            <Select
              aria-label="Account"
              className="min-w-36 flex-1 sm:w-44 sm:flex-none"
              value={filters.accountId || ALL}
              onValueChange={(v) => setFilter("accountId", String(v))}
              items={{ [ALL]: "All accounts", ...Object.fromEntries(accounts) }}
            />
          )}
          <DropdownMenu>
            <DropdownMenu.Trigger
              render={
                <Button variant="secondary" icon={<FunnelSimpleIcon />}>
                  Filters{chips.length ? ` (${chips.length})` : ""}
                </Button>
              }
            />
            <DropdownMenu.Content className="max-h-[60vh] overflow-y-auto">
              {/* What the finding is about, then where it is. Severity, account and the platform switch sit outside this menu. */}
              <DropdownMenu.Group>
                <DropdownMenu.Label>What</DropdownMenu.Label>
                <FilterMenu
                  label="Category"
                  value={filters.category}
                  options={Object.fromEntries(categories.map((c) => [c, c]))}
                  onPick={(v) => setFilter("category", v)}
                />
                <FilterMenu label="Confidence" value={filters.confidence} options={CONFIDENCE_LABEL} onPick={(v) => setFilter("confidence", v)} />
                {anyInsights && <FilterMenu label="Reported by" value={filters.source} options={SOURCE_LABEL} onPick={(v) => setFilter("source", v)} />}
                {anySpans && <FilterMenu label="Correlation" value={filters.spans} options={SPANS_LABEL} onPick={(v) => setFilter("spans", v)} />}
              </DropdownMenu.Group>
              <DropdownMenu.Separator />
              <DropdownMenu.Group>
                <DropdownMenu.Label>Where</DropdownMenu.Label>
                <FilterMenu
                  label={zoneLabel}
                  value={filters.zone}
                  options={Object.fromEntries(zones.map((z) => [z, z === "account" ? "Account-wide" : z]))}
                  onPick={(v) => setFilter("zone", v)}
                />
              </DropdownMenu.Group>
            </DropdownMenu.Content>
          </DropdownMenu>
          <Select
            aria-label="Grouping"
            className="min-w-36 flex-1 sm:w-44 sm:flex-none"
            value={groupBy}
            onValueChange={(v) => setParams({ group: v === "check" ? null : String(v) })}
            items={groupLabels(zoneLabel, mixed)}
          />
        </div>
        {(chips.length > 0 || anyFilter) && (
          <div className="flex flex-wrap items-center gap-1.5">
            {chips.map((c) => (
              <button
                key={c.label}
                type="button"
                onClick={c.clear}
                className="inline-flex items-center gap-1 rounded-full bg-kumo-recessed px-2.5 py-0.5 text-xs text-kumo-default hover:bg-kumo-tint focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
                aria-label={`Remove filter ${c.label}`}
              >
                {c.label} <XIcon size={12} />
              </button>
            ))}
            {anyFilter && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() =>
                  setParams({ q: null, severity: null, category: null, zone: null, account: null, source: null, confidence: null, spans: null, check: null })
                }
              >
                Clear filters
              </Button>
            )}
          </div>
        )}
      </div>
    );

  const pages = Math.ceil(rows.length / PER_PAGE);
  const page = clampPage(pageState, rows.length, PER_PAGE);
  const flat = groupBy === "none";
  const footer = (
    <>
      <span>
        {num(rows.length)} of {num(findings.length)} findings
      </span>
      {flat && pages > 1 && <Pagination page={page} setPage={setPage} perPage={PER_PAGE} totalCount={rows.length} />}
    </>
  );

  // The dialog walks the list in the order shown.
  const index = open ? rows.findIndex((r) => r.fingerprint === open) : -1;
  const openFinding = open ? rows[index] || findings.find((f) => f.fingerprint === open) || null : null;
  const go = (i: number) => (i >= 0 && i < rows.length ? () => setOpen(rows[i].fingerprint) : undefined);
  const close = () => {
    setOpen(null);
    if (deepLink) setParams({ finding: null });
  };
  const tableProps = { selected, toggle, onOpen: (f: Finding) => setOpen(f.fingerprint), multi, sort, desc };

  return (
    <Page title={TITLE} description={DESCRIPTION} actions={actions}>
      <div className="-mb-2 overflow-x-auto">
        <Tabs
          value={filters.status || "active"}
          onValueChange={(v) => setFilter("status", v === "active" ? null : String(v))}
          tabs={STATUS_VIEWS.filter((s) => s !== "new" || newSet.size > 0).map((s) => ({ value: s, label: `${STATUS_VIEW_LABEL[s]} ${num(tabCounts[s])}` }))}
        />
      </div>
      <ListCard toolbar={toolbar} footer={footer}>
        {rows.length === 0 ? (
          <Empty
            className="py-12"
            icon={<ShieldCheckIcon size={40} className="text-kumo-subtle" />}
            title={findings.length ? "No findings match" : "No findings"}
            description={findings.length ? "Try another tab, or clear a filter." : "Every check passed in the latest scan."}
          />
        ) : flat ? (
          <FindingsTable rows={rows.slice((page - 1) * PER_PAGE, page * PER_PAGE)} {...tableProps} />
        ) : (
          <GroupedTable rows={rows} groupBy={groupBy} expanded={expanded} setExpanded={setExpanded} {...tableProps} />
        )}
      </ListCard>

      {openFinding && (
        <FindingDialog
          finding={openFinding}
          onClose={close}
          nav={index >= 0 ? { onPrev: go(index - 1), onNext: go(index + 1), position: `${index + 1} of ${rows.length}` } : undefined}
          onSaved={(t) => applyTriage([openFinding.fingerprint], t)}
        />
      )}
      {bulk && (
        <BulkTriageDialog
          findings={selectedFindings}
          onClose={() => setBulk(false)}
          onSaved={() => {
            setBulk(false);
            setSelected(new Set());
            void reload();
          }}
        />
      )}
    </Page>
  );
}

function FilterMenu({ label, value, options, onPick }: { label: string; value?: string; options: Record<string, string>; onPick: (v: string | null) => void }) {
  return (
    <DropdownMenu.Sub>
      <DropdownMenu.SubTrigger>
        {label}
        {value ? `: ${options[value] || value}` : ""}
      </DropdownMenu.SubTrigger>
      <DropdownMenu.SubContent className="max-h-[60vh] overflow-y-auto">
        <DropdownMenu.Item onClick={() => onPick(null)}>Any</DropdownMenu.Item>
        <DropdownMenu.Separator />
        {Object.entries(options).map(([k, v]) => (
          <DropdownMenu.Item key={k} onClick={() => onPick(k)}>
            {v}
          </DropdownMenu.Item>
        ))}
      </DropdownMenu.SubContent>
    </DropdownMenu.Sub>
  );
}

interface TableProps {
  rows: Finding[];
  selected: Set<string>;
  toggle: (fps: string[], on: boolean) => void;
  onOpen: (f: Finding) => void;
  /** Several accounts are in view: show which one each finding belongs to. */
  multi: boolean;
  sort: SortKey;
  desc: boolean;
}

/** The finding title as a real link: a click opens the dialog, a modifier click opens the page. */
function TitleLink({ f, onOpen, wrap }: { f: Finding; onOpen: (f: Finding) => void; wrap?: boolean }) {
  const l = link(`/findings/${f.fingerprint}`);
  return (
    <a
      href={l.href}
      className={`${wrap ? "" : "truncate "}text-kumo-default hover:text-kumo-link focus-visible:rounded-sm focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none`}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        e.stopPropagation();
        onOpen(f);
      }}
    >
      {f.title}
    </a>
  );
}

function SortHead({ k, label, sort, desc, className }: { k: SortKey; label: string; sort: SortKey; desc: boolean; className?: string }) {
  const active = sort === k;
  return (
    <Table.Head className={className} aria-sort={active ? (desc ? "descending" : "ascending") : "none"}>
      <button
        type="button"
        className="inline-flex items-center gap-1 whitespace-nowrap hover:text-kumo-default focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
        onClick={() => setParams({ sort: k === "severity" && (!active || desc) ? null : k, dir: active && !desc ? "desc" : null })}
      >
        {label}
        {active ? desc ? <SortDescendingIcon /> : <SortAscendingIcon /> : null}
      </button>
    </Table.Head>
  );
}

function FindingsTable({ rows, selected, toggle, onOpen, nested, multi, sort, desc }: TableProps & { nested?: boolean }) {
  const { view } = useShell();
  const providers = view.accounts.map((a) => a.provider);
  const mixed = new Set(providers).size > 1;
  const all = rows.every((r) => selected.has(r.fingerprint));
  const some = rows.some((r) => selected.has(r.fingerprint));
  return (
    <>
      {/* Phones get stacked cards; the table needs more width than they have. */}
      <ul className="divide-y divide-kumo-hairline sm:hidden">
        {rows.map((x) => (
          <li key={x.fingerprint} className="flex gap-3 px-4 py-3">
            <Checkbox
              className="mt-1"
              aria-label={`Select ${x.title}`}
              checked={selected.has(x.fingerprint)}
              onCheckedChange={(v: boolean) => toggle([x.fingerprint], v)}
            />
            <div className="min-w-0 flex-1">
              <div className="mb-1 flex flex-wrap items-center gap-1.5">
                <SeverityBadge severity={x.severity} />
                <StatusBadge status={x.status} overdue={x.overdue} />
                <ConfidenceBadge confidence={x.confidence} />
              </div>
              <TitleLink f={x} onOpen={onOpen} wrap />
              <div className="truncate text-sm text-kumo-subtle">
                {x.resource}
                {multi ? ` · ${x.account}` : ""}
              </div>
              <div className="text-xs text-kumo-subtle">
                Open {openFor(x.firstSeen).toLowerCase()}
                {x.triage?.owner ? ` · ${x.triage.owner}` : ""}
              </div>
            </div>
          </li>
        ))}
      </ul>
      <div className="hidden sm:block">
        <Table layout="auto">
          <Table.Header variant="compact">
            <Table.Row>
              <Table.CheckHead
                checked={all}
                indeterminate={some && !all}
                onCheckedChange={() =>
                  toggle(
                    rows.map((r) => r.fingerprint),
                    !all,
                  )
                }
                aria-label="Select all"
              />
              {nested ? (
                <Table.Head className="w-28">Severity</Table.Head>
              ) : (
                <SortHead k="severity" label="Severity" sort={sort} desc={desc} className="w-28" />
              )}
              <Table.Head>Finding</Table.Head>
              {multi && <Table.Head>Account</Table.Head>}
              <Table.Head>{zoneWord(providers)}</Table.Head>
              {nested ? <Table.Head className="whitespace-nowrap">Open for</Table.Head> : <SortHead k="age" label="Open for" sort={sort} desc={desc} />}
              {nested ? <Table.Head>Due</Table.Head> : <SortHead k="due" label="Due" sort={sort} desc={desc} />}
              <Table.Head>Owner</Table.Head>
              <Table.Head>Status</Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {rows.map((x) => (
              <Table.Row
                key={x.fingerprint}
                variant={selected.has(x.fingerprint) ? "selected" : "default"}
                className="cursor-pointer"
                onClick={() => onOpen(x)}
              >
                <Table.CheckCell
                  checked={selected.has(x.fingerprint)}
                  onCheckedChange={(v: boolean) => toggle([x.fingerprint], v)}
                  onClick={(e: React.MouseEvent) => e.stopPropagation()}
                  aria-label={`Select ${x.title}`}
                />
                <Table.Cell>
                  <SeverityBadge severity={x.severity} />
                </Table.Cell>
                <Table.Cell className="max-w-md">
                  <div className="flex min-w-0 items-center gap-2">
                    <PlatformMark provider={x.provider} spans={x.spans} />
                    <TitleLink f={x} onOpen={onOpen} />
                    <ConfidenceBadge confidence={x.confidence} />
                    {x.reopened && <ReopenedBadge />}
                  </div>
                  <div className="truncate text-sm text-kumo-subtle">{x.resource}</div>
                </Table.Cell>
                {multi && (
                  <Table.Cell className="max-w-40 truncate whitespace-nowrap text-kumo-subtle">
                    <AccountName name={x.account} provider={x.provider} showProvider={mixed} />
                  </Table.Cell>
                )}
                <Table.Cell className="max-w-48 truncate whitespace-nowrap text-kumo-subtle">{x.zone || "Account-wide"}</Table.Cell>
                <Table.Cell className="whitespace-nowrap tabular-nums text-kumo-subtle">{openFor(x.firstSeen)}</Table.Cell>
                <Table.Cell className={`whitespace-nowrap tabular-nums ${x.overdue ? "text-kumo-danger" : "text-kumo-subtle"}`}>
                  {x.due && !x.settled ? dateOnly(x.due) : "—"}
                </Table.Cell>
                <Table.Cell className="max-w-40 truncate text-kumo-subtle">{x.triage?.owner || "—"}</Table.Cell>
                <Table.Cell>
                  <StatusBadge status={x.status} overdue={x.overdue} />
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table>
      </div>
    </>
  );
}

interface Group {
  id: string;
  title: ReactNode;
  subtitle: string;
  items: Finding[];
  severity: Severity;
  tag?: ReactNode;
  why?: string | null;
  fix?: string | null;
}

function groupRows(rows: Finding[], by: Exclude<GroupBy, "none">, multi: boolean): Group[] {
  const key = (f: Finding) =>
    by === "check" ? f.checkId : by === "zone" ? `${f.accountId}|${f.zone || "account"}` : by === "platform" ? f.provider : f.accountId;
  const platforms = (items: Finding[]) => [...new Set(items.map((i) => i.provider))];
  return [...groupBy(rows, key).entries()]
    .map(([id, items]): Group => {
      const severity = items.reduce<Severity>((s, i) => (SEVERITY_WEIGHT[i.severity] > SEVERITY_WEIGHT[s] ? i.severity : s), "info");
      const first = items[0];
      const sample =
        items
          .slice(0, 3)
          .map((i) => (by === "check" ? i.resource : i.title))
          .join(", ") + (items.length > 3 ? `, +${items.length - 3} more` : "");
      if (by === "check") {
        const accounts = new Set(items.map((i) => i.accountId)).size;
        return {
          id,
          items,
          severity,
          why: first.why,
          fix: first.fix,
          title: first.title,
          tag: (
            <>
              <PlatformMark provider={platforms(items)} spans={first.spans} />
              <Tag info={first.source === "security_center"}>{first.source === "security_center" ? "Security Center" : first.checkId}</Tag>
            </>
          ),
          subtitle: `${multi ? (accounts > 1 ? `${accounts} accounts · ` : `${first.account} · `) : ""}${sample}`,
        };
      }
      const tag = <PlatformMark key="platform" provider={first.provider} />;
      if (by === "zone") return { id, items, severity, tag, title: first.zone || "Account-wide", subtitle: `${multi ? `${first.account} · ` : ""}${sample}` };
      if (by === "platform") {
        const accounts = new Set(items.map((i) => i.accountId)).size;
        return {
          id,
          items,
          severity,
          tag,
          title: PROVIDER_INFO[first.provider].label,
          subtitle: `${plural(accounts, PROVIDER_INFO[first.provider].account, PROVIDER_INFO[first.provider].accounts)} · ${sample}`,
        };
      }
      return { id, items, severity, tag, title: first.account, subtitle: `${first.entity ? `${first.entity} · ` : ""}${sample}` };
    })
    .sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] || b.items.length - a.items.length);
}

function GroupedTable({
  rows,
  groupBy,
  expanded,
  setExpanded,
  ...rest
}: TableProps & { groupBy: Exclude<GroupBy, "none">; expanded: Set<string>; setExpanded: (s: Set<string>) => void }) {
  const { selected, toggle, multi } = rest;
  const { view } = useShell();
  const groups = useMemo(() => groupRows(rows, groupBy, multi), [rows, groupBy, multi]);
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head className="w-10">
            <span className="sr-only">Expand</span>
          </Table.Head>
          <Table.Head className="w-10">
            <span className="sr-only">Select</span>
          </Table.Head>
          <Table.Head className="w-28">Severity</Table.Head>
          <Table.Head>
            {groupBy === "check"
              ? "Check"
              : groupBy === "zone"
                ? zoneWord(view.accounts.map((a) => a.provider))
                : groupBy === "platform"
                  ? "Platform"
                  : "Account"}
          </Table.Head>
          <Table.Head className="text-right">Findings</Table.Head>
          <Table.Head className="hidden md:table-cell">Owned</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {groups.map((g) => {
          const isOpen = expanded.has(g.id);
          const fps = g.items.map((i) => i.fingerprint);
          const all = fps.every((fp) => selected.has(fp));
          const flip = () => {
            const n = new Set(expanded);
            if (isOpen) n.delete(g.id);
            else n.add(g.id);
            setExpanded(n);
          };
          const owned = g.items.filter((i) => i.triage?.owner).length,
            overdue = g.items.filter((i) => i.overdue).length;
          return (
            <Fragment key={g.id}>
              <Table.Row className="cursor-pointer" onClick={flip}>
                <Table.Cell onClick={(e: React.MouseEvent) => e.stopPropagation()}>
                  <button
                    type="button"
                    aria-expanded={isOpen}
                    aria-label={`${isOpen ? "Collapse" : "Expand"} ${typeof g.title === "string" ? g.title : "group"}`}
                    onClick={flip}
                    className="flex h-7 w-7 items-center justify-center rounded text-kumo-subtle hover:bg-kumo-tint focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
                  >
                    {isOpen ? <CaretDownIcon /> : <CaretRightIcon />}
                  </button>
                </Table.Cell>
                <Table.Cell onClick={(e: React.MouseEvent) => e.stopPropagation()}>
                  <Checkbox
                    aria-label="Select this group"
                    checked={all}
                    indeterminate={!all && fps.some((fp) => selected.has(fp))}
                    onCheckedChange={() => toggle(fps, !all)}
                  />
                </Table.Cell>
                <Table.Cell>
                  <SeverityBadge severity={g.severity} />
                </Table.Cell>
                <Table.Cell className="max-w-xl">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate text-kumo-default">{g.title}</span>
                    {g.tag}
                    {g.items.some((i) => i.reopened) && <ReopenedBadge />}
                  </div>
                  <div className="truncate text-sm text-kumo-subtle">{g.subtitle}</div>
                </Table.Cell>
                <Table.Cell className="text-right tabular-nums">{num(g.items.length)}</Table.Cell>
                <Table.Cell className="hidden whitespace-nowrap tabular-nums text-kumo-subtle md:table-cell">
                  {owned}/{g.items.length}
                  {overdue ? <span className="ml-2 text-kumo-danger">{overdue} overdue</span> : null}
                </Table.Cell>
              </Table.Row>
              {isOpen && (
                <Table.Row>
                  <Table.Cell colSpan={6} className="bg-kumo-recessed p-4">
                    {(g.why || g.fix) && (
                      <div className="mb-3 flex flex-col gap-1 text-sm">
                        {g.why && (
                          <p>
                            <span className="font-medium text-kumo-default">Why it matters: </span>
                            <span className="text-kumo-default">{g.why}</span>
                          </p>
                        )}
                        {g.fix && (
                          <p>
                            <span className="font-medium text-kumo-default">How to fix: </span>
                            <span className="text-kumo-default">{g.fix}</span>
                          </p>
                        )}
                      </div>
                    )}
                    <div className="overflow-hidden rounded-lg bg-kumo-base ring ring-kumo-hairline">
                      <FindingsTable nested rows={g.items} {...rest} />
                    </div>
                  </Table.Cell>
                </Table.Row>
              )}
            </Fragment>
          );
        })}
      </Table.Body>
    </Table>
  );
}
