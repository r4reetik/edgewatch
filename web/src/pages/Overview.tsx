// The first screen: what to fix first, and whether things are getting better.
// Order: attack paths, the four numbers that matter, the most urgent problems
// (grouped by check), what changed since the last scan, trends, categories,
// and with several accounts, how each account compares.

import { useState } from "react";
import { Banner, Button, Table, Tabs } from "@cloudflare/kumo";
import { ArrowRightIcon, ArrowsClockwiseIcon, WarningIcon } from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import {
  ago,
  dateTime,
  link,
  navigate,
  num,
  plural,
  score,
  scopeKeyFor,
  totalScored,
  type AccountSummary,
  type FindingBrief,
  type FindingGroup,
  type Overview,
} from "../lib.ts";
import { Aside, Card, ConfidenceBadge, ListCard, NoRows, Page, PageState, Row, ScoreMeter, SeverityBadge, Stat } from "../components/ui.tsx";
import { TrendCharts } from "../components/charts.tsx";

const TITLE = "Overview";

export function OverviewPage() {
  const { startScan, status, multi, view } = useShell();
  const { data, error, loading, reload } = useScopedApi<Overview>("/api/overview");
  const [since, setSince] = useState<"new" | "resolved">("new");
  const description = multi
    ? `Security posture of ${view.kind === "all" ? "every account in All accounts" : `the ${plural(view.accounts.length, "account")} in ${view.label}`}, from each account's latest scan.`
    : "Security posture of this Cloudflare account, from its latest scan.";

  if (error || !data?.scan) {
    return (
      <PageState
        title={TITLE}
        description={description}
        error={error}
        loading={!data && loading}
        empty={!!data && !data.scan}
        retry={reload}
        emptyAction={
          <Button variant="primary" icon={<ArrowsClockwiseIcon />} loading={status?.running} onClick={startScan}>
            Run first scan
          </Button>
        }
      />
    );
  }

  const prev = data.trend.length > 1 ? data.trend[data.trend.length - 2] : null;
  const delta = prev?.score != null && data.score != null ? Math.round(data.score - prev.score) : null;
  const gaps = data.coverage.filter((c) => !c.ok);
  const gapAccounts = [...new Set(gaps.flatMap((g) => (g.notReadableIn || []).map((a) => a.name)))];
  const skipped = new Set(gaps.flatMap((g) => g.skippedChecks || []));
  const categories = Object.entries(data.categoryScores)
    .filter((e): e is [string, number] => e[1] != null)
    .sort((a, b) => a[1] - b[1]);
  const sinceRows = since === "new" ? data.newSince : data.resolvedSince;

  return (
    <Page title={TITLE} description={description}>
      {gaps.length > 0 && (
        <Banner
          variant="alert"
          icon={<WarningIcon weight="fill" />}
          title={`${multi && gapAccounts.length ? `The token for ${gapAccounts.join(", ")}` : "The API token"} can't read ${plural(gaps.length, "data source")}`}
          description={`${skipped.size ? `${plural(skipped.size, "check")} were skipped, not passed. ` : ""}Missing: ${[...new Set(gaps.map((g) => g.permission || g.label))].slice(0, 3).join("; ")}${gaps.length > 3 ? "; and more" : ""}.`}
          action={<Banner.Action onClick={() => navigate("/scans#coverage")}>See what's missing</Banner.Action>}
        />
      )}

      {data.attackPaths.length > 0 && <AttackPaths data={data} multi={multi} />}

      <Row cols={4}>
        <Stat
          label="Posture score"
          hint={
            multi
              ? "Average of the accounts' scores, out of 100, so a small account counts as much as a large one. Accepted risks and false positives don't count against it."
              : "Average of the category scores, out of 100. Accepted risks and false positives don't count against it."
          }
          value={
            <>
              {score(data.score)}
              <span className="text-base font-normal text-kumo-subtle"> / 100</span>
            </>
          }
          note={
            delta == null
              ? "Trend starts with the next scan"
              : delta === 0
                ? "No change since the previous scan"
                : `${delta > 0 ? "+" : ""}${delta} since the previous scan`
          }
        />
        <Stat
          label="Critical and high"
          value={num(data.counts.critical + data.counts.high)}
          note={`${num(data.counts.critical)} critical, ${num(data.counts.high)} high`}
          onClick={() => navigate("/findings?severity=critical,high")}
        />
        <Stat
          label="Overdue"
          hint="Past their due date, or open longer than the SLA for their severity (set in Settings)."
          value={num(data.triage.overdue)}
          note={data.triage.overdue ? "Past their due date or SLA" : "Nothing past its due date"}
          onClick={() => navigate("/findings?status=overdue")}
        />
        <Stat
          label="Without an owner"
          value={num(data.triage.unowned)}
          note="Critical and high findings"
          onClick={() => navigate("/findings?status=unowned&severity=critical,high")}
        />
      </Row>

      <ListCard
        title="Fix these first"
        actions={
          <Button size="sm" variant="ghost" icon={<ArrowRightIcon />} onClick={() => navigate("/findings?severity=critical,high")}>
            All critical and high
          </Button>
        }
      >
        {data.fixFirst.length ? <GroupTable rows={data.fixFirst} multi={multi} /> : <NoRows>No open critical or high findings.</NoRows>}
      </ListCard>

      {data.previousAt && (
        <ListCard
          title={multi ? "Since each account's previous scan" : `Since the previous scan · ${dateTime(data.previousAt)}`}
          actions={
            <>
              <Tabs
                size="sm"
                value={since}
                onValueChange={(v) => setSince(v as "new" | "resolved")}
                tabs={[
                  { value: "new", label: `New ${num(data.newSinceCount)}` },
                  { value: "resolved", label: `Resolved ${num(data.resolvedSince.length)}` },
                ]}
              />
              {since === "new" && data.newSinceCount > data.newSince.length && (
                <Button size="sm" variant="ghost" icon={<ArrowRightIcon />} onClick={() => navigate("/findings?status=new")}>
                  All {num(data.newSinceCount)}
                </Button>
              )}
            </>
          }
          footer={data.triage.reopened ? <span>{plural(data.triage.reopened, "open finding")} came back after being resolved.</span> : undefined}
        >
          {sinceRows.length ? (
            <BriefTable rows={sinceRows} linked={since === "new"} multi={multi} />
          ) : (
            <NoRows>{since === "new" ? "Nothing new since the previous scan." : "Nothing was resolved since the previous scan."}</NoRows>
          )}
        </ListCard>
      )}

      <TrendCharts points={data.trend} latest={data.counts} Card={Card} />

      <Card title="Score by category" actions={<Aside>Lowest first</Aside>}>
        <div className="grid grid-cols-1 gap-x-10 gap-y-5 md:grid-cols-2 xl:grid-cols-3">
          {categories.map(([cat, v]) => {
            const c = data.categoryCounts[cat];
            const n = totalScored(c);
            return (
              <a
                key={cat}
                {...link(`/findings?category=${encodeURIComponent(cat)}`)}
                className="group rounded focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
              >
                <ScoreMeter
                  label={cat}
                  value={v}
                  note={
                    <span className="group-hover:text-kumo-link">
                      {n ? `${plural(n, "open finding")}${c.critical + c.high ? ` · ${num(c.critical + c.high)} critical or high` : ""}` : "No open findings"}
                    </span>
                  }
                />
              </a>
            );
          })}
        </div>
      </Card>

      {multi && <AccountsCard rows={data.accounts} unscanned={data.unscanned} showEntity={view.kind === "all"} />}

      <p className="text-sm text-kumo-subtle">
        {multi
          ? `${plural(data.scan.accounts, "account")} scanned between ${dateTime(data.scan.oldestFinishedAt)} and ${dateTime(data.scan.finishedAt)}, with ${num(data.scan.apiCalls)} read-only API calls.`
          : `Scanned ${dateTime(data.scan.finishedAt)} with ${num(data.scan.apiCalls)} read-only API calls.`}
        {data.securityCenter.total != null &&
          ` Includes ${num(data.securityCenter.imported)} Cloudflare Security Center insights; ${num(data.securityCenter.corroborated)} more confirm Edgewatch's own findings.`}
      </p>
    </Page>
  );
}

function AttackPaths({ data, multi }: { data: Extract<Overview, { trend: unknown }>; multi: boolean }) {
  return (
    <ListCard
      title="Attack paths"
      actions={
        <>
          <Aside>Correlated from DNS, rules, tunnels, Access, traffic and the audit log</Aside>
          {data.attackPathCount > data.attackPaths.length && (
            <Button size="sm" variant="ghost" icon={<ArrowRightIcon />} onClick={() => navigate("/findings?category=Attack%20surface")}>
              All {num(data.attackPathCount)}
            </Button>
          )}
        </>
      }
    >
      <ul className="divide-y divide-kumo-hairline">
        {data.attackPaths.map((p) => (
          <li key={p.fingerprint}>
            <a
              {...link(`/findings/${p.fingerprint}`)}
              className="flex flex-col items-start gap-2 px-4 py-3 hover:bg-kumo-tint focus-visible:bg-kumo-tint focus-visible:outline-none sm:flex-row sm:gap-3"
            >
              <div className="shrink-0 pt-0.5 sm:w-24">
                <SeverityBadge severity={p.severity} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-kumo-default">{p.title}</span>
                  <ConfidenceBadge confidence={p.confidence} />
                </div>
                <p className="mt-0.5 text-sm break-words text-kumo-subtle [overflow-wrap:anywhere]">
                  {multi && <span className="font-medium text-kumo-default">{p.account}: </span>}
                  {p.detail}
                </p>
              </div>
              <ArrowRightIcon className="mt-1 hidden shrink-0 text-kumo-subtle sm:block" />
            </a>
          </li>
        ))}
      </ul>
    </ListCard>
  );
}

function AccountsCard({ rows, unscanned, showEntity }: { rows: AccountSummary[]; unscanned: { id: string; name: string }[]; showEntity: boolean }) {
  const { setScope } = useShell();
  const sorted = [...rows].sort((a, b) => (a.score ?? 101) - (b.score ?? 101));
  return (
    <ListCard
      title="Accounts"
      actions={<Aside>Lowest score first</Aside>}
      footer={
        <span>
          {plural(rows.length + unscanned.length, "account")}
          {unscanned.length ? ` · ${unscanned.length} not scanned yet` : ""}
        </span>
      }
    >
      <Table layout="auto">
        <Table.Header variant="compact">
          <Table.Row>
            <Table.Head>Account</Table.Head>
            {showEntity && <Table.Head>Entity</Table.Head>}
            <Table.Head className="w-48">Score</Table.Head>
            <Table.Head className="text-right whitespace-nowrap">Critical and high</Table.Head>
            <Table.Head className="text-right whitespace-nowrap">Open findings</Table.Head>
            <Table.Head className="whitespace-nowrap">Last scan</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {sorted.map((a) => (
            <Table.Row key={a.id}>
              <Table.Cell className="max-w-64 truncate">
                <button
                  type="button"
                  className="text-kumo-link hover:underline focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
                  onClick={() => setScope(scopeKeyFor.account(a.id))}
                >
                  {a.name}
                </button>
              </Table.Cell>
              {showEntity && <Table.Cell className="max-w-48 truncate text-kumo-subtle">{a.entity}</Table.Cell>}
              <Table.Cell>{a.score == null ? "—" : <ScoreMeter label="Score" value={a.score} />}</Table.Cell>
              <Table.Cell className="text-right tabular-nums">{num(a.counts.critical + a.counts.high)}</Table.Cell>
              <Table.Cell className="text-right tabular-nums">{num(totalScored(a.counts))}</Table.Cell>
              <Table.Cell className="whitespace-nowrap text-kumo-subtle">{ago(a.finishedAt)}</Table.Cell>
            </Table.Row>
          ))}
          {unscanned.map((a) => (
            <Table.Row key={a.id}>
              <Table.Cell className="max-w-64 truncate">{a.name}</Table.Cell>
              {showEntity && <Table.Cell />}
              <Table.Cell colSpan={4} className="text-kumo-subtle">
                Not scanned yet
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table>
    </ListCard>
  );
}

/** One row per check: a single finding opens directly, several open the filtered list. */
function GroupTable({ rows, multi }: { rows: FindingGroup[]; multi: boolean }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head className="w-28">Severity</Table.Head>
          <Table.Head>Finding</Table.Head>
          <Table.Head>Where</Table.Head>
          <Table.Head className="hidden text-right md:table-cell">Overdue</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((g) => {
          const to = g.fingerprint ? `/findings/${g.fingerprint}` : `/findings?check=${g.checkId}&severity=critical,high`;
          const zones = g.zones.slice(0, 2).join(", ") + (g.zones.length > 2 ? ` +${g.zones.length - 2}` : "");
          const where = [g.count > 1 ? plural(g.count, "place") : null, multi && g.accounts.length ? g.accounts.join(", ") : null, zones || null]
            .filter(Boolean)
            .join(" · ");
          return (
            <Table.Row key={g.checkId}>
              <Table.Cell>
                <SeverityBadge severity={g.severity} />
              </Table.Cell>
              <Table.Cell className="max-w-md">
                <div className="flex min-w-0 items-center gap-2">
                  <a
                    {...link(to)}
                    className="truncate text-kumo-link hover:underline focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
                  >
                    {g.title}
                  </a>
                  <ConfidenceBadge confidence={g.confidence} />
                </div>
              </Table.Cell>
              <Table.Cell className="max-w-xs truncate text-kumo-subtle">{where || "Account-wide"}</Table.Cell>
              <Table.Cell className={`hidden text-right tabular-nums md:table-cell ${g.overdue ? "text-kumo-danger" : "text-kumo-subtle"}`}>
                {g.overdue || "—"}
              </Table.Cell>
            </Table.Row>
          );
        })}
      </Table.Body>
    </Table>
  );
}

function BriefTable({ rows, linked, multi }: { rows: FindingBrief[]; linked: boolean; multi: boolean }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head className="w-28">Severity</Table.Head>
          <Table.Head>Finding</Table.Head>
          <Table.Head>Resource</Table.Head>
          {multi && <Table.Head>Account</Table.Head>}
          <Table.Head className="hidden md:table-cell">Category</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((f) => (
          <Table.Row key={f.fingerprint}>
            <Table.Cell>
              <SeverityBadge severity={f.severity} />
            </Table.Cell>
            <Table.Cell className="max-w-md">
              {linked ? (
                <a
                  {...link(`/findings/${f.fingerprint}`)}
                  className="text-kumo-link hover:underline focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
                >
                  {f.title}
                </a>
              ) : (
                <span className="text-kumo-default">{f.title}</span>
              )}
            </Table.Cell>
            <Table.Cell className="max-w-sm truncate text-kumo-subtle">
              {f.resource}
              {f.zone && f.zone !== f.resource ? ` · ${f.zone}` : ""}
            </Table.Cell>
            {multi && <Table.Cell className="max-w-48 truncate whitespace-nowrap text-kumo-subtle">{f.account}</Table.Cell>}
            <Table.Cell className="hidden whitespace-nowrap text-kumo-subtle md:table-cell">{f.category}</Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
}
