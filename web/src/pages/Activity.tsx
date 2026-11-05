import { useMemo, useState } from "react";
import { Badge, Empty, Input, Pagination, Select, Table } from "@cloudflare/kumo";
import { ClockCounterClockwiseIcon } from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import { clampPage, dateTime, num, setParams, useLocation, type ActivityResponse } from "../lib.ts";
import { ListCard, NoRows, Page, PageState, Row, Stat, unreadableText } from "../components/ui.tsx";

const ALL = "all";
const PER_PAGE = 50;
const TITLE = "Activity";
const DESCRIPTION = "Changes made in the account over the last 7 days, from the audit log. Look for changes nobody expected.";
const SHOW: Record<string, string> = { changes: "Changes", destructive: "Destructive only", failed: "Failed only", everything: "Including sign-ins" };

export function ActivityPage() {
  const { multi } = useShell();
  const { data, error, loading, reload } = useScopedApi<ActivityResponse>("/api/activity");
  // Filters live in the URL, so a filtered view can be shared.
  const { params } = useLocation();
  const account = params.get("account") || ALL,
    q = params.get("q") || "",
    area = params.get("area") || ALL;
  const actor = params.get("actor") || ALL,
    show = params.get("show") || "changes";
  const param = (k: string, def: string) => (v: string) => setParams({ [k]: v === def ? null : v });
  const [setAccount, setQ, setArea, setActor, setShow] = [
    param("account", ALL),
    param("q", ""),
    param("area", ALL),
    param("actor", ALL),
    param("show", "changes"),
  ];
  const [pageState, setPage] = useState(1);
  const a = data?.activity;
  const rows = useMemo(
    () =>
      (a?.events || []).filter((e) => {
        if (show === "changes" && e.routine) return false;
        if (show === "destructive" && !e.destructive) return false;
        if (show === "failed" && e.ok) return false;
        if (area !== ALL && e.category !== area) return false;
        if (actor !== ALL && e.actor !== actor) return false;
        if (account !== ALL && e.accountId !== account) return false;
        if (q && !`${e.type} ${e.info} ${e.resource} ${e.zone} ${e.actor}`.toLowerCase().includes(q.toLowerCase())) return false;
        return true;
      }),
    [a, q, area, actor, account, show],
  );
  const page = clampPage(pageState, rows.length, PER_PAGE);

  if (error || !data?.scan || !a)
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={data?.scan ? unreadableText(data.coverage, "auditLogs", "activity") : undefined}
      />
    );
  if (!a.available) {
    return (
      <Page title={TITLE} description={DESCRIPTION}>
        <ListCard>
          <Empty
            className="py-12"
            icon={<ClockCounterClockwiseIcon size={40} className="text-kumo-inactive" />}
            title="Audit log not readable"
            description="Grant the token Account Settings read access to see account activity."
          />
        </ListCard>
      </Page>
    );
  }

  const changes = a.events.filter((e) => !e.routine);
  const actors = Object.entries(a.byActor).sort((x, y) => y[1] - x[1]);
  const areas = Object.entries(a.byCategory).sort((x, y) => y[1] - x[1]);
  const accounts = [...new Map(a.events.map((e) => [e.accountId ?? "", e.account ?? ""])).entries()].sort((x, y) => x[1].localeCompare(y[1]));
  const reset = (fn: () => void) => {
    fn();
    setPage(1);
  };

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <Row cols={4}>
        <Stat label="Changes" value={num(changes.length)} note={areas.length ? `Most in ${areas[0][0]}` : "Excluding sign-ins"} />
        <Stat
          label="Destructive actions"
          value={num(changes.filter((e) => e.destructive).length)}
          note="Deletes, removals, revocations"
          onClick={() => reset(() => setShow("destructive"))}
        />
        <Stat label="People and tokens" value={num(actors.length)} note={actors.length ? `Most active: ${actors[0][0]}` : "Made at least one change"} />
        <Stat
          label="Failed actions"
          value={num(a.events.filter((e) => !e.ok).length)}
          note="Rejected by Cloudflare"
          onClick={() => reset(() => setShow("failed"))}
        />
      </Row>

      <ListCard
        toolbar={
          <>
            <Input
              className="w-full min-w-48 sm:w-auto sm:flex-1"
              aria-label="Search activity"
              placeholder="Search actions and resources"
              value={q}
              onChange={(e) => reset(() => setQ(e.target.value))}
            />
            {multi && (
              <Select
                aria-label="Account"
                className="min-w-36 flex-1 sm:w-44 sm:flex-none"
                value={account}
                onValueChange={(v) => reset(() => setAccount(String(v)))}
                items={{ [ALL]: "All accounts", ...Object.fromEntries(accounts) }}
              />
            )}
            <Select
              aria-label="Area"
              className="min-w-36 flex-1 sm:w-48 sm:flex-none"
              value={area}
              onValueChange={(v) => reset(() => setArea(String(v)))}
              items={{ [ALL]: "All areas", ...Object.fromEntries(areas.map(([c, n]) => [c, `${c} (${n})`])) }}
            />
            <Select
              aria-label="Who"
              className="min-w-36 flex-1 sm:w-56 sm:flex-none"
              value={actor}
              onValueChange={(v) => reset(() => setActor(String(v)))}
              items={{ [ALL]: "Everyone", ...Object.fromEntries(actors.map(([w, n]) => [w, `${w} (${n})`])) }}
            />
            <Select
              aria-label="Show"
              className="min-w-36 flex-1 sm:w-44 sm:flex-none"
              value={show}
              onValueChange={(v) => reset(() => setShow(String(v)))}
              items={SHOW}
            />
          </>
        }
        footer={
          <>
            <span>
              {num(rows.length)} events since {dateTime(a.since)}
            </span>
            {rows.length > PER_PAGE && <Pagination page={page} setPage={setPage} perPage={PER_PAGE} totalCount={rows.length} />}
          </>
        }
      >
        {rows.length ? (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>When</Table.Head>
                {multi && <Table.Head>Account</Table.Head>}
                <Table.Head>Who</Table.Head>
                <Table.Head>Action</Table.Head>
                <Table.Head>Resource</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {rows.slice((page - 1) * PER_PAGE, page * PER_PAGE).map((e, i) => (
                <Table.Row key={`${e.when}-${i}`}>
                  <Table.Cell className="whitespace-nowrap tabular-nums text-kumo-subtle">{dateTime(e.when)}</Table.Cell>
                  {multi && <Table.Cell className="max-w-40 truncate whitespace-nowrap text-kumo-subtle">{e.account}</Table.Cell>}
                  <Table.Cell>
                    <div className="max-w-[14rem] truncate">{e.actor}</div>
                    {e.ip && <div className="max-w-[14rem] truncate font-mono text-xs text-kumo-subtle">{e.ip}</div>}
                  </Table.Cell>
                  <Table.Cell>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm">{e.type}</span>
                      {e.destructive && <Badge variant="warning">Destructive</Badge>}
                      {!e.ok && <Badge variant="error">Failed</Badge>}
                    </div>
                    {e.info && <div className="max-w-[26rem] truncate text-sm text-kumo-subtle">{e.info}</div>}
                  </Table.Cell>
                  <Table.Cell>
                    <div className="max-w-[18rem] truncate text-kumo-subtle" title={e.resource}>
                      {e.resource || "—"}
                    </div>
                    <div className="max-w-[18rem] truncate text-sm text-kumo-subtle">{[e.zone, e.category].filter(Boolean).join(" · ")}</div>
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        ) : (
          <NoRows>No events match these filters.</NoRows>
        )}
      </ListCard>
    </Page>
  );
}
