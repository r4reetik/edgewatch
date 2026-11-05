import { Badge, Table } from "@cloudflare/kumo";
import { useScopedApi, useShell } from "../shell.tsx";
import { dateTime, link, num, plural, score, type ScansResponse } from "../lib.ts";
import { Aside, Flag, ListCard, NoRows, Page, PageState } from "../components/ui.tsx";

const TITLE = "Scans";
const DESCRIPTION = "Scan history, and what the API token could read. A scan runs daily at the time set in Settings, and whenever you click Run scan.";
const TRIGGER: Record<string, string> = {
  manual: "Manual",
  schedule: "Scheduled",
  "catch-up": "Catch-up",
  setup: "Account added",
  token: "Token replaced",
};

export function ScansPage() {
  const { status, multi } = useShell();
  // Refetch as each queued account starts and finishes, so the history fills in live.
  const { data, error, loading, reload } = useScopedApi<ScansResponse>("/api/scans", [status?.running, status?.accountId]);
  if (error || !data) return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={loading} empty={false} retry={reload} />;
  const coverage = [...(data.coverage || [])].sort((a, b) => Number(a.ok) - Number(b.ok) || a.label.localeCompare(b.label));
  const unreadable = coverage.filter((c) => !c.ok).length;

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <ListCard title="History" footer={<span>{plural(data.scans.length, "scan")}</span>}>
        {data.scans.length ? (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>Started</Table.Head>
                {multi && <Table.Head>Account</Table.Head>}
                <Table.Head>Trigger</Table.Head>
                <Table.Head>Status</Table.Head>
                <Table.Head className="text-right">Score</Table.Head>
                <Table.Head>Open (critical / high / medium / low)</Table.Head>
                <Table.Head className="text-right">API calls</Table.Head>
                <Table.Head className="text-right">Duration</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {data.scans.map((s) => (
                <Table.Row key={s.id}>
                  <Table.Cell className="whitespace-nowrap tabular-nums">{dateTime(s.startedAt)}</Table.Cell>
                  {multi && <Table.Cell className="max-w-48 truncate whitespace-nowrap">{s.account}</Table.Cell>}
                  <Table.Cell className="text-kumo-subtle">{TRIGGER[s.trigger] || s.trigger}</Table.Cell>
                  <Table.Cell>
                    {s.status === "done" ? (
                      <Badge variant="success" appearance="dot">
                        Done
                      </Badge>
                    ) : s.status === "failed" ? (
                      <Badge variant="error" appearance="dot">
                        Failed
                      </Badge>
                    ) : (
                      <Badge variant="warning" appearance="dot">
                        Running
                      </Badge>
                    )}
                    {s.error && (
                      <div className="mt-1 max-w-md truncate text-sm text-kumo-danger" title={s.error}>
                        {s.error.split("\n")[0]}
                      </div>
                    )}
                  </Table.Cell>
                  <Table.Cell className="text-right tabular-nums">{score(s.score)}</Table.Cell>
                  <Table.Cell className="whitespace-nowrap tabular-nums text-kumo-subtle">
                    {s.counts ? `${s.counts.critical} / ${s.counts.high} / ${s.counts.medium} / ${s.counts.low}` : "—"}
                  </Table.Cell>
                  <Table.Cell className="text-right tabular-nums">{num(s.apiCalls)}</Table.Cell>
                  <Table.Cell className="text-right tabular-nums">
                    {s.finishedAt ? `${Math.round((Date.parse(s.finishedAt) - Date.parse(s.startedAt)) / 1000)} s` : "—"}
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        ) : (
          <NoRows>No scans yet.</NoRows>
        )}
      </ListCard>

      <span id="coverage" />
      <ListCard
        title="Data coverage"
        actions={<Aside>Unreadable data means skipped checks, never passed ones</Aside>}
        footer={
          coverage.length ? (
            <span>
              {plural(coverage.length, "data source")}
              {unreadable ? ` · ${unreadable} not readable` : " · all readable"}
            </span>
          ) : undefined
        }
      >
        {coverage.length ? (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>Data source</Table.Head>
                <Table.Head>Access</Table.Head>
                <Table.Head>What to do</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {coverage.map((c) => (
                <Table.Row key={c.label}>
                  <Table.Cell className="whitespace-nowrap">{c.label}</Table.Cell>
                  <Table.Cell className="whitespace-nowrap">
                    <Flag value={c.ok} on={multi ? "Readable in all" : "Readable"} off={`Not readable${c.status ? ` (${c.status})` : ""}`} />
                  </Table.Cell>
                  <Table.Cell className="max-w-xl text-sm text-kumo-subtle">
                    {c.ok ? (
                      "—"
                    ) : (
                      <div className="flex flex-col gap-0.5">
                        {c.permission && (
                          <span className="text-kumo-default">
                            Needs <span className="font-medium">{c.permission}</span>
                            {c.notReadableIn?.length ? ` for ${c.notReadableIn.map((a) => a.name).join(", ")}` : ""}
                          </span>
                        )}
                        {c.skippedChecks?.length ? (
                          <span>
                            {plural(c.skippedChecks.length, "check")} skipped: {c.skippedChecks.slice(0, 6).join(", ")}
                            {c.skippedChecks.length > 6 ? "…" : ""}
                          </span>
                        ) : null}
                        {c.message && (
                          <span className="truncate" title={c.message}>
                            Cloudflare said: {c.message}
                          </span>
                        )}
                        <a {...link("/accounts")} className="text-kumo-link">
                          Replace the token on the Accounts page
                        </a>
                      </div>
                    )}
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        ) : (
          <NoRows>Available after the first scan.</NoRows>
        )}
      </ListCard>
    </Page>
  );
}
