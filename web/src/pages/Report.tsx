// Print-optimized audit report. Opens in its own tab; "Save as PDF" is the browser's print dialog.

import { useEffect } from "react";
import { Button, Meter, Table } from "@cloudflare/kumo";
import { ArrowLeftIcon, PrinterIcon } from "@phosphor-icons/react";
import { useShell } from "../shell.tsx";
import { useApi, plural, dateOnly, dateTime, num, SCORED_SEVERITIES, SEVERITY_LABEL, STATUS_LABEL } from "../lib.ts";
import { ErrorState, Loading, SeverityBadge } from "../components/ui.tsx";
import { Wordmark } from "../components/brand.tsx";
import type { Report } from "../lib.ts";

export function ReportPage() {
  const { scoped } = useShell();
  const { data, error, loading, reload } = useApi<Report>(scoped("/api/report"));

  // Reports always render light, on screen and on paper.
  useEffect(() => {
    const prev = document.documentElement.getAttribute("data-mode");
    document.documentElement.setAttribute("data-mode", "light");
    document.title = "Edgewatch report";
    return () => {
      if (prev) document.documentElement.setAttribute("data-mode", prev);
      document.title = "Edgewatch";
    };
  }, []);

  if (error)
    return (
      <div className="p-8">
        <ErrorState error={error} retry={reload} />
      </div>
    );
  if (!data && loading) return <Loading label="Preparing report" />;
  if (!data?.scan) return <div className="p-8 text-kumo-subtle">Run a scan before generating a report.</div>;

  const open = data.findings.filter((f) => !f.settled);
  const settled = data.findings.filter((f) => f.settled);
  const top = open.filter((f) => f.severity === "critical" || f.severity === "high");
  const byCategory = groupBy(open, (f) => f.category);
  const evaluations = Object.values(data.checks || {}).reduce((s, c) => s + c.evaluated, 0);
  const gaps = data.coverage.filter((c) => !c.ok);
  const multi = data.accounts.length > 1;
  const one = data.accounts.length === 1 ? data.accounts[0] : null;
  const subtitle = one
    ? one.entity && one.entity !== one.name
      ? `${one.name} · ${one.entity}`
      : one.name
    : `${data.scope.label} · ${plural(data.accounts.length, "Cloudflare account")}`;

  return (
    <div className="min-h-full bg-kumo-canvas print:bg-white">
      <div className="no-print sticky top-0 z-10 flex items-center justify-between border-b border-kumo-hairline bg-kumo-base px-6 py-3">
        <Button
          variant="ghost"
          icon={<ArrowLeftIcon />}
          onClick={() => {
            location.href = "/";
          }}
        >
          Back to Edgewatch
        </Button>
        <Button variant="primary" icon={<PrinterIcon />} onClick={() => window.print()}>
          Print or save as PDF
        </Button>
      </div>

      <article className="mx-auto max-w-4xl bg-kumo-base px-10 py-12 text-sm text-kumo-default shadow-sm print:max-w-none print:px-0 print:py-0 print:shadow-none">
        <header className="mb-10 border-b border-kumo-hairline pb-8">
          <Wordmark />
          <h1 className="mt-8 text-3xl font-semibold">Cloudflare security posture report</h1>
          <p className="mt-2 text-base text-kumo-subtle">{subtitle}</p>
          <dl className="mt-6 grid grid-cols-2 gap-y-1 text-xs text-kumo-subtle sm:grid-cols-4">
            <dt>{multi ? "Scans completed" : "Scan completed"}</dt>
            <dd className="sm:col-span-3">
              {multi && dateTime(data.scan.oldestFinishedAt) !== dateTime(data.scan.finishedAt)
                ? `${dateTime(data.scan.oldestFinishedAt)} to ${dateTime(data.scan.finishedAt)}`
                : dateTime(data.scan.finishedAt)}
            </dd>
            <dt>Report generated</dt>
            <dd className="sm:col-span-3">{dateTime(data.generatedAt)}</dd>
            {data.accountId && (
              <>
                <dt>Account ID</dt>
                <dd className="font-mono sm:col-span-3">{data.accountId}</dd>
              </>
            )}
          </dl>
        </header>

        <section className="avoid-break mb-10">
          <h2 className="mb-4 text-lg font-semibold">Summary</h2>
          <div className="grid grid-cols-1 gap-8 sm:grid-cols-[200px_1fr]">
            <div>
              <div className="text-xs text-kumo-subtle">{multi ? "Posture score (average of accounts)" : "Posture score"}</div>
              <div className="text-5xl font-semibold tabular-nums">
                {data.score ?? "—"}
                <span className="text-lg text-kumo-subtle"> / 100</span>
              </div>
              <ul className="mt-4 space-y-1.5">
                {SCORED_SEVERITIES.map((s) => (
                  <li key={s} className="flex items-center justify-between gap-3">
                    <SeverityBadge severity={s} />
                    <span className="tabular-nums">{num(data.counts[s])}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-kumo-subtle">
                {num(open.length)} open findings across {num(data.zones?.length ?? 0)} zones. {num(settled.length)} accepted or marked false positive.
              </p>
            </div>
            <div className="flex flex-col gap-3">
              {Object.entries(data.categoryScores)
                .filter(([, v]) => v != null)
                .sort((a, b) => (a[1] as number) - (b[1] as number))
                .map(([c, v]) => (
                  <Meter key={c} label={c} value={v as number} customValue={`${Math.round(v as number)}`} />
                ))}
            </div>
          </div>
        </section>

        {multi && (
          <section className="avoid-break mb-10">
            <h2 className="mb-4 text-lg font-semibold">Accounts</h2>
            <Table layout="auto" className="text-xs">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.Head>Account</Table.Head>
                  {data.scope.kind === "all" && <Table.Head>Entity</Table.Head>}
                  <Table.Head className="text-right">Score</Table.Head>
                  <Table.Head className="text-right">Critical</Table.Head>
                  <Table.Head className="text-right">High</Table.Head>
                  <Table.Head className="text-right">Open</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {data.accounts.map((a) => (
                  <Table.Row key={a.id}>
                    <Table.Cell>
                      <div>{a.name}</div>
                      <div className="font-mono text-kumo-subtle">{a.id}</div>
                    </Table.Cell>
                    {data.scope.kind === "all" && <Table.Cell>{a.entity}</Table.Cell>}
                    <Table.Cell className="text-right tabular-nums">{a.score ?? "—"}</Table.Cell>
                    <Table.Cell className="text-right tabular-nums">{num(a.counts.critical)}</Table.Cell>
                    <Table.Cell className="text-right tabular-nums">{num(a.counts.high)}</Table.Cell>
                    <Table.Cell className="text-right tabular-nums">{num(SCORED_SEVERITIES.reduce((s, k) => s + (a.counts[k] || 0), 0))}</Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          </section>
        )}

        {top.length > 0 && (
          <section className="mb-10">
            <h2 className="mb-1 text-lg font-semibold">Priority findings</h2>
            <p className="mb-4 text-kumo-subtle">Open critical and high findings, with what to do about each.</p>
            <ol className="space-y-4">
              {top.map((f) => (
                <li key={f.fingerprint} className="avoid-break rounded-lg p-4 ring ring-kumo-hairline">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="font-medium">{f.title}</span>
                  </div>
                  <div className="mt-1 break-all font-mono text-xs text-kumo-subtle">
                    {multi && `${f.account} · `}
                    {f.resource}
                    {f.zone && f.zone !== f.resource ? ` · ${f.zone}` : ""}
                  </div>
                  {f.detail && <p className="mt-2">{f.detail}</p>}
                  {f.why && (
                    <p className="mt-2">
                      <span className="font-medium">Why it matters: </span>
                      {f.why}
                    </p>
                  )}
                  {f.fix && (
                    <p className="mt-1">
                      <span className="font-medium">How to fix: </span>
                      {f.fix}
                    </p>
                  )}
                  {f.triage?.owner && (
                    <p className="mt-2 text-xs text-kumo-subtle">
                      Owner: {f.triage.owner}
                      {f.due ? ` · due ${dateOnly(f.due)}` : ""}
                    </p>
                  )}
                </li>
              ))}
            </ol>
          </section>
        )}

        <section className="print-break mb-10">
          <h2 className="mb-1 text-lg font-semibold">All open findings</h2>
          <p className="mb-4 text-kumo-subtle">Grouped by category, highest severity first.</p>
          {Object.entries(byCategory).map(([cat, items]) => (
            <div key={cat} className="mb-6">
              <h3 className="mb-2 font-semibold">
                {cat} <span className="font-normal text-kumo-subtle">({items.length})</span>
              </h3>
              <Table layout="auto" className="text-xs">
                <Table.Header variant="compact">
                  <Table.Row>
                    <Table.Head>Severity</Table.Head>
                    <Table.Head>Finding</Table.Head>
                    <Table.Head>Status</Table.Head>
                    <Table.Head>Owner</Table.Head>
                    <Table.Head>Due</Table.Head>
                  </Table.Row>
                </Table.Header>
                <Table.Body>
                  {items.map((f) => (
                    <Table.Row key={f.fingerprint} className="avoid-break">
                      <Table.Cell>
                        <SeverityBadge severity={f.severity} />
                      </Table.Cell>
                      <Table.Cell>
                        <div>{f.title}</div>
                        <div className="break-all text-kumo-subtle">
                          {multi && `${f.account} · `}
                          {f.resource}
                        </div>
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap">{f.overdue ? "Overdue" : STATUS_LABEL[f.status]}</Table.Cell>
                      <Table.Cell>{f.triage?.owner || "—"}</Table.Cell>
                      <Table.Cell className="whitespace-nowrap">{f.due ? dateOnly(f.due) : "—"}</Table.Cell>
                    </Table.Row>
                  ))}
                </Table.Body>
              </Table>
            </div>
          ))}
        </section>

        {settled.length > 0 && (
          <section className="mb-10">
            <h2 className="mb-1 text-lg font-semibold">Accepted risks and false positives</h2>
            <Table layout="auto" className="text-xs">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.Head>Finding</Table.Head>
                  <Table.Head>Decision</Table.Head>
                  <Table.Head>Until</Table.Head>
                  <Table.Head>Note</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {settled.map((f) => (
                  <Table.Row key={f.fingerprint} className="avoid-break">
                    <Table.Cell>
                      <div>{f.title}</div>
                      <div className="break-all text-kumo-subtle">{f.resource}</div>
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap">
                      {STATUS_LABEL[f.status]}
                      {f.triage?.owner ? ` by ${f.triage.owner}` : ""}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap">{f.triage?.acceptUntil ? dateOnly(f.triage.acceptUntil) : "—"}</Table.Cell>
                    <Table.Cell>{f.triage?.note || "—"}</Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          </section>
        )}

        <section className="avoid-break border-t border-kumo-hairline pt-6 text-xs text-kumo-subtle">
          <h2 className="mb-2 text-sm font-semibold text-kumo-default">Method</h2>
          <p>
            Edgewatch {data.version} read {multi ? `the configuration of ${plural(data.accounts.length, "account")}` : "the account's configuration"} through
            the Cloudflare API with read-only tokens ({num(data.scan.apiCalls)} requests), ran {num(Object.keys(data.checks || {}).length)} checks over{" "}
            {num(evaluations)} resources, and imported Cloudflare Security Center insights. Each category score is the severity-weighted share of passing
            evaluations (critical 10, high 6, medium 3, low 1); the posture score is the average of the categories.
            {multi && " With several accounts, the posture score is the average of the accounts' scores."}
            Accepted risks and false positives don't count against the score.
          </p>
          {gaps.length > 0 && (
            <p className="mt-2">
              Not readable, so related checks were skipped:{" "}
              {gaps.map((g) => (g.notReadableIn?.length ? `${g.label} (${g.notReadableIn.join(", ")})` : g.label)).join(", ")}.
            </p>
          )}
          <p className="mt-2">
            Severity labels: {SCORED_SEVERITIES.map((s) => SEVERITY_LABEL[s]).join(", ")}. Edgewatch is an independent project, not affiliated with Cloudflare.
          </p>
        </section>
      </article>
    </div>
  );
}

const groupBy = <T,>(arr: T[], key: (x: T) => string) =>
  arr.reduce<Record<string, T[]>>((m, x) => {
    (m[key(x)] ||= []).push(x);
    return m;
  }, {});
