// One finding on its own page, reachable from any scope: /findings/<fingerprint>.
// Shows the finding with its triage and a timeline of every scan and change.
// When the finding has been resolved, the page says so and shows its last state.

import { Badge, Button } from "@cloudflare/kumo";
import { ArrowLeftIcon } from "@phosphor-icons/react";
import { HttpError, dateTime, link, navigate, scopeKeyFor, useApi, type FindingDetail, type Triage } from "../lib.ts";
import { useShell } from "../shell.tsx";
import { Card, Page, PageState } from "../components/ui.tsx";
import { CopyLinkButton, FindingBody, FindingHeader, TriagePanel } from "../components/triage.tsx";
import { SeverityBadge } from "../components/ui.tsx";
import { Timeline } from "../components/history.tsx";

export function FindingPage({ params }: { params: Record<string, string> }) {
  const fp = params.fp;
  const { view, setScope, dataVersion } = useShell();
  const { data, error, loading, reload, setData } = useApi<FindingDetail>(`/api/finding/${fp}`, dataVersion);
  const back = (
    <Button variant="ghost" size="sm" icon={<ArrowLeftIcon />} onClick={() => navigate("/findings")}>
      Findings
    </Button>
  );

  if (error || !data) {
    const gone = error instanceof HttpError && error.status === 404;
    return (
      <PageState
        title="Finding"
        error={gone ? null : error}
        loading={loading}
        empty={gone}
        emptyText="This finding doesn't exist, or its account was removed."
        retry={reload}
      />
    );
  }

  const outOfView = !view.accounts.some((a) => a.id === data.accountId);
  const f = data.finding;
  const onSaved = (t: Triage) =>
    setData({ ...data, finding: f && { ...f, triage: t, status: t.status, settled: t.status === "accepted" || t.status === "false_positive" } });

  return (
    <Page
      title={f?.title || data.last?.title || "Finding"}
      actions={
        <>
          {back}
          <CopyLinkButton fingerprint={fp} />
        </>
      }
    >
      {outOfView && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-kumo-elevated p-4 text-sm ring ring-kumo-line">
          <span>
            This finding belongs to <strong>{data.account}</strong>, which isn't in the current view ({view.label}).
          </span>
          <Button size="sm" onClick={() => setScope(scopeKeyFor.account(data.accountId))}>
            Show {data.account}
          </Button>
        </div>
      )}
      {f ? (
        <Card>
          <FindingHeader f={f} hideTitle />
          <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(20rem,26rem)]">
            <FindingBody f={f} />
            <TriagePanel
              f={f}
              onSaved={(t) => {
                onSaved(t);
                void reload();
              }}
            />
          </div>
        </Card>
      ) : (
        <Card>
          <div className="flex flex-wrap items-center gap-2">
            {data.last && <SeverityBadge severity={data.last.severity} />}
            <Badge variant="outline">Resolved</Badge>
          </div>
          <p className="mt-3 text-sm text-kumo-default">
            This finding is no longer reported{data.resolvedAt ? `; the scan on ${dateTime(data.resolvedAt)} didn't find it` : ""}.
            {data.last && (
              <>
                {" "}
                It was <span className="font-medium">{data.last.title}</span> on <span className="break-all">{data.last.resource}</span>.
              </>
            )}
          </p>
          {data.last && (
            <p className="mt-2 text-sm">
              <a {...link(`/findings?check=${data.last.checkId}&status=all`)} className="text-kumo-link">
                Other findings from this check
              </a>
            </p>
          )}
        </Card>
      )}
      <Card title="Timeline">
        <Timeline events={data.events} />
      </Card>
    </Page>
  );
}
