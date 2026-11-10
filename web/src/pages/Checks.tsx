import { useMemo, useState } from "react";
import { Input, Link, Select, Switch, Table, useKumoToastManager } from "@cloudflare/kumo";
import { BookOpenIcon } from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import { api, link, num, pct, plural, SEVERITY_LABEL, siteName, type CheckRow, type ChecksResponse, type Severity } from "../lib.ts";
import { ListCard, NoRows, Page, PageState, PlatformMark, Tag } from "../components/ui.tsx";
type Check = CheckRow;

const ALL = "all";
const DEFAULT = "default";
const TITLE = "Checks";
const DESCRIPTION =
  "Every check Edgewatch runs. Turning a check off or changing its severity applies to every account, from the next scan. The counts show the accounts in view.";

export function ChecksPage() {
  const { multi } = useShell();
  const { data, error, loading, reload, setData } = useScopedApi<ChecksResponse>("/api/checks");
  const toasts = useKumoToastManager();
  const [cat, setCat] = useState(ALL);
  const [q, setQ] = useState("");
  const checks = useMemo(
    () =>
      (data?.checks || []).filter((c) => (cat === ALL || c.category === cat) && (!q || `${c.id} ${c.title} ${c.why}`.toLowerCase().includes(q.toLowerCase()))),
    [data, cat, q],
  );

  if (error || !data) return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={loading} empty={false} retry={reload} />;

  const save = async (c: Check, patch: Partial<Pick<Check, "disabled" | "severityOverride">>) => {
    const next = { ...c, ...patch };
    setData((d) => d && { ...d, checks: d.checks.map((x) => (x.id === c.id ? next : x)) });
    try {
      await api(`/api/checks/${c.id}`, { method: "PUT", body: { disabled: next.disabled, severity: next.severityOverride } });
      toasts.add({ title: `${c.id} updated`, description: "Takes effect on the next scan.", variant: "success" });
    } catch (e) {
      setData((d) => d && { ...d, checks: d.checks.map((x) => (x.id === c.id ? c : x)) });
      toasts.add({ title: "Couldn't save", description: (e as Error).message, variant: "error" });
    }
  };
  const categories = [...new Set(data.checks.map((c) => c.category))];
  const evaluations = data.checks.reduce((s, c) => s + c.evaluated, 0);
  const off = data.checks.filter((c) => c.disabled).length;
  // The server lists checks for the providers in view; with more than one, each row names its provider.
  const providers = new Set(data.checks.map((c) => c.provider));

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <ListCard
        toolbar={
          <>
            <Input
              className="w-full min-w-48 sm:w-auto sm:flex-1"
              aria-label="Search checks"
              placeholder="Search checks"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            <Select
              aria-label="Category"
              className="min-w-36 flex-1 sm:w-48 sm:flex-none"
              value={cat}
              onValueChange={(v) => setCat(String(v))}
              items={{ [ALL]: "All categories", ...Object.fromEntries(categories.map((c) => [c, c])) }}
            />
          </>
        }
        footer={
          <>
            <span>
              {plural(checks.length, "check")}
              {off ? ` · ${off} turned off` : ""}
            </span>
            {data.scan && (
              <span>
                {num(evaluations)} evaluations in the latest scan{providers.has("cloudflare") ? ", plus every Security Center insight" : ""}
              </span>
            )}
          </>
        }
      >
        {checks.length ? (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>Check</Table.Head>
                <Table.Head>Category</Table.Head>
                <Table.Head>Severity</Table.Head>
                <Table.Head className="text-right">Evaluated</Table.Head>
                <Table.Head className="text-right">Failing</Table.Head>
                <Table.Head className="text-right">Passing</Table.Head>
                <Table.Head>Enabled</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {checks.map((c) => (
                <Table.Row key={c.id} className={c.disabled ? "[&_td]:text-kumo-subtle" : undefined}>
                  <Table.Cell className="max-w-xl">
                    <div className="flex min-w-0 items-center gap-2">
                      <PlatformMark provider={c.provider} spans={c.spans} />
                      <Tag>{c.id}</Tag>
                      <span className="truncate text-kumo-default">{c.title}</span>
                    </div>
                    <div className="mt-0.5 line-clamp-2 text-sm text-kumo-subtle">{c.why}</div>
                    {c.docs && (
                      <Link href={c.docs} target="_blank" rel="noopener noreferrer" className="mt-0.5 inline-flex items-center gap-1 text-sm">
                        <BookOpenIcon /> {siteName(c.docs)} docs
                      </Link>
                    )}
                  </Table.Cell>
                  <Table.Cell className="whitespace-nowrap text-kumo-subtle">{c.category}</Table.Cell>
                  <Table.Cell>
                    <Select
                      aria-label={`Severity for ${c.id}`}
                      size="sm"
                      className="w-40"
                      value={c.severityOverride || DEFAULT}
                      onValueChange={(v) => save(c, { severityOverride: v === DEFAULT ? null : (v as Severity) })}
                      items={{
                        [DEFAULT]: `${SEVERITY_LABEL[c.severity]} (default)`,
                        critical: "Critical",
                        high: "High",
                        medium: "Medium",
                        low: "Low",
                        info: "Info (not scored)",
                      }}
                    />
                  </Table.Cell>
                  <Table.Cell className="text-right tabular-nums">{num(c.evaluated)}</Table.Cell>
                  <Table.Cell className="text-right tabular-nums">
                    {c.failed ? (
                      <a
                        {...link(`/findings?check=${c.id}&status=all`)}
                        className="text-kumo-danger hover:underline"
                        title={`See the ${plural(c.failed, "finding")}${multi ? " in view" : ""}`}
                      >
                        {num(c.failed)}
                      </a>
                    ) : (
                      "0"
                    )}
                  </Table.Cell>
                  <Table.Cell className="text-right tabular-nums">
                    {c.evaluated ? pct((c.evaluated - c.failed) / c.evaluated) : <span className="text-kumo-subtle">Not run</span>}
                  </Table.Cell>
                  <Table.Cell>
                    <Switch aria-label={`Enable ${c.id}`} checked={!c.disabled} onCheckedChange={(v: boolean) => save(c, { disabled: !v })} />
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        ) : (
          <NoRows>No checks match.</NoRows>
        )}
      </ListCard>
    </Page>
  );
}
