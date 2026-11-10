// AWS regions: what runs in each, whether GuardDuty watches it, and its open
// findings, one row per region plus one for the account's global resources (IAM,
// S3, CloudFront, Route 53). The AWS counterpart of Zones and Projects.

import { Badge, Input, Switch, Table } from "@cloudflare/kumo";
import { useScopedApi, useShell } from "../shell.tsx";
import { link, num, plural, SCORED_SEVERITIES, setParams, totalScored, useLocation, type RegionRow, type RegionsResponse } from "../lib.ts";
import { Flag, ListCard, NoRows, Page, PageState, SeverityBadge, unreadableText } from "../components/ui.tsx";

const TITLE = "Regions";
const DESCRIPTION = "Every enabled AWS region: what runs there, whether GuardDuty is on, and its open findings. Global holds IAM, S3, CloudFront and Route 53.";

const used = (r: RegionRow) => r.resources.reduce((n, x) => n + x.count, 0);

export function RegionsPage() {
  const { multi } = useShell();
  const { params } = useLocation();
  const { data, error, loading, reload } = useScopedApi<RegionsResponse>("/api/regions");
  if (error || !data?.scan || !data.regions) {
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={data?.scan ? unreadableText(data.coverage, "regions", "regions") : undefined}
      />
    );
  }
  const q = (params.get("q") || "").toLowerCase();
  const issuesOnly = params.get("issues") === "1";
  const regions = data.regions
    .filter((r) => (!q || `${r.name} ${r.account || ""}`.toLowerCase().includes(q)) && (!issuesOnly || totalScored(r.findings) > 0))
    .sort((a, b) => totalScored(b.findings) - totalScored(a.findings) || used(b) - used(a) || a.name.localeCompare(b.name));

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <ListCard
        toolbar={
          <>
            <Input
              className="w-full min-w-48 sm:w-72"
              aria-label="Search regions"
              placeholder="Search regions"
              value={params.get("q") || ""}
              onChange={(e) => setParams({ q: e.target.value || null })}
            />
            <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
              <Switch
                aria-label="Only regions with open findings"
                checked={issuesOnly}
                onCheckedChange={(v: boolean) => setParams({ issues: v ? "1" : null })}
              />
              <span aria-hidden>Only regions with open findings</span>
            </span>
          </>
        }
        footer={
          <span>
            {regions.length === data.regions.length ? plural(data.regions.length, "row") : `${num(regions.length)} of ${plural(data.regions.length, "row")}`} ·
            most findings first
          </span>
        }
      >
        {!regions.length ? (
          <NoRows>No regions match.</NoRows>
        ) : (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head sticky="left">Region</Table.Head>
                <Table.Head>Resources</Table.Head>
                <Table.Head className="whitespace-nowrap">GuardDuty</Table.Head>
                <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {regions.map((r) => {
                // Findings record the region as their zone; the account is part of the link, as accounts share region names.
                const href = `/findings?zone=${encodeURIComponent(r.name)}${r.accountId ? `&account=${r.accountId}` : ""}&status=all`;
                const present = r.resources.filter((x) => x.count > 0);
                return (
                  <Table.Row key={`${r.accountId}/${r.name}`}>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <a className="text-kumo-link hover:underline" {...link(href)}>
                        {r.name}
                      </a>
                      {multi && <div className="max-w-80 truncate text-sm text-kumo-subtle">{r.account}</div>}
                    </Table.Cell>
                    <Table.Cell>
                      {r.skipped ? (
                        <span className="inline-flex items-center gap-2">
                          <Badge variant="warning">Not readable</Badge>
                          <span className="text-sm text-kumo-subtle">AWS refused the access key here, so nothing in this region was checked.</span>
                        </span>
                      ) : present.length ? (
                        <span className="flex max-w-xl flex-wrap gap-x-4 gap-y-1">
                          {present.map((x) => (
                            <span key={x.label} className="whitespace-nowrap text-kumo-subtle">
                              {x.label} <span className="tabular-nums text-kumo-default">{num(x.count)}</span>
                            </span>
                          ))}
                        </span>
                      ) : (
                        <span className="text-kumo-subtle">Nothing found</span>
                      )}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap">
                      <Flag value={r.guardDuty} />
                    </Table.Cell>
                    <Table.Cell>
                      <div className="flex items-center gap-3 whitespace-nowrap">
                        {SCORED_SEVERITIES.filter((s) => r.findings[s]).map((s) => (
                          <span key={s} className="inline-flex items-center gap-1.5">
                            <SeverityBadge severity={s} />
                            <span className="tabular-nums text-kumo-subtle">{r.findings[s]}</span>
                          </span>
                        ))}
                        {!SCORED_SEVERITIES.some((s) => r.findings[s]) && <span className="text-kumo-subtle">None</span>}
                      </div>
                    </Table.Cell>
                  </Table.Row>
                );
              })}
            </Table.Body>
          </Table>
        )}
      </ListCard>
    </Page>
  );
}
