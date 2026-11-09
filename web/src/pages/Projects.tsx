// Vercel projects: who can open their deployments, the firewall, how secrets are
// stored, and open findings, one row per project. The Vercel counterpart of Zones.

import { Input, Switch, Table } from "@cloudflare/kumo";
import { useScopedApi, useShell } from "../shell.tsx";
import { link, num, plural, SCORED_SEVERITIES, setParams, totalScored, useLocation, type ProjectRow, type ProjectsResponse } from "../lib.ts";
import { Flag, ListCard, NoRows, Page, PageState, SeverityBadge, unreadableText } from "../components/ui.tsx";

const TITLE = "Projects";
const DESCRIPTION = "Every Vercel project: who can open its deployments, whether the firewall runs, and how its secrets are stored.";

const RULESET: Record<string, string> = { bot_protection: "Bots", ai_bots: "AI bots", owasp: "OWASP", vercel_ruleset: "Vercel", traffic_sources: "Sources" };

export function ProjectsPage() {
  const { multi } = useShell();
  const { params } = useLocation();
  const { data, error, loading, reload } = useScopedApi<ProjectsResponse>("/api/projects");
  if (error || !data?.scan || !data.projects) {
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={data?.scan ? unreadableText(data.coverage, "projects", "projects") : undefined}
      />
    );
  }
  const q = (params.get("q") || "").toLowerCase();
  const issuesOnly = params.get("issues") === "1";
  const projects = data.projects
    .filter((p) => (!q || `${p.name} ${p.account || ""} ${p.domains.join(" ")}`.toLowerCase().includes(q)) && (!issuesOnly || totalScored(p.findings) > 0))
    .sort((a, b) => totalScored(b.findings) - totalScored(a.findings) || a.name.localeCompare(b.name));

  const cols: [string, (p: ProjectRow) => React.ReactNode][] = [
    ["Previews", (p) => <Flag value={p.previews !== "Public"} on={p.previews} off="Public" />],
    ["*.vercel.app URLs", (p) => <Flag value={p.productionUrls !== "Public"} on="Protected" off="Public" warn={p.domains.length === 0} />],
    ["Fork protection", (p) => <Flag value={p.gitForkProtection} na="No Git" />],
    ["Firewall", (p) => <Flag value={p.firewall} />],
    [
      "Managed rules",
      (p) => (
        <Flag value={p.managedRules == null ? null : p.managedRules.length > 0} on={p.managedRules?.map((r) => RULESET[r] ?? r).join(", ")} off="None" warn />
      ),
    ],
    [
      "Sensitive variables",
      (p) => (
        <Flag
          value={p.envVars == null ? null : p.envVars === 0 || p.sensitiveEnvVars === p.envVars}
          on={p.envVars ? `All ${num(p.envVars)}` : "None"}
          off={`${num(p.sensitiveEnvVars || 0)} of ${num(p.envVars || 0)}`}
          warn
        />
      ),
    ],
    ["Node.js", (p) => <span className="text-kumo-default">{p.nodeVersion || "—"}</span>],
  ];

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <ListCard
        toolbar={
          <>
            <Input
              className="w-full min-w-48 sm:w-72"
              aria-label="Search projects"
              placeholder="Search projects or domains"
              value={params.get("q") || ""}
              onChange={(e) => setParams({ q: e.target.value || null })}
            />
            <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
              <Switch
                aria-label="Only projects with open findings"
                checked={issuesOnly}
                onCheckedChange={(v: boolean) => setParams({ issues: v ? "1" : null })}
              />
              <span aria-hidden>Only projects with open findings</span>
            </span>
          </>
        }
        footer={
          <span>
            {projects.length === data.projects.length
              ? plural(data.projects.length, "project")
              : `${num(projects.length)} of ${plural(data.projects.length, "project")}`}{" "}
            · most findings first
          </span>
        }
      >
        {!projects.length ? (
          <NoRows>No projects match.</NoRows>
        ) : (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head sticky="left">Project</Table.Head>
                {cols.map(([t]) => (
                  <Table.Head key={t} className="whitespace-nowrap">
                    {t}
                  </Table.Head>
                ))}
                <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {projects.map((p) => {
                // Findings record the project as their zone; the account is part of the link, as two teams can share a project name.
                const href = `/findings?zone=${encodeURIComponent(p.name)}${p.accountId ? `&account=${p.accountId}` : ""}&status=all`;
                return (
                  <Table.Row key={`${p.accountId}/${p.id}`}>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <a className="text-kumo-link hover:underline" {...link(href)}>
                        {p.name}
                      </a>
                      <div className="max-w-80 truncate text-sm text-kumo-subtle">
                        {multi && `${p.account} · `}
                        {[p.framework, p.domains.filter((d) => !d.endsWith(".vercel.app")).join(", ") || "No custom domain"].filter(Boolean).join(" · ")}
                      </div>
                    </Table.Cell>
                    {cols.map(([t, fn]) => (
                      <Table.Cell key={t} className="whitespace-nowrap">
                        {fn(p)}
                      </Table.Cell>
                    ))}
                    <Table.Cell>
                      <div className="flex items-center gap-3 whitespace-nowrap">
                        {SCORED_SEVERITIES.filter((s) => p.findings[s]).map((s) => (
                          <span key={s} className="inline-flex items-center gap-1.5">
                            <SeverityBadge severity={s} />
                            <span className="tabular-nums text-kumo-subtle">{p.findings[s]}</span>
                          </span>
                        ))}
                        {!SCORED_SEVERITIES.some((s) => p.findings[s]) && <span className="text-kumo-subtle">None</span>}
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
