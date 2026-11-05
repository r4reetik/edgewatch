import { Input, Switch, Table } from "@cloudflare/kumo";
import { useScopedApi, useShell } from "../shell.tsx";
import { compact, link, num, plural, SCORED_SEVERITIES, setParams, totalScored, useLocation, type ZoneRow, type ZonesResponse } from "../lib.ts";
import { Flag, ListCard, NoRows, Page, PageState, SeverityBadge, unreadableText } from "../components/ui.tsx";
import { OLD_TLS, WEAK_SECURITY_LEVELS } from "../../../src/core/cf-constants.ts";
type Zone = ZoneRow;

const TITLE = "Zones";
const DESCRIPTION = "Baseline security settings for every zone. Edge settings only apply to zones that proxy traffic through Cloudflare.";

export function ZonesPage() {
  const { multi } = useShell();
  const { params } = useLocation();
  const { data, error, loading, reload } = useScopedApi<ZonesResponse>("/api/zones");
  if (error || !data?.scan || !data.zones) {
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={data?.scan ? unreadableText(data.coverage, "zones", "zones") : undefined}
      />
    );
  }
  const q = (params.get("q") || "").toLowerCase();
  const issuesOnly = params.get("issues") === "1";
  const zones = data.zones
    .filter((z) => (!q || `${z.name} ${z.account || ""}`.toLowerCase().includes(q)) && (!issuesOnly || totalScored(z.findings) > 0))
    .sort((a, b) => totalScored(b.findings) - totalScored(a.findings) || a.name.localeCompare(b.name));

  const edge = (z: Zone, node: React.ReactNode) => (z.proxiedZone ? node : <Flag value={null} na="DNS only" />);
  const paid = (z: Zone, v: boolean | "n/a" | null) => (v === "n/a" ? <Flag value={null} na="Free plan" /> : edge(z, <Flag value={v} />));
  const cols: [string, (z: Zone) => React.ReactNode][] = [
    ["SSL mode", (z) => edge(z, <Flag value={z.ssl === "strict"} warn={z.ssl === "full"} on="Full (strict)" off={z.ssl === "full" ? "Full" : z.ssl || "—"} />)],
    ["Min TLS", (z) => edge(z, <Flag value={!OLD_TLS.includes(z.minTls || "")} on={z.minTls || "—"} off={z.minTls || "—"} />)],
    ["Always HTTPS", (z) => edge(z, <Flag value={z.alwaysHttps == null ? null : z.alwaysHttps === "on"} />)],
    ["HSTS", (z) => edge(z, <Flag value={z.hsts} />)],
    ["TLS 1.3", (z) => edge(z, <Flag value={z.tls13 == null ? null : z.tls13 !== "off"} />)],
    [
      "DNSSEC",
      (z) => (
        <Flag
          value={z.dnssec == null ? null : z.dnssec === "active"}
          on="Active"
          off={z.dnssec === "pending" ? "Pending DS" : "Off"}
          warn={z.dnssec === "pending"}
        />
      ),
    ],
    ["CAA", (z) => <Flag value={z.caa} on="Yes" off="None" />],
    ["Managed WAF", (z) => paid(z, z.wafManaged)],
    ["OWASP", (z) => paid(z, z.owasp)],
    [
      "Rate limits",
      (z) => edge(z, <Flag value={z.rateLimitRules == null ? null : z.rateLimitRules > 0} on={plural(z.rateLimitRules || 0, "rule")} off="None" />),
    ],
    ["Bot protection", (z) => edge(z, <Flag value={z.botProtection} />)],
    [
      "AI crawlers",
      (z) =>
        edge(
          z,
          <Flag value={z.aiBots == null ? null : z.aiBots === "block"} on="Blocked" off={z.aiBots === "only_on_ad_pages" ? "Ad pages only" : "Allowed"} warn />,
        ),
    ],
    [
      "Security level",
      (z) =>
        edge(
          z,
          <Flag
            value={z.securityLevel == null ? null : !WEAK_SECURITY_LEVELS.includes(z.securityLevel)}
            on={cap(z.securityLevel)}
            off={cap(z.securityLevel)}
          />,
        ),
    ],
    ["Page Shield", (z) => edge(z, <Flag value={z.pageShield} />)],
    ["Leaked creds", (z) => edge(z, <Flag value={z.leakedCredentials} />)],
  ];

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <ListCard
        toolbar={
          <>
            <Input
              className="w-full min-w-48 sm:w-72"
              aria-label="Search zones"
              placeholder="Search zones"
              value={params.get("q") || ""}
              onChange={(e) => setParams({ q: e.target.value || null })}
            />
            <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
              <Switch aria-label="Only zones with open findings" checked={issuesOnly} onCheckedChange={(v: boolean) => setParams({ issues: v ? "1" : null })} />
              <span aria-hidden>Only zones with open findings</span>
            </span>
          </>
        }
        footer={
          <span>
            {zones.length === data.zones.length ? plural(data.zones.length, "zone") : `${num(zones.length)} of ${plural(data.zones.length, "zone")}`} · most
            findings first
          </span>
        }
      >
        {!zones.length ? (
          <NoRows>No zones match.</NoRows>
        ) : (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head sticky="left">Zone</Table.Head>
                <Table.Head className="text-right whitespace-nowrap">Requests (30d)</Table.Head>
                <Table.Head className="text-right whitespace-nowrap">Threats (30d)</Table.Head>
                {cols.map(([t]) => (
                  <Table.Head key={t} className="whitespace-nowrap">
                    {t}
                  </Table.Head>
                ))}
                <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {zones.map((z) => {
                // The account is part of the link: two accounts can have zones with the same name.
                const href = `/findings?zone=${encodeURIComponent(z.name)}${z.accountId ? `&account=${z.accountId}` : ""}&status=all`;
                return (
                  <Table.Row key={`${z.accountId}/${z.name}`}>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <a className="text-kumo-link hover:underline" {...link(href)}>
                        {z.name}
                      </a>
                      <div className="text-sm text-kumo-subtle">
                        {multi && `${z.account} · `}
                        {z.planName} · {num(z.records)} records, {num(z.proxied)} proxied
                      </div>
                    </Table.Cell>
                    <Table.Cell className="text-right tabular-nums">{compact(z.traffic?.requests)}</Table.Cell>
                    <Table.Cell className="text-right tabular-nums">{compact(z.traffic?.threats)}</Table.Cell>
                    {cols.map(([t, fn]) => (
                      <Table.Cell key={t} className="whitespace-nowrap">
                        {fn(z)}
                      </Table.Cell>
                    ))}
                    <Table.Cell>
                      <div className="flex items-center gap-3 whitespace-nowrap">
                        {SCORED_SEVERITIES.filter((s) => z.findings[s]).map((s) => (
                          <span key={s} className="inline-flex items-center gap-1.5">
                            <SeverityBadge severity={s} />
                            <span className="tabular-nums text-kumo-subtle">{z.findings[s]}</span>
                          </span>
                        ))}
                        {!SCORED_SEVERITIES.some((s) => z.findings[s]) && <span className="text-kumo-subtle">None</span>}
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

const cap = (s: string | null) => (s ? (s[0].toUpperCase() + s.slice(1)).replace(/_/g, " ") : "—");
