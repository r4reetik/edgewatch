import { Badge, Table } from "@cloudflare/kumo";
import { useScopedApi, useShell } from "../shell.tsx";
import { compact, num, pct, plural, type ValueResponse } from "../lib.ts";
import { Aside, Flag, ListCard, NoRows, Page, PageState, Row, Stat, unreadableText } from "../components/ui.tsx";

const PAID_FEATURES = new Set(["Managed WAF", "OWASP ruleset", "Image optimization (Polish)"]);
const TITLE = "Value";
const DESCRIPTION = "What you pay Cloudflare for, what it delivers, and capabilities your plans include that are switched off.";

const money = (n: number, cur = "USD") => new Intl.NumberFormat("en-US", { style: "currency", currency: cur, maximumFractionDigits: n % 1 ? 2 : 0 }).format(n);
const BILLING: Record<string, string> = { monthly: "Monthly", yearly: "Yearly", quarterly: "Quarterly" };

export function ValuePage() {
  const { multi } = useShell();
  const { data, error, loading, reload } = useScopedApi<ValueResponse>("/api/value");
  if (error || !data?.scan || !data.value)
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={data?.scan ? unreadableText(data.coverage, "subscriptions", "plan and usage data") : undefined}
      />
    );

  const v = data.value,
    c = v.counts;
  const features = Object.keys(v.zones[0]?.features || {});
  const unused = features
    .map((feat) => ({ feat, zones: v.zones.filter((z) => z.features[feat] === false), paid: PAID_FEATURES.has(feat) }))
    .filter((u) => u.zones.length)
    .sort((a, b) => Number(b.paid) - Number(a.paid) || b.zones.length - a.zones.length);
  const cachedShare = c.requests30d ? (c.cachedRequests30d || 0) / (c.requests30d as number) : null;
  const subs = [...v.subscriptions].sort((a, b) => b.price - a.price);

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <Row cols={4}>
        <Stat
          label="Subscriptions per month"
          value={money(v.monthly)}
          note={`${plural(v.subscriptions.filter((s) => s.price > 0).length, "paid subscription")}, list price`}
        />
        <Stat label="Requests served (30 days)" value={compact(c.requests30d)} note={`${pct(cachedShare)} served from cache`} />
        <Stat label="Threats stopped (30 days)" value={compact(c.threats30d)} note="Blocked or challenged by Cloudflare" />
        <Stat label="Zones" value={num(c.zones)} note={`${num(c.paidZones)} paid · ${num(c.tunnels)} tunnels · ${num(c.workers)} Workers`} />
      </Row>

      <ListCard
        title="Included but switched off"
        actions={<Aside>No extra cost on your current plans</Aside>}
        footer={<span>{plural(unused.length, "capability", "capabilities")}</span>}
      >
        {unused.length ? (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>Capability</Table.Head>
                <Table.Head>Type</Table.Head>
                <Table.Head>Off on</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {unused.map((u) => (
                <Table.Row key={u.feat}>
                  <Table.Cell className="whitespace-nowrap font-medium">{u.feat}</Table.Cell>
                  <Table.Cell>{u.paid ? <Badge variant="orange">Paid plan feature</Badge> : <Badge variant="neutral">Included</Badge>}</Table.Cell>
                  <Table.Cell className="text-kumo-subtle">{u.zones.map((z) => z.name).join(", ")}</Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        ) : (
          <NoRows>Everything available is in use.</NoRows>
        )}
      </ListCard>

      <ListCard
        title="Subscriptions"
        footer={
          <>
            <span>{plural(subs.length, "subscription")}</span>
            <span className="font-medium text-kumo-default">{money(v.monthly)} per month</span>
          </>
        }
      >
        {subs.length ? (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>Product</Table.Head>
                {multi && <Table.Head>Account</Table.Head>}
                <Table.Head>Applies to</Table.Head>
                <Table.Head>Billing</Table.Head>
                <Table.Head className="text-right">Price</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {subs.map((s, i) => (
                <Table.Row key={i}>
                  <Table.Cell>{s.name}</Table.Cell>
                  {multi && <Table.Cell className="max-w-48 truncate text-kumo-subtle">{s.account}</Table.Cell>}
                  <Table.Cell className="text-kumo-subtle">{s.zone || "Account"}</Table.Cell>
                  <Table.Cell className="text-kumo-subtle">{BILLING[s.frequency] || "—"}</Table.Cell>
                  <Table.Cell className="text-right tabular-nums">{s.price ? money(s.price, s.currency) : "Free"}</Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        ) : (
          <NoRows>Grant Billing read access to see subscriptions.</NoRows>
        )}
      </ListCard>

      <ListCard title="Feature use by zone" footer={<span>{plural(v.zones.length, "zone")}</span>}>
        <Table layout="auto">
          <Table.Header variant="compact">
            <Table.Row>
              <Table.Head sticky="left">Zone</Table.Head>
              <Table.Head className="text-right">Requests</Table.Head>
              <Table.Head className="text-right">Threats</Table.Head>
              <Table.Head className="text-right">Cached</Table.Head>
              {features.map((f) => (
                <Table.Head key={f} className="whitespace-nowrap">
                  {f}
                </Table.Head>
              ))}
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {v.zones.map((z) => (
              <Table.Row key={`${z.accountId}/${z.name}`}>
                <Table.Cell sticky="left" className="whitespace-nowrap">
                  {z.name}
                  <div className="text-sm text-kumo-subtle">
                    {multi && `${z.account} · `}
                    {z.plan}
                  </div>
                </Table.Cell>
                <Table.Cell className="text-right tabular-nums">{compact(z.requests)}</Table.Cell>
                <Table.Cell className="text-right tabular-nums">{compact(z.threats)}</Table.Cell>
                <Table.Cell className="text-right tabular-nums">{pct(z.cached)}</Table.Cell>
                {features.map((f) => (
                  <Table.Cell key={f}>
                    <Flag value={z.features[f]} on="In use" off="Off" />
                  </Table.Cell>
                ))}
              </Table.Row>
            ))}
          </Table.Body>
        </Table>
      </ListCard>
    </Page>
  );
}
