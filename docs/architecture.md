# How it works

```mermaid
flowchart LR
  subgraph Cloudflare
    REST[REST API<br/>GET only]
    GQL[GraphQL analytics<br/>queries only]
  end
  subgraph Vercel
    VREST[REST API<br/>GET only]
  end
  DOH[Public DNS<br/>cloudflare-dns.com]
  HOSTS[Your hostnames<br/>takeover probe, optional]

  SCH[Scheduler<br/>daily or Run scan] --> SC[Scanner<br/>one account at a time]
  SC --> PROV[Provider<br/>src/providers]
  PROV --> INV[Cloudflare inventory<br/>inventory.ts, analytics.ts]
  PROV --> VINV[Vercel inventory<br/>providers/vercel]
  INV --> REST & GQL & DOH & HOSTS
  VINV --> VREST
  INV & VINV --> ENG[Engine<br/>check modules]
  ENG --> DB[(SQLite<br/>scans, findings,<br/>history, triage)]
  DB --> API[HTTP API<br/>Hono]
  API --> WEB[Web app<br/>React + Kumo]
  SC --> NOTIFY[Alerts<br/>Slack, webhooks]
```

## Providers

Every account belongs to one provider (Cloudflare or Vercel), recorded on the account. The scanner, the account
routes and the setup screen only talk to a provider through the `Provider` interface in `src/providers/types.ts`:
verify a token, list the accounts it reaches, probe what it can read, and scan an account. `src/providers/index.ts`
lists them. Cloudflare's code predates providers and lives in `src/core`, wrapped by `src/providers/cloudflare.ts`;
Vercel's lives in `src/providers/vercel/`, and new providers get their own folder the same way.

What every provider shares: the check-module format and evaluator (`src/core/checks/define.ts`), the categories,
fingerprints and scoring (`src/core/engine.ts`), storage, triage, alerts and the whole web app. The dashboard's scope
can be narrowed to one provider (`e:3@vercel`), and every scoped page follows it.

## A scan

The steps below are Cloudflare's; a Vercel scan reads teams, members, tokens, projects with their domains,
environment variable names and firewall, and the team's domains, certificates, drains and webhooks (about
four requests per project), then runs the same check, store and alert steps.

1. **Inventory.** For one account, Edgewatch reads everything the checks need into one typed `Inventory`:
   zones and their settings, DNS records, rulesets, certificates, members, tokens, Access, Gateway, Workers,
   R2, email routing and more, about 60 REST reads per account plus a few per zone. Every read is declared
   in `src/core/sources.ts` with the permission it needs; a read the token can't do is recorded as a coverage
   gap instead of failing the scan.
2. **Analytics.** GraphQL queries summarise the last 7 days of traffic: security actions, status codes,
   TLS versions, paths, leaked-credential checks, attack scores and more. Zones are batched by plan, since
   Free, Pro, Business and Enterprise expose different fields, and a field the plan can't read is dropped
   rather than failing the query.
3. **Checks.** Each module in `src/core/checks/` reads the inventory and reports pass or fail for every
   resource a check applies to. A check whose source couldn't be read is skipped, never passed.
4. **Store.** Findings get a stable fingerprint (check, account, zone, resource), so the same problem is
   the same finding from scan to scan. That's what carries triage, "first seen", "resolved" and "reopened"
   across scans.
5. **Alert.** New findings at or above the chosen severity, and findings that came back after being fixed,
   go to each entity's Slack channel or webhook.

The scanner never changes anything: REST calls are GET, GraphQL is POST but only ever queries, and
`test/integration.test.ts` (Cloudflare) and `test/vercel.test.ts` (Vercel) fail on any other request.

## Checks that span providers

Some problems only show when a company's Cloudflare and Vercel accounts are compared, for example a Cloudflare
DNS record that points at Vercel when no Vercel project in the company serves that hostname. Each scan stores a
few `links` in its snapshot (Cloudflare: its DNS records that point at Vercel; Vercel: the domains its projects
serve). When an account is scanned, the scanner gathers the links from the latest scans of the other accounts
in the same entity and passes them to the checks as `related`. These checks (IDs `XP-…`) never look outside the
entity, and are skipped when the entity has no scanned account on the other provider.

## Scoring

Every evaluation is pass or fail, weighted by severity (critical 10, high 6, medium 3, low 1). A category's
score is the weighted share of passing evaluations, and the posture score is the average of the categories,
so a category with thousands of DNS records can't drown out one with three notification checks. With several
accounts in view, the score is the average of the accounts' scores. Accepted risks and false positives don't
count against it.

## Triage and history

Triage (status, owner, due date, note, accepted-until) belongs to the fingerprint, not to a scan, so it
survives rescans. Every change is recorded in `triage_events`; together with which scans reported the
finding, that gives each finding its timeline and draws the lanes on the **Triaged** page. Accepted risk
reads as open again after its expiry date.

## Code layout

```
src/
  bin.ts, cli.ts        the edgewatch command: Node.js version check, then the command line
  main.ts               start(), which wires everything up
  core/                 Cloudflare's client, inventory and checks, and the engine every provider shares
    sources.ts          every Cloudflare data source: label, token permission, setup-screen probe
    cloudflare.ts       read-only API client: retries, rate limits, pagination, coverage
    inventory.ts        one scan's REST reads; analytics.ts holds the GraphQL reads
    checks/             check modules, one file per area, registered in checks/index.ts
    engine.ts           runs the modules, de-duplicates, fingerprints, scores
  providers/            the Provider interface, the registry, Cloudflare's adapter and the full check catalog
    vercel/             Vercel: read-only client, sources, inventory, checks, views, token checks
  store/                SQLite: migrations (db.ts) and one repository per concern
  server/               Hono app: routes/, guards, validation, presentation
  shared/               API types and logic shared with the web app (no Node, no DOM)
web/src/                React app: routes.tsx lists every page
dev/mock/               mocked Cloudflare and Vercel APIs, for tests and `npm run dev -- --mock`
scripts/                dev runner, and the generator for docs/checks.md and docs/permissions.md
test/                   node:test suites
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to add a check.
