<p align="center">
  <img src="docs/images/logo.svg" width="72" height="72" alt="">
</p>

<h1 align="center">Edgewatch</h1>

<p align="center">
  <strong>Security posture tracking for Cloudflare and Vercel.</strong><br>
  Read-only checks across DNS, WAF, TLS, Zero Trust, email, live traffic, deployments and secrets, and a place to triage every finding until it's fixed.
</p>

<p align="center">
  <a href="https://github.com/r4reetik/edgewatch/actions/workflows/ci.yml"><img src="https://github.com/r4reetik/edgewatch/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/r4reetik/edgewatch/actions/workflows/codeql.yml"><img src="https://github.com/r4reetik/edgewatch/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://www.npmjs.com/package/edgewatch"><img src="https://img.shields.io/npm/v/edgewatch" alt="npm"></a>
  <a href="https://github.com/r4reetik/edgewatch/pkgs/container/edgewatch"><img src="https://img.shields.io/badge/docker-ghcr.io-2496ED?logo=docker&logoColor=white" alt="Docker"></a>
  <img src="https://img.shields.io/node/v/edgewatch" alt="Node.js">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/r4reetik/edgewatch" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="docs/checks.md">All checks</a> ·
  <a href="docs/permissions.md">Permissions</a> ·
  <a href="docs/deployment.md">Deployment</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/overview-dark.png">
  <img src="docs/images/overview.png" alt="The Edgewatch overview: attack paths, posture score, overdue and unowned findings, and the findings to fix first">
</picture>

Point Edgewatch at your Cloudflare accounts, your Vercel teams, or both, and it scans them (one, or dozens
across several companies), scores them, and tracks every finding until it's fixed: who owns it, when it's due,
and which risks were accepted and until when. It runs on your machine or your server, and only ever reads.
Use it for Cloudflare alone, Vercel alone, or both: a company's accounts on both platforms sit together in
one entity, and checks that span the two catch what neither dashboard shows.

> Edgewatch is an independent open-source project, not affiliated with or endorsed by Cloudflare or Vercel.
> Its interface is built with [Kumo](https://github.com/cloudflare/kumo), Cloudflare's open-source design system.

## Quick start

```bash
npx edgewatch@latest
```

That's the whole install. A browser tab opens, you choose Cloudflare or Vercel, paste a token, pick the
accounts or teams it should scan, and the first scans run. It needs Node.js 26 LTS; on an older one it says how to upgrade. To run it for a team, use
[Docker](#run-it-for-a-team-docker).

## What it checks

### Cloudflare

Its own checks, plus every insight from Cloudflare Security Center, imported and
de-duplicated against those checks. Many of them correlate data that no single Cloudflare
screen shows together, so they find problems a settings review or Security Center won't. Some go
further and check configuration against the last week of traffic from Cloudflare's analytics:
managed rules that log attacks without blocking them, `.env` files being served, plain-HTTP APIs.

| Area | Examples |
|---|---|
| Attack surface | Proxied origins whose IP is published by another record, SPF or MX; origins reachable without Cloudflare; admin tools (Grafana, n8n, Jenkins…) with no Access in front; tunnels or Spectrum publishing SSH or RDP; subdomain takeovers confirmed with a live check; lame NS delegations |
| Traffic | From the last 7 days of analytics: managed rules overridden to log while matching attacks, attack-scored requests answered, leaked-password logins not stopped, `.env` or `/.git/` served, plain HTTP, TLS 1.0 clients, rules that never match, bots on login pages |
| Identity & access | Members without 2FA, too many Super Administrators, external members, 2FA not enforced; account API tokens with no IP restriction, no expiry, unused, or write access to every zone |
| Zero Trust | Access groups or policies open to everyone or a webmail domain, leaked service tokens, CORS with credentials, one-time PIN beside SSO, Gateway without TLS inspection or logging, WARP that users can switch off, broad private routes, outdated cloudflared, idle seats |
| TLS & HTTPS | SSL mode below Full (strict), TLS 1.0/1.1 (zone or per hostname), no HSTS, legacy ciphers, proxied hostnames no certificate covers, expiring edge, Origin CA, custom, client and mTLS certificates |
| WAF & bots | Managed rules not deployed or switched to log-only, exceptions keyed on a header anyone can send, IP Access allowlists for whole countries or networks, weakened DDoS protection, mTLS that nothing enforces, URL normalization off, malicious scripts found by Page Shield, secrets hard-coded in transform rules |
| DNS | Hostnames pointing at deleted tunnels, dangling CNAMEs to cloud resources (takeover risk), private IPs, stale records, DNS-only load balancers handing out origin IPs, DNSSEC off, no CAA |
| Email | Missing or permissive SPF, DMARC not enforcing, SPF over 10 lookups, weak DKIM keys, DMARC reports silently dropped, no MTA-STS, catch-all forwarding, failing senders in DMARC reports |
| Platform | Workers reachable on workers.dev, public R2 buckets, R2 CORS open to any site, credentials in plain-text Worker or Pages variables, public Pages previews |
| Monitoring | Missing notifications, failing Logpush jobs, insecure or failing alert webhooks, Access apps rejecting thousands of logins |
| Change risk | In the last 7 days: security rules turned off, Access policies widened, zone security settings lowered (who and when, from the audit log) |
| Cost & usage | Paid plans on zones with almost no traffic |

### Vercel

Teams on any plan, and personal (Hobby) accounts. Edgewatch reads environment variable names and types,
never their values.

| Area | Examples |
|---|---|
| Deployments | Preview deployments open to anyone, *.vercel.app production URLs that skip the custom domain, pull requests from forks deploying with your secrets, protection bypass secrets, deploy hooks, cron jobs anyone can trigger, previews that never expire |
| Secrets | Secrets Vercel itself flags as readable, keys and tokens stored as plain text, secrets with a `NEXT_PUBLIC_`/`VITE_` prefix shipped to browsers, production secrets shared with previews or downloaded to laptops by `vercel env pull`, credentials written into build commands, team-wide shared variables, no Sensitive policy on the team |
| Identity & access | SAML SSO or two-factor authentication not required, too many Owners, members outside company domains who can deploy, open invitations and requests to join, integrations that can change every project, access tokens that leaked, never expire or sit unused, the global OIDC issuer |
| WAF & bots | Firewall off, bot protection off on public sites, OWASP rules left in log mode, wide IP ranges that bypass the firewall, no rate limiting |
| DNS, TLS & monitoring | Domains about to lapse with auto-renew off, unverified project domains, expiring custom certificates, log drains writing public S3 objects or sending over HTTP, failing drains |
| Platform | Node.js versions past end of life, production builds over a year old, directory listing, public source maps, projects deployed outside Git |

### Across providers

Checks that compare a company's Cloudflare and Vercel accounts in the same entity: a Cloudflare DNS record
that points at Vercel but no Vercel project serves (anyone could claim it), a Vercel site proxied through
Cloudflare whose *.vercel.app URLs skip Cloudflare's WAF, and Vercel sites behind Cloudflare's proxy.

Every check, with why it matters and how to fix it, is listed in [docs/checks.md](docs/checks.md).

Each finding explains why it matters, how to fix it, and the evidence behind it, step by step. It links
to the right page in the Cloudflare or Vercel dashboard. Findings from heuristics (name patterns, sampled analytics)
and traffic are marked **Likely**, and ones a live check confirmed are marked **Confirmed**. A finding that
was fixed and came back is marked **Reopened**. Every check links to the provider's documentation, and every
finding has its own page with a history of each scan and triage change, to share by link.

## What you get

<table>
  <tr>
    <td width="50%"><img src="docs/images/findings.png" alt="Findings grouped by check, with status tabs, filters and owners"></td>
    <td width="50%"><img src="docs/images/finding.png" alt="A finding with its evidence, fix steps and triage panel"></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/images/triaged.png" alt="The Triaged page: each finding's current state and a lane showing how it moved over time"></td>
    <td width="50%"><img src="docs/images/accounts.png" alt="Accounts grouped into entities, with scores and daily scan switches"></td>
  </tr>
</table>

- **Overview.** Attack paths first, then the score, what's critical, overdue and unowned, the problems to fix first (one row per check, however many places it appears), what changed since the last scan, trends and category scores. With several accounts in view, a table ranks them by score; with Cloudflare and Vercel in view, each gets its own score too.
- **Findings.** Tabs for open, overdue, unowned and new findings; filter, search, sort, and group by check, zone or account. Triage one at a time (J and K move through the list) or in bulk, changing only the fields you pick: status, owner (suggested from the owners already in the entity), due date, note. Accepted risk takes an expiry date and reopens when it lapses. Each severity has an SLA, and findings past it are flagged overdue. Exports contain exactly what the list shows.
- **Triaged.** Everything you've triaged in one place: where each finding stands now, a lane showing how its status moved over time (including when a scan stopped finding it), and a feed of every change.
- **Zones** (Cloudflare). A settings grid for every zone: TLS, HSTS, DNSSEC, WAF, rate limits, bots and more.
- **Projects** (Vercel). Every project: who can open its previews and *.vercel.app URLs, fork protection, the firewall and its managed rules, how many secrets are Sensitive.
- **Activity** (Cloudflare). Seven days of audit log, filtered down to changes, with destructive actions highlighted.
- **Value** (Cloudflare). What you pay for, the traffic and threats it handled, and features your plans include but that are switched off.
- **Audit report.** A print-ready report for auditors and management (use the browser's Save as PDF). Findings also export as CSV and JSON.
- **Daily scans and alerts.** Posts new findings at or above a chosen severity to Slack or any webhook.
- **Check tuning.** Disable checks that don't apply, or override their severity.

## Several accounts and companies

Edgewatch watches as many Cloudflare accounts and Vercel teams as you add, from one token or many. Accounts are
grouped into **entities**: a company, legal entity or team that owns them. An entity can hold accounts on both
platforms. You decide how they're shown, and can
change it at any time on the **Accounts** page:

- **Pick the view.** The switcher in the top bar shows one account, one entity, or **All accounts**. Beside it,
  the provider switch narrows the view to Cloudflare or Vercel when both are in it. Every page, the score, the
  audit report and the exports follow them. Links in alerts open the right account.
- **Keep companies apart.** Turn off **Show in All accounts** for an entity and its accounts never appear in the
  combined view or its report; they're only shown when that entity or account is chosen. Entities that belong
  together stay combined.
- **Per-entity settings.** Each entity has its own company email domains (so a member from a sister company
  isn't "external", but one from an unrelated company is) and its own Slack channel or webhook, so alerts
  never cross between companies.
- **Arrange.** Rename accounts, move them between entities, reorder entities and accounts, and leave an
  account out of the daily scan.

Accounts are scanned one after another, each with its own token. When several accounts are in view, the
posture score is the average of the accounts' scores, so a small account counts as much as a large one.

## Create the tokens

### Cloudflare

In the Cloudflare dashboard, go to **My Profile → API Tokens → Create Token** and use the
**Read all resources** template. It covers every check and grants read access only. Include
the accounts you want to scan: one token can cover several accounts. Accounts that belong to
another company usually need their own token, created by someone with access to them.

If you'd rather grant the minimum, the setup screen has a pre-filled link with the read
permissions Cloudflare lets a link include, and lists the rest to add yourself. Setup checks the
token against every permission before you connect. Anything it can't read is listed with the
permission it needs, and the checks that depend on it are **skipped, never passed**
([full list](docs/permissions.md)). Two sources
need more than "Read all resources": account API tokens (Account API Tokens Read) and Logpush job
listings, which Cloudflare only exposes with a write permission; Edgewatch reads Logpush health
from analytics instead.

### Vercel

In Vercel, go to **Account Settings → Tokens** and create a token. Set its scope to the team to scan, or
**Full Account** for every team you belong to and your personal projects, and give it an expiration date.
Vercel tokens can't be limited to reading: a token can do what its user's role allows. Edgewatch only ever
sends GET requests to Vercel (a test fails on anything else) and never asks for environment variable values.
What each team role can read is in [docs/permissions.md](docs/permissions.md#vercel).

## Run it for a team (Docker)

```bash
docker run -d --name edgewatch -p 4317:4317 \
  -v edgewatch-data:/data \
  -e EDGEWATCH_PASSWORD='a-long-admin-password' \
  ghcr.io/r4reetik/edgewatch:0.7
```

Open it, sign in with the password, and add accounts in the browser. Tokens are stored in the volume.

The container listens on all interfaces, so it **refuses to start without a password**. If an
authenticating proxy such as Cloudflare Access already protects it, set `EDGEWATCH_AUTH=none`
instead. Behind a TLS-terminating proxy, also set `EDGEWATCH_TRUST_PROXY=1` so session cookies are
marked Secure. Data lives in `/data`; back up that volume. [docs/deployment.md](docs/deployment.md) covers
Compose, Cloudflare Access, reverse proxies, systemd and backups.

## Updating

Edgewatch tells you when a new version is out (in the sidebar and under **Settings → Updates**), with the
exact upgrade command and a warning when it has breaking changes. Releases follow semantic versioning in
**release lines** (`0.4`, `0.5`…; `1`, `2`… from 1.0): updates within a line never break anything, so it's
safe to take them automatically. The Docker tag `:0.7` above does exactly that; `npm install -g
edgewatch@0.7` is the npm equivalent. The database is backed up before every upgrade that changes it.
[docs/upgrading.md](docs/upgrading.md) has automatic updates, release candidates and rolling back.

## Configuration

| Flag | Environment | Default | |
|---|---|---|---|
| `--port` | `EDGEWATCH_PORT` | `4317` | Port to listen on |
| `--host` | `EDGEWATCH_HOST` | `127.0.0.1` | Address to bind. Anything but loopback requires a password |
| `--data-dir` | `EDGEWATCH_DATA_DIR` | `~/.edgewatch` | Database and stored tokens |
| `--password-file` | `EDGEWATCH_PASSWORD` | none | Admin password, at least 12 characters |
| `--trust-proxy` | `EDGEWATCH_TRUST_PROXY=1` | off | Trust `X-Forwarded-*` from your reverse proxy |
| `--no-open` | | | Don't open a browser |
| | `EDGEWATCH_AUTH=none` | | Allow no password on a network address (only behind an authenticating proxy) |
| | `EDGEWATCH_ALLOWED_HOSTS` | | Extra hostnames accepted in local mode, comma-separated |
| | `EDGEWATCH_LOG=json` | text | Log one JSON object per line |
| | `EDGEWATCH_UPDATE_CHECK=off` | on | Never check GitHub for new releases |

Schedule, retention, SLAs and the takeover probe are set in **Settings**. Accounts, entities, company
email domains and alert destinations are set on the **Accounts** page.

Upgrading from 0.2? The single account it scanned is imported into an entity on first start, with its
history, email domains and alert destinations.

## Security and privacy

- **Read-only.** The scanner only sends GET requests to Cloudflare and Vercel, and GraphQL analytics queries to Cloudflare (GraphQL is POST by design, and query-only). Tests run full scans of both and fail if any request is anything else. Vercel environment variables are listed without their values, and drain and webhook URLs are stored without their paths or secrets.
- **Local.** Findings and tokens stay in the data directory. The database, tokens and backups are readable by your user only, and so is the directory when Edgewatch creates it.
  Tokens live in `credentials.json`, apart from the database, which only holds a reference to each one.
- **Contained.**
  - Tokens are never sent to the browser or written to logs. Each account is only ever scanned with its own token.
  - Webhook URLs are write-only in the UI.
  - Outbound traffic goes to `api.cloudflare.com` and `api.vercel.com` (for the platforms you connect), to `cloudflare-dns.com` (public DNS lookups), to any webhook you configure, and to `api.github.com` shortly after start and then daily, to see if there's a newer release (no identifying data; turn it off in Settings or with `EDGEWATCH_UPDATE_CHECK=off`).
  - **Takeover check (on by default):** a `GET /` to each of your own hostnames that points at a cloud provider known for takeovers (S3, GitHub Pages, Heroku, Vercel, Azure…), over HTTPS and then HTTP if that fails, following at most two redirects on the same host. At most 100 hosts per scan, no cookies, the first 64 KB of the answer, and a User-Agent of `Edgewatch takeover check (+https://github.com/r4reetik/edgewatch)`. Turn it off under **Settings → Scans → Confirm subdomain takeovers** to keep every request inside Cloudflare's API.
  - There is no telemetry.
- **Hardened web app.**
  - In local mode, Host-header checks block DNS rebinding.
  - State-changing requests must be same-origin JSON, which blocks CSRF.
  - Strict CSP, framing blocked, and CSV exports are protected against formula injection.
  - Password mode uses scrypt, rate-limited login and HttpOnly SameSite=Strict cookies.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## How scoring works

Every check evaluates each resource it applies to as pass or fail. A category's score is the
severity-weighted share of passing evaluations (critical 10, high 6, medium 3, low 1). The posture
score is the average of the categories, so one category with thousands of DNS records can't drown
out another with three notification checks. With several accounts in view, the score is the average of the
accounts' scores. Accepted risks and false positives stop counting against the score. Security Center insights are listed alongside, since Security Center only reports failures.

DNS lookup counts come from Cloudflare's sampled analytics, so "no lookups in 30 days" means fewer
than roughly 20–30. Confirm with the record's owner before deleting anything.

## FAQ

**Can Edgewatch change anything in my account?** No. The scanner only sends GET requests (and, to Cloudflare,
GraphQL queries), and tests that run full scans fail the build if it ever sends anything else. Give Cloudflare a
read-only token; Vercel has no read-only tokens, so its token can do what its user's role allows, and Edgewatch
still only reads.

**Does any data leave my machine?** Only requests to the Cloudflare and Vercel APIs and public DNS, the optional takeover
check (one GET to your own hostnames that point at cloud providers), alerts to webhooks you configure, and the
update check.
The daily update check only reads GitHub's public list of releases. There's no telemetry, no account, and
no hosted service.

**How is this different from Cloudflare Security Center?** Security Center flags individual settings.
Edgewatch imports its insights, and adds checks that correlate sources Security Center doesn't combine (DNS
with tunnels with Access policies, rules with traffic analytics, the audit log with settings), plus a
workflow to track each finding to a fix across many accounts.

**Which plans does it support?** All of them, on both platforms. Checks for features a plan doesn't include are
skipped, and Cloudflare analytics queries adapt to what each zone's plan exposes.

**Which platforms are next?** Edgewatch is built so each platform is a provider behind one interface
(`src/providers`). AWS, Google Cloud and Google Workspace are the likely next ones.

**A finding is wrong. What do I do?** Mark it **False positive** in its triage panel so it stops counting,
and please [report it](https://github.com/r4reetik/edgewatch/issues/new?template=false_positive.yml).
Wrong findings are the most useful bug reports we get.

## Roadmap

Alerts before accepted risks expire, comments on findings, ticketing integrations (Jira, Linear, GitHub
Issues) and saved views are next. Ideas and votes are welcome in
[Discussions](https://github.com/r4reetik/edgewatch/discussions).

## Contributing

Contributions are welcome, and new checks especially. A check is one small module with its metadata,
and the test suite tells you what's missing.

```bash
npm install
npm run dev -- --mock   # mocked Cloudflare and Vercel data, in three entities
npm run dev             # your real accounts, kept in ./.edgewatch
npm run check           # typecheck, lint, tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the layout of the code and how to add a check,
[docs/architecture.md](docs/architecture.md) for how a scan works, and [SUPPORT.md](SUPPORT.md) for where
to ask questions. Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).

## Sponsoring

Edgewatch is free and MIT-licensed. If it's useful to you or your company, you can support its development
through [GitHub Sponsors](https://github.com/sponsors/r4reetik).

## License

[MIT](LICENSE)
