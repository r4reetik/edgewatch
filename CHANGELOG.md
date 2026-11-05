# Changelog

## 0.4.0

- **45 new checks** (120 in total), from about 60 more Cloudflare reads and GraphQL analytics:
  - **Traffic**, a new category that checks configuration against the last 7 days of requests: managed rules overridden to log while matching attacks, attack-scored requests that got an answer, leaked-password logins nothing stops, `.env` or `/.git/` files being served, plain-HTTP responses, clients still on TLS 1.0/1.1, rules that never match, and bots succeeding on login pages. Analytics queries adapt to each zone's plan.
  - **Identity & access:** account API tokens without an IP restriction or expiry, unused for 90 days, or able to change every zone.
  - **Zero Trust:** Access groups and reusable policies open to everyone or a webmail domain (and groups are now resolved inside app policies), leaked service tokens, CORS with credentials, weak Access cookies, one-time PIN beside SSO, Gateway without TLS inspection or logging, WARP that users can turn off, broad private routes, missing posture checks, outdated cloudflared, idle seats.
  - **TLS, WAF and more:** legacy ciphers, per-hostname TLS overrides, expiring custom, client and mTLS certificates, Universal SSL off; weakened DDoS protection, IP Access allowlists for whole countries or networks, URL normalization off, unenforced mTLS, malicious scripts; DNS-only load balancers, Spectrum publishing SSH or RDP; credentials in plain-text Worker or Pages variables, public previews, open R2 CORS; catch-all email forwarding, failing DMARC senders; failing Logpush jobs and alert webhooks; Access apps rejecting thousands of logins.
  - Account-level WAF deployments (Enterprise) now count, so WAF checks no longer fail on zones protected that way.
- **Finding pages.** Every finding has a link that works from any view, with a timeline of scans and triage changes. Copy it from the finding.
- **Triaged page.** Everything you've triaged in one place: where each finding stands now, a lane showing how its status moved over time (including when a scan stopped finding it, or an accepted risk lapsed), its full history, and a feed of every change. Filter by state, account and when it last changed.
- **Findings page.** Status tabs with counts, sorting, a due-date column, grouping by check, zone or account, filter chips, exports that match the filters, and export of a selection. Bulk triage changes only the fields you set, can append to notes, and can be undone. J and K move between findings.
- **Overview.** Fix-first grouped by check, separate overdue and unowned tiles, links to everything new since the last scan, and trends that wait for a second scan.
- **Clearer coverage.** Every unreadable source names the permission it needs and the checks it skipped; pages say why they're empty.
- **The URL carries the view** (`?scope=`), so any page can be shared as it is.
- **Alerts** link to each new finding and say when a finding came back after being fixed.
- **Settings** save as soon as they change.
- **Documentation.** A reference page for every check and every token permission, generated from the code; guides for deployment and how a scan works; issue templates for bugs, false positives and new checks.
- **For contributors:** checks are self-describing modules with typed IDs, a contract test requires a failing case for every check, server and web share their API types, the server is split into route modules with guards on each route, `npm run dev -- --mock` runs on mocked data, and Biome lints and formats the code.
- **Changed:** API responses use camelCase; triage requests take `dueDate` and `acceptUntil`. CSV export columns are camelCase (`checkId`, `firstSeen`).
- **Next:** alerts before accepted risks expire, comments on findings, ticketing integrations, saved views.

## 0.3.0

- **Several accounts.** Add as many Cloudflare accounts as you like, from one token or many. Accounts are scanned one after another, each with its own token.
- **Entities.** Group accounts by the company or team that owns them. Each entity has its own company email domains and its own Slack or webhook alerts, and can be kept out of **All accounts** so another company's accounts never mix into combined views or reports.
- **View switcher.** Show one account, one entity or All accounts; every page, the audit report and the exports follow it. Combined views tag each row with its account and average the accounts' scores.
- **Accounts page.** Add accounts, replace tokens, rename, move between entities, reorder, leave accounts out of the daily scan, or remove them with their data.
- **Breaking:** `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are no longer read; add accounts in the browser. A 0.2 install's account, history and alert settings are imported automatically on first start.

## 0.2.0

- **24 deeper checks** (75 in total), most of them correlating sources that no single setting shows together:
  - **Attack surface:** exposed origin IPs, origins reachable without Cloudflare, admin tools without Access, SSH/RDP over tunnels, confirmed subdomain takeovers, lame delegations, tunnel/DNS drift.
  - **Rule analysis:** log-only managed rules, exceptions on forgeable headers, broad network skips, stale hostnames, toothless rate limits, per-path security downgrades, hard-coded secrets.
  - **More:** uncovered proxied hostnames, Origin CA expiry, weak DKIM keys, dropped DMARC reports, MTA-STS, unused service tokens.
  - **Change risk** from the audit log: rules disabled, Access widened, settings lowered.
- **Overview "Attack paths"** card, step-by-step evidence in every finding, and **Verified / Likely / Reopened** badges.
- **Takeover confirmation probe**, on by default; turn it off in Settings → Scans.
- **Faster scans** with higher API concurrency.

## 0.1.0

First release.

- **Scanning.** 51 posture checks across identity, Zero Trust, TLS, WAF and bots, DNS, email, platform, monitoring and cost. Cloudflare Security Center insights are imported and de-duplicated.
- **Setup.** In-browser setup with token verification and a permission check per data source. Checks that lack data are skipped, never passed.
- **Pages.** Overview, Findings (triage, bulk triage, accepted risk with expiry, SLAs and overdue), Zones, Activity, Value, Checks (disable or re-rank), Scans and Settings.
- **Report and exports.** Print-ready audit report, plus CSV and JSON exports.
- **Automation.** Daily scheduled scans, with Slack and webhook alerts for new findings.
- **Distribution.** `npx edgewatch` for local use, and a Docker image for shared instances (password required when exposed).
