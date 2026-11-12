# Changelog

## Unreleased

- **Edgewatch is now Keelson.** Start it with `npx keelson@latest`, or use the image `ghcr.io/r4reetik/keelson`. Existing installations keep working without changes: the `edgewatch` npm package and image are still published with every release and run Keelson, `EDGEWATCH_*` variables are still read, and an existing `~/.edgewatch` folder and `edgewatch.db` are used where they are. See [upgrading from Edgewatch](docs/upgrading.md#upgrading-from-edgewatch).
- The Docker image no longer sets `KEELSON_HOST` and `KEELSON_DATA_DIR`; it defaults to `0.0.0.0` and `/data` itself, so a variable set on the container (by either name) is the one used.

## 0.9.0

- **AWS support.** Connect AWS accounts with an access key for an IAM user that has AWS's managed SecurityAudit policy. Scans check IAM (root user MFA and access keys, console users without MFA, old and unused access keys, the password policy, administrators with long-lived keys, roles any AWS account can assume, policies that allow everything), S3 (public buckets after the bucket's and the account's Block Public Access), security groups open to the internet, public databases, EBS snapshots and machine images, instances that still allow IMDSv1, unencrypted and unbacked databases, deprecated Lambda runtimes and function URLs without authentication, CloudFront distributions and load balancers that serve plain HTTP or old TLS, Route 53 records that point at resources the entity no longer has, and GuardDuty and VPC flow logs where workloads run. Edgewatch only sends signed GET requests to AWS, so CloudTrail, KMS and Config, which only answer POST, aren't read yet. The new **Regions** page shows what runs in each region and its findings; a region that refuses the access key is shown as not readable instead of failing the scan.
- **AWS in an entity with Cloudflare and Vercel.** New checks compare them: a Cloudflare DNS record that points at a CloudFront distribution, load balancer or S3 bucket none of the entity's AWS accounts has, and a Route 53 record that points at Vercel when no Vercel project in the entity serves it.
- **Deeper AWS checks.** An internet-facing instance whose role has administrator access (critical while IMDSv1 is allowed), credentials written into instance start-up scripts, roles that trust an AWS account outside the entity without an external ID, and internet-facing load balancers without access logs. An instance that still allows IMDSv1 is rated by what there is to take: high when it is public and has a role, low when it has no role. A console user without MFA is critical when that user is an administrator, and so is a public Lambda function URL whose role is one.
- **Cloudflare and AWS compared.** A hostname proxied through Cloudflare whose AWS load balancer or instance also accepts web traffic from anywhere is reported as an origin that skips Cloudflare's WAF, and Edgewatch now remembers the public addresses each AWS account holds: when one disappears between scans and a Cloudflare or Route 53 record still points at it, the record is reported as dangling, with the date the address was last seen. An AWS address that nobody in the entity holds is noted at low severity, since it is usually a vendor's. With AWS connected, Edgewatch reads AWS's public address-range file (`ip-ranges.amazonaws.com`) to recognise AWS addresses; your access key isn't sent with that request.
- AWS security group findings are rated by what the group is attached to: high or critical when something with a public address uses it, one step lower when only private interfaces do, low when nothing does. Each finding names what is reachable.
- A publicly accessible database is critical when its security group lets the internet reach it and medium when it doesn't. Classic load balancers and API Gateway custom domains are read, so Route 53 records that point at them are no longer reported as dangling, and a record that points at a load balancer that really is gone is low severity: its name can't be claimed by anyone else. The "no web ACL" check is limited to CloudFront distributions in front of an application, not ones that only serve files from S3.
- Checks that compare accounts in an entity wait until every account they depend on has been scanned, instead of comparing against a partial list.
- Platform icons are now Cloudflare's, Vercel's and AWS's own marks, in one colour, instead of a generic cloud, triangle and cube.
- Layout fixes: the sidebar's header line meets the top bar's, the collapsed sidebar shows only the Edgewatch mark (centred over the menu icons) instead of a clipped name, and the sidebar footer no longer crowds its border. Table headings stay on one line, the column after a pinned first column is no longer faded at its start, and table footers line up with the rows. On phones, the view picker keeps room for the entity's name and attack paths keep the platform icon beside the title.
- **Findings show where they come from.** With several platforms in view, every finding, check and group carries its platform's icon. A finding from a check that compares platforms shows both, joined by arrows (AWS ⇄ Cloudflare), and Findings → Filters → Correlation lists only those. Findings can also be grouped by platform.
- **Pick any set of accounts.** The two pickers in the top bar are tick boxes now. Ticking an entity ticks every account in it, and each account can be ticked on its own; the platform picker lists each platform with its accounts beneath it, so one of two AWS accounts can be left out. Every page, the score, the report and the exports follow the ticked set, and the link keeps it. An entity that is kept separate is still never combined with another.
- **Clearer words and grouping.** The app says "platform" for Cloudflare, Vercel and AWS everywhere, and "location" for a zone, project or region when a view mixes them. The sidebar is split into Posture, Inventory (one page per platform, marked with its icon), Insights and Manage. The view picker says what each level is, Findings filters are grouped into What and Where, filter chips name what they filter, and the Accounts page explains how entities, platforms, accounts, locations, checks and findings fit together.
- Opening Export on the Findings page crashed the page; it opens now.
- Setup, Accounts and every message name the platform's own credential ("API token", "access token", "access key") instead of saying "token" for all of them, and the Accounts page's Token column is now Credential. The provider switch, the audit report and the finding filter work for any number of platforms: a finding's place is called a zone, project or region to match the platforms in view.
- Findings and checks link to "the AWS console" or "the Cloudflare dashboard" by the provider's own name for it.

## 0.8.0

- **Owner suggestions when triaging.** The Owner field, in a finding's triage and in bulk triage, lists the owners already assigned in the same entity as soon as you click it, and narrows them as you type, so a name is picked instead of retyped (and spelled the same way every time). Owners from other entities are never suggested.
- Creating or renaming an entity to a name that's already taken is caught in the dialog. When adding accounts, typing the name of an existing entity offers to add them to it instead of making a second one.
- Settings → Notifications offers the address you opened Edgewatch at as the Link URL, in one click.
- **Vercel support.** Connect Vercel teams, or a personal Hobby account, with a Vercel access token. Scans check deployment protection (public previews and *.vercel.app URLs, fork pull requests, bypass secrets, deploy hooks), secrets in environment variables (readable, plain-text, sent to browsers, shared with previews), SSO and two-factor enforcement, Owners, outside members, open invitations and access tokens, integrations that can change every project, the Vercel Firewall (bot protection, OWASP rules left in log mode, IP bypasses, rate limits), domains and certificates, log drains and webhooks, cron jobs anyone can trigger, credentials written into build commands, production secrets downloaded to developer machines, team-wide shared variables, runtimes past end of life and production builds over a year old. Edgewatch only sends GET requests to Vercel and never reads environment variable values. The new **Projects** page shows every project's protection, firewall and secrets.
- **Cloudflare and Vercel in one entity.** A company's Cloudflare accounts and Vercel teams can share an entity, and new checks compare them: a Cloudflare DNS record pointing at Vercel that no Vercel project serves (anyone could claim it), a Vercel site behind Cloudflare whose *.vercel.app URLs skip Cloudflare's WAF, and Vercel sites proxied through Cloudflare.
- **Provider switch.** With both platforms in view, a switch beside the account picker narrows every page, the score, the audit report and the exports to Cloudflare or Vercel, and the Overview shows each one's score. Pages that only apply to one platform (Zones, Activity and Value for Cloudflare; Projects for Vercel) only show when it's in view.
- Setup and Accounts → Add accounts start by asking for the platform, so someone who only uses Vercel, or only Cloudflare, only sees that one's steps.
- Alerts name the account's platform, finding exports add a `provider` column (at the end), and findings, checks and data coverage show which platform each row is from.
- The audit report listed unreadable sources as "[object Object]" when several accounts were in view; it names the accounts now.

## 0.7.0

- **Breaking:** Edgewatch now needs Node.js 26 LTS (26.13.0 or newer); Node.js 24 is no longer supported. On an older Node.js, `edgewatch` stops and gives the command to upgrade. Docker users have nothing to do: the image already runs Node.js 26.
- **`npx edgewatch` always gets the newest release.** On a Node.js older than Edgewatch needs, npm used to fall back to an older Edgewatch without saying so; now the newest one runs and says how to upgrade Node.js (with nvm, fnm, Volta, Homebrew or winget, whichever you use).
- Settings → Updates gives the right upgrade command when Edgewatch was started with npx (`npx edgewatch@latest`).
- The README and deployment guide point at the current release line for Docker and npm, and each new release line updates them.

## 0.6.0

- **Run scan** scans the account you have selected (or the entity, or All accounts, when that's what you're viewing). The menu beside it scans the whole entity, or every account in every entity, including entities kept out of All accounts.
- Buttons with tooltips are one tab stop instead of two.

## 0.5.0

- **Breaking:** Edgewatch now needs Node.js 24.22.1 or newer (the October 2026 security release) when run with `npx` or `npm install -g`; Node 26 LTS is recommended. Upgrade Node.js before upgrading Edgewatch; `edgewatch` says so if it's too old. Docker users have nothing to do.
- The Docker image now runs Node.js 26 LTS.

## 0.4.0

- **45 new checks**, from about 60 more Cloudflare reads and GraphQL analytics:
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
- **Updates.** Edgewatch checks GitHub daily for a newer release and says so in the sidebar; Settings → Updates shows the upgrade command for Docker or npm and warns about breaking changes. Releases follow semantic versioning in release lines (Docker `:0.4`, npm `edgewatch@0.4`) that are safe to auto-update. Turn checks off in Settings or with `EDGEWATCH_UPDATE_CHECK=off`.
- **Safer upgrades.** The database is copied to `<data-dir>/backups/` before a migration changes it, and a database from a newer Edgewatch is refused instead of misread, so a rollback is restoring one file.
- **Checks you can trust when access is partial.** A check that needs data the token couldn't read is now skipped everywhere, rather than failing on the missing data (Access hosts reported as unprotected, live tunnels as deleted) or passing on it (traffic checks after an analytics error, email checks when public DNS is blocked). Long lists are read completely: R2 buckets past the first 20, audit logs past 1000 entries, and list endpoints that don't report a page count. The API rate limit is shared by every account on a token, and a 429 pauses all of them.
- **Harder to abuse when exposed.** Request bodies are capped, login limits use the address your proxy saw rather than one the client sends, failed logins no longer block the server, and sessions renew while you use them. Slack alerts stay under Slack's size limit, and alert webhooks don't follow redirects.
- **Smaller fixes.** "Scan now" on an account scans that account; the audit report has a button on the Overview; switching views clears stale data, filters and selections; exports report errors instead of leaving the page; bulk triage only clears an owner or due date when you tick it; clear messages for a wrong flag, an unreadable password file or an old Node.js.
- **Documentation.** A reference page for every check and every token permission, generated from the code; guides for deployment and how a scan works; issue templates for bugs, false positives and new checks.
- **For contributors:** checks are self-describing modules with typed IDs, a contract test requires a failing case for every check, server and web share their API types, the server is split into route modules with guards on each route, `npm run dev -- --mock` runs on mocked data, and Biome lints and formats the code.
- **Breaking:** API responses use camelCase; triage requests take `dueDate` and `acceptUntil`. CSV export columns are camelCase (`checkId`, `firstSeen`).
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
