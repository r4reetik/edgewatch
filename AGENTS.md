# AGENTS.md

Read this first. It holds the decisions behind this project and the rules for changing it. It is written for coding agents (Claude Code reads it through `CLAUDE.md`; Codex, Cursor, Copilot and others read `AGENTS.md` directly) and for people.

It sits on top of the human docs and doesn't repeat them: [CONTRIBUTING.md](CONTRIBUTING.md) covers setup and adding a check; [docs/architecture.md](docs/architecture.md) covers how a scan works; [docs/releasing.md](docs/releasing.md) covers releases; [docs/deployment.md](docs/deployment.md) covers running it.

## Keep this file current

This file is part of the code. It is only useful while it is true, so every change keeps it true:

1. **In the same commit** as any change that makes, changes or reverses a decision, update the section it affects and add a dated line to the [decision log](#decision-log). Examples: a supported version, a dependency or tool choice, a UX pattern, a security rule, a release or process step, or a preference the maintainer stated in a session.
2. **Edit, don't append contradictions.** When a decision is reversed, rewrite the rule where it lives, and change the old log line to say it was superseded and by what. No two lines of this file may disagree.
3. **Link, don't copy.** When the detail lives in a doc or in code, point to it. Copies go stale.
4. **Check it.** `test/agents.test.ts` fails when this file names a path that doesn't exist or an `npm run` script that isn't in package.json, when the Node.js version here doesn't match `src/node-check.ts`, or when `CLAUDE.md` stops importing this file. `npm run check` runs it.
5. **Before you finish a task,** reread the [decision log](#decision-log) and the sections you touched, and ask whether your change belongs in either. If the maintainer told you how they want something done, record it under [Working with the maintainer](#working-with-the-maintainer). A contributor's own preferences don't go in this file (see [Working with a contributor](#working-with-a-contributor)).

## What Edgewatch is

A self-hosted, **read-only** security posture tracker for **Cloudflare and Vercel** (more providers, such as AWS, Google Cloud and Google Workspace, are planned). You give it a token per platform, and it scans daily. The web app lets you triage every finding until it is fixed. It runs locally with `npx edgewatch@latest`, or for a team in Docker (`ghcr.io/r4reetik/edgewatch`). It is open source (MIT) and published to npm and GHCR from GitHub Actions.

It is built for many accounts, grouped into **entities**. An entity is a company, legal entity or team, and can hold accounts on several providers (its Cloudflare accounts and its Vercel teams together). Entities can be different companies, so their data, alerts and suggestions never cross. Each entity chooses whether it appears in the combined "All accounts" view (`includeInAll`). People may use one platform only: nothing may assume Cloudflare is connected.

### Providers

- **Every account belongs to one provider** (`accounts.provider`; `src/shared/providers.ts` lists them). Everything provider-specific goes through the `Provider` interface (`src/providers/types.ts`), registered in `src/providers/index.ts`. The scanner, account routes and setup screen never branch on a provider by name. How to add one: [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-provider).
- **Layout.** New providers get `src/providers/<id>/` (client, sources, inventory, checks, catalog, engine, views, permissions), like `src/providers/vercel/`. Cloudflare predates this and stays in `src/core`, wrapped by `src/providers/cloudflare.ts`; the engine, check format and categories in `src/core` are shared by all providers.
- **One check format, one engine.** Provider checks are written with `checksFor<Context, SourceKey>()` and summarised by `summarize()` in `src/core/engine.ts`. Categories are one shared list (`src/core/categories.ts`); add one only when no existing category fits. IDs carry a provider prefix (`V…` for Vercel) and are unique across providers. The full catalog is `src/providers/catalog.ts`.
- **Findings of a Vercel project use its name as their `zone`**, so grouping, filters and links work the same; the UI calls it "Project" (`zoneWord`).
- **Checks that span providers** (`XP-…`) compare an account with the other accounts in its entity through `links` stored in each scan's snapshot and passed as `related`. They never look outside the entity, and are skipped (not passed) when the entity has no scanned account on the other provider. See [docs/architecture.md](docs/architecture.md#checks-that-span-providers).
- **The provider filter is part of the scope key** (`e:3@vercel`, `src/shared/scope.ts`), so every scoped API, export, report and link follows it. It's dropped when the view has only one provider. The UI shows the switch only when the view has more than one provider, and it must keep working for any number of providers (a menu, not a fixed toggle).
- **Scores:** each account is scored on its own checks; a view's score is the mean of its accounts' scores, and with several providers in view the Overview also shows each provider's mean (`providerScores`).
- **Vercel API facts learned from a real team** (the OpenAPI description doesn't say them):
  - Managed rulesets (bot protection as `bot_filter`, `ai_bots`, `owasp`, `vercel_ruleset`) live on the project in `security.managedRules`, not in the firewall configuration. The firewall configuration holds custom rules, IP rules and the OWASP core ruleset (`crs`, per attack type).
  - A project that was never configured has no `security` block and its firewall configuration answers 404. Vercel's defaults apply: firewall on, managed rulesets off.
  - Someone invited appears both in `emailInviteCodes` and as a member with `confirmed: false`.
  - A token scoped to one team gets 400 from `/v6/user/tokens`; only a Full Account token can list tokens.
  - Team two-factor enforcement is `mfa.enforced` on the team.
  To check a shape against a real team, use a throwaway script that sends GET requests only and prints keys and counts, never values or the token.
- **Provider glyphs are neutral icons** (Phosphor's cloud and triangle), never the providers' logos. Edgewatch isn't affiliated with them.

## Commands

```bash
npm install
npm run dev -- --mock   # mocked Cloudflare and Vercel (3 entities, one with both), nothing written to disk
npm run dev             # real accounts, data in ./.edgewatch
npm run check           # typecheck + lint/format check + tests: must pass before every commit
npm run format          # fix formatting (Biome)
npm run docs            # regenerate docs/checks.md and docs/permissions.md after changing a check
npm run build           # dist/ (server via tsc, web via Vite)
npm run sync            # maintainer's clone only: catch up with origin/main (instead of git pull), repairing moved release notes
npm run release -- minor --dry-run   # maintainer's clone only: what a release would do; drop --dry-run to cut it
```

API on port 4317, web with hot reload on 5173. Tests are `node:test` and run TypeScript directly (`npm test`). There is no build step for the server in development.

## Hard rules

These are never broken. A test enforces most of them.

- **The scanner only reads.** REST calls are GET. Cloudflare's GraphQL is POST but query-only. `test/integration.test.ts` (Cloudflare) and `test/vercel.test.ts` (Vercel) fail on anything else. Never add a write call to any provider, even behind a flag. This matters most where a provider can't issue read-only tokens: Vercel tokens can do whatever their user's role allows, so Edgewatch is what keeps them read-only.
- **Secret values are never read or stored.** Vercel environment variables are listed without `decrypt` and their values dropped; drain and webhook URLs keep only scheme and host; drain headers are dropped. Secrets are judged by name, type and Vercel's own flags. `test/vercel.test.ts` checks the stored data.
- **A check whose data couldn't be read is skipped, never passed or failed.** Missing permissions become coverage gaps (`src/core/sources.ts`), not errors.
- **Secrets never leave the vault.** Tokens of every provider are stored in `<data-dir>/credentials.json` (mode 0600), and the database holds only a token ID. No API response, log line, test fixture or screenshot may contain a token, a real account ID, a hostname or an email. `test/server.test.ts` checks the API responses.
- **Entities stay apart.** Alerts go to each entity's own Slack channel or webhook. Owner suggestions come only from the same entity. An entity left out of All accounts stays out of combined views and exports. Anything new that aggregates across accounts must respect this.
- **`src/shared` is portable**: no `node:` imports and no DOM. The server returns shared DTOs with `satisfies`, and the web imports them as types.
- **Routes carry their guards** (`src/server/router.ts`): `routes(app).with(requireSession(auth))`. Who can reach a route never depends on where it is registered.
- **Migrations are append-only.** New ones go at the end of `MIGRATIONS` in `src/store/db.ts`, ship only in a new release line, and their fingerprint goes in `test/migrations.test.ts`. Never edit a shipped migration.
- **Don't quote a total check count** in the README, the docs, images or the changelog. It goes stale with every new check.

## Node.js and tooling

- **Node.js 26 LTS only.** The minimum is 26.13.0, the first Node 26 LTS release. `NODE_MAJOR` and `MIN_NODE` in `src/node-check.ts` are the source of truth. `.nvmrc` says `26`, the Dockerfile uses `node:26-slim`, and CI tests on 26. The `minimum-node` job runs the packed CLI on 26.13.0 and checks that Node 24 is refused.
- **`engines` in package.json is deliberately `>=18`.** npm treats `engines` as a filter: with a strict range, `npx edgewatch` on an older Node.js quietly installs an old Edgewatch. Instead, `src/bin.ts` runs `checkNode` before importing anything else, and prints the exact upgrade command for the user's Node manager (nvm, fnm, Volta, Homebrew, winget) plus `npx edgewatch@latest`. `src/node-check.ts` imports nothing, so it runs on old Node.js. Don't tighten `engines`, and don't add imports to that file.
- **Users always get the newest release.** Docs and in-app upgrade steps say `npx edgewatch@latest`. A plain `npx edgewatch` reuses a cached copy.
- Biome 2.6 is used for both lint and format (`biome.json`: 2 spaces, 160 columns, double quotes, trailing commas). TypeScript runs with type stripping, so use `.ts` extensions in imports and no enums or namespaces.
- Dependabot ignores major updates of `@types/node` and the Docker `node` image (`.github/dependabot.yml`). Those move together with `NODE_MAJOR`, by hand.
- GitHub Actions use current majors (checkout and setup-node v7, CodeQL v4, Docker actions v4–v7).
- **`.claude/settings.json` is shared** with everyone who uses Claude Code here. It lets the checks, tests, formatting, docs, build and the mock dev server run without a prompt, and denies `npm run release`, `npm run sync` and reading `.edgewatch/` (real scan data and tokens). Keep it to commands that are safe on any clone; personal permissions go in `.claude/settings.local.json`, which git ignores.

## Code conventions

- **Every file starts with a short comment saying what it is and why.** Comments explain *why*, not what the code does.
- **Server:** Hono, with one route module per area in `src/server/routes/`. Request bodies are validated in `src/server/validate.ts` before any write. Scoped routes read `c.get("scope")` (`all`, `e:<id>` or `a:<id>`, resolved in `src/shared/scope.ts`).
- **Store:** SQLite, with one repository per concern behind `Repo` (`src/store/repo.ts`). Triage belongs to the finding's fingerprint (check, account, zone, resource), not to a scan, so it survives rescans. Every triage change is recorded in `triage_events`.
- **Checks:** follow [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-check). Report passes as well as failures. Use `confidence: "likely"` for heuristics and `"confirmed"` for probes. Each new check gets a failing case in `test/checks/cases.ts`. Aim for checks that go deeper than other tools, for example correlations across sources and GraphQL traffic evidence, while keeping the finding text plain.
- **Tests:** every bug fix or feature comes with a test that would have caught it. Server behaviour is tested through the app (`test/helpers/app.ts`, `makeApp`) against the mock Cloudflare (`dev/mock/cloudflare.ts`) and mock Vercel (`dev/mock/vercel.ts`). Each Vercel check has a failing case in `test/vercel-cases.ts`. The mock data must stay fictional.
- **Vercel API shapes** come from Vercel's OpenAPI description (`https://openapi.vercel.sh/`). Check field names there before reading a new one, and treat a missing field as unreadable or not configured, never as a pass.

## Web UI conventions

The UI follows **Cloudflare's design language** using Kumo (`@cloudflare/kumo`), with Phosphor icons and Tailwind. The maintainer asked for no "AI slop" design: no gradients, emoji, decorative cards or made-up components where Kumo has one.

- **Use the shared building blocks** in `web/src/components/ui.tsx`: `Page`, `Card`, `ListCard`, `SettingRow` and `SettingRows`, `FormGrid`, `DialogHeader`, `PageState`, and the badges. Use the shell state from `web/src/shell.tsx` (`useShell`, `useScopedApi`). Every page is listed in `web/src/routes.tsx`.
- **Alignment is strict.** Fields that share a row line up their labels and controls on one baseline, and descriptions sit below the control (`FormGrid`). Spacing comes from the shared components, not from one-off margins.
- **Hierarchy:** an entity name always reads as the parent of its account names (entity, then account). Where accounts from several providers mix, an account name carries its provider glyph (`AccountName`, `ProviderIcon`).
- **Provider-specific pages** declare `providers` in `web/src/routes.tsx` and are hidden when no account in view is on that provider. Wording says the provider's own words (`PROVIDER_INFO`: "team" for Vercel, "account" for Cloudflare) and never assumes Cloudflare.
- **Onboarding starts with the platform** (`ProviderPicker`, then that provider's `TokenHelp` and `ConnectForm`). Someone on one platform never has to read the other's steps.
- **Kumo specifics:** give `Tooltip` the button through `render={<Button …/>}`. Wrapping a button in a tooltip trigger nests one button in another. Use `ButtonGroup` for split buttons, and `Autocomplete` for free text with suggestions.
- **Finding dialogs** are at least 75% of the screen width on desktop (`sm:w-[75vw]`). J and K move through the list, and only when focus isn't in a field.
- **Type less, pick more.** When a field asks for a value the app already knows, offer it. Owners suggest the owners already used in the entity (`GET /api/owners`). A new entity name that matches an existing one is caught, and the add-accounts form offers to use the existing entity. The Link URL offers the current address. Apply this to any new field.
- **Actions do what their label says for the current view.** "Run scan" scans the selected account, or the entity or All accounts when that is the view, and its menu offers the wider scopes. Tooltips say what will happen.
- **Bulk edits change only the fields the user touched.** Clearing a field is a separate, explicit choice, and every bulk change can be undone.
- `localStorage` is for per-browser conveniences only (theme, last scope), and every read is wrapped in `try`.

## Writing

The same rules apply to UI copy, docs, changelog and commit messages:

- **Plain, specific English** for someone running Edgewatch, not a reviewer. Say what happens and what to do. Write sentences, and avoid jargon and marketing.
- **UI copy** names the thing the user sees. Error messages say what's wrong and the fix ("Mock Group already exists. Pick another name.").
- **Commit messages:** one imperative line that says what changed for the user (for example "Run scan scans the selected account, with a menu for the entity or every account"). No AI attribution or co-author trailers.

## Changelog, versions and releases

- **Every user-visible change adds a line under `## Unreleased` in `CHANGELOG.md`**, in the same commit. Mark it `**Breaking:**` with the steps to take if users must act. The release script refuses a breaking change or a new migration within the same release line.
- **Releases are cut locally with `npm run release -- <patch|minor|major|rc>`** (`--dry-run` to preview). It requires a clean `main`, syncs with `origin/main`, runs `npm run check`, bumps, commits `Release vX.Y.Z`, tags, and pushes `main` and the tag in one atomic push. Before 1.0, breaking changes and migrations are `minor`. The tag starts `.github/workflows/release.yml`, which only publishes: npm (`latest`, or `next` for candidates), GHCR (`:X.Y.Z`, `:X.Y`, `:latest`) and GitHub Releases. Running installations read the release to show updates and breaking-change warnings.
- **The workflow never commits or pushes to `main`** (`test/release.test.ts` enforces it), and there is no "Run workflow" button. When CI made the release commit, every release forked `main` from the maintainer's clone. Don't bring that back.
- **Catch up with `npm run sync`** rather than `git pull`: it merges `origin/main` and moves notes that a merge landed under a released version back to `## Unreleased` (`repairReleasedNotes`), committing the repair. The tests fail while released notes differ from their tag, and point at `npm run sync`.
- Agents never run `npm run release` or `npm run sync`'s merge on their own: releasing is the maintainer's call, and both commit (and `release` pushes).
- The README and `docs/deployment.md` pin the current release line (`:0.6`, `edgewatch@0.6`). `scripts/release.ts` (`pinLine`) updates them on each new line, so don't edit those pins by hand.
- Releases come only from `main`. Older lines get no backports.

## How to work here

These apply in every session, whoever you're working with:

- **Design for more providers.** AWS, Alibaba Cloud, Google Cloud, Google Workspace and others are planned, so UI and code choices should work for any number of providers, not two.
- **Treat every real account as production.** Use the mock (`npm run dev -- --mock`) by default. Against real accounts, run nothing that writes, never print a token, and delete any scratch copies of `~/.edgewatch` you make. A Cloudflare token for Edgewatch is read-only; a Vercel token can't be, so Edgewatch's GET-only rule is what protects it.
- **Accept Vercel tokens quietly**: no warning when the token's user can write (see the decision log).
- Confirm before anything destructive or outward-facing.
- When asked for "everywhere", apply the change across the whole app and its docs, not only the place that was named.
- Verify UI changes in a browser against the mock, not just with tests, and say what wasn't checked.
- No attribution lines (`Co-Authored-By`, "Generated with…") in commits or pull requests.

### Who you're working with

The maintainer, r4reetik on GitHub, works in a clone whose `origin` is `github.com/r4reetik/edgewatch` and cuts the releases. Everyone else is a contributor, working on a fork, so their `origin` is the fork. When it isn't clear which you're working with, ask once before committing, pushing or recording a preference.

## Working with a contributor

Most people who clone this repository are contributors. In their sessions:

- **Work on a branch of their fork**, never on `main`. Commit and push to the fork when they ask, and open the pull request against `main` of `r4reetik/edgewatch`. Never push to `r4reetik/edgewatch` itself.
- **Catch up with the upstream repository** (`git remote add upstream https://github.com/r4reetik/edgewatch.git`, then `git fetch upstream` and rebase the branch on `upstream/main`). `npm run sync` and `npm run release` are for the maintainer's clone; they merge into and push `main`.
- **Check before you commit.** `npm run check` must pass, every change comes with a test, and anything a user would notice gets a line under `## Unreleased` in `CHANGELOG.md` (see [CONTRIBUTING.md](CONTRIBUTING.md#pull-requests)).
- **Bigger changes start with an issue**, so the approach is agreed before the code is written: a new provider, a new dependency, a change to a hard rule or to the UI's structure.
- **Decisions are proposed, not made.** If the change makes or reverses a decision, update this file and add a decision-log line in the same pull request, and say so in the pull request description. The maintainer accepts the decision by merging it.
- **The contributor's own preferences stay out of this file.** They belong in their personal agent settings (for Claude Code, a CLAUDE.local.md file, which git ignores, or its memory), not in the project's rules.

## Working with the maintainer

Preferences the maintainer stated, which apply only in the maintainer's sessions:

- **Commit only when asked**, and **never push**: the maintainer pushes and runs releases. Branch only when asked.
- The maintainer's Cloudflare accounts are **production** and their token is read-only; their Vercel team is production too. The rules for real accounts under [How to work here](#how-to-work-here) apply in full.

## Decision log

Newest first. One line each: the date, the decision, and why. When a decision is reversed, mark the old line "Superseded" and point to the new one.

- 2026-11-10: A shared `.claude/settings.json` allows the safe development commands and denies release, sync and reading `.edgewatch/`. *Why:* contributors working with Claude Code shouldn't be asked to approve every test run, and no session should cut a release or read real tokens.
- 2026-11-10: This file separates rules for every session from the maintainer's own preferences, and gives contributors' agents a workflow: a branch on their fork, a pull request to `r4reetik/edgewatch`, decisions proposed in the pull request. *Why:* it was written as if every session were the maintainer's, so a contributor's agent would refuse to push to its own fork and record the contributor's preferences as the maintainer's.
- 2026-11-09: Vercel is the second provider, behind a `Provider` interface built for more (AWS, Google Cloud, Google Workspace…). Accounts record their provider; an entity can mix providers. *Why:* the maintainer runs Vercel next to Cloudflare and wants one place for both, with more platforms to come.
- 2026-11-09: Vercel tokens are accepted without a warning about their write access; Edgewatch only sends GET requests and never reads environment variable values. *Why:* Vercel has no read-only tokens, and the maintainer chose not to warn.
- 2026-11-09: The provider filter is part of the scope key and applies to every page; the Overview shows a score per provider next to the combined one. *Why:* the maintainer wants to see Cloudflare or Vercel findings on their own, and one filter that scales to many providers beats per-page filters.
- 2026-11-09: Checks that span providers (`XP-`) compare accounts within an entity, from the latest scans of the other accounts, and ship from the first Vercel release. *Why:* the problems between platforms (dangling records, WAF bypass through *.vercel.app) are the ones neither dashboard shows.
- 2026-11-09: Releases are cut on the maintainer's machine (`npm run release`) and only published by CI on the tag; `npm run sync` merges `origin/main` and repairs moved notes. *Why:* the workflow's commit to `origin/main` forked `main` on every release. 0.7.0 shipped without two unpushed commits, and pulls kept moving new notes under released versions. Supersedes the Actions → Release flow from 2026-11-05.
- 2026-11-09: Vercel checks were verified against the maintainer's real team, which corrected where managed rulesets are read and how unconfigured firewalls count. Checks that would fire on most projects of a normal team are limited to where they matter (bot protection on public sites only; AI crawlers, OWASP and rate limits once the firewall is being configured). *Why:* findings must be right on real data, and a check that fires everywhere gets ignored.
- 2026-11-09: Setup and Add accounts start with a platform choice. *Why:* people may use only one platform and shouldn't see the other's steps.
- 2026-11-08: This file is the single place for decisions and rules. `CLAUDE.md` imports it, and `test/agents.test.ts` checks that the paths, scripts and Node version it names are still right. *Why:* future work, by agents or people, should start from the decisions already made, and stay in sync with them.
- 2026-11-07: Free-text fields suggest values the app already knows: owners scoped to the entity, existing entity names, the current address for the Link URL. *Why:* a typed owner should match earlier spellings, and a duplicate entity is almost always a mistake.
- 2026-11-06: Node.js 26 LTS only, with a minimum of 26.13.0, and Node 24 dropped. *Why:* one supported line, and the maintainer asked for it. Supersedes the 24.x minimums from 2026-11-05.
- 2026-11-06: `engines` stays wide (`>=18`), and the real Node.js check runs first in `src/bin.ts`, with upgrade steps. *Why:* npm used `engines` to quietly serve 0.4.0 to older Node.js, and users should always get the newest Edgewatch.
- 2026-11-06: Run scan scans the current view, and a split menu offers the entity or every account in every entity. *Why:* it used to scan everything, across companies.
- 2026-11-06: The release script refuses to run when released notes moved, and docs pin the release line automatically. *Why:* a `git pull` merge moved 0.5.0's notes and broke the next release.
- 2026-11-05: Dependabot ignores major updates of `@types/node` and the `node` image. Actions moved to their latest majors, and Biome to 2.6. *Why:* the Node major changes on purpose, together with `NODE_MAJOR`.
- 2026-11-05: GitHub Sponsors are set up (`.github/FUNDING.yml`, `funding` in package.json, a README section).
- 2026-11-05: No total check count anywhere. *Why:* it goes stale with every new check.
- 2026-11-05: Releases come from GitHub Actions (superseded 2026-11-09: cut locally, published by Actions), with npm and Docker release lines safe to auto-update, update checks in the app, backups before migrations, and newer databases refused. *Why:* self-hosters need updates that are safe to take, and breaking changes need a warning.
- 2026-11-05: Distributed as both `npx edgewatch` and a Docker image (also runs on ECS). *Why:* anyone should be able to start it with just a token. A Cloudflare Workers deployment was dropped.
- 2026-11-05: Multi-account with entities that may be separate legal entities, each with its own domains, alerts and inclusion in All accounts. A Triaged page follows every triaged finding over time. *Why:* the maintainer runs accounts for different companies.
- 2026-11-05: Cloudflare design language with Kumo, strict alignment and no AI-looking design. Finding dialogs are at least 75% wide. *Why:* the maintainer's requirement for the UI.
- 2026-11-05: Read-only by construction: GET and GraphQL queries only, skip what couldn't be read, and secrets kept outside the database. *Why:* it runs against production accounts with a read-only token.
