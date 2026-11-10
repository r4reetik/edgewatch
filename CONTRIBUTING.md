# Contributing to Edgewatch

Thanks for helping. Bug reports, wrong findings, new checks, docs and UI fixes are all welcome. For anything
bigger than a fix, open an issue or a discussion first so we can agree on the approach before you write code.
Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Setup

You need Node.js 26 LTS (`.nvmrc` pins it; `nvm install` picks it up). CI also runs the package on 26.13.0, the first Node 26 LTS and the oldest version it supports. The real minimum is `MIN_NODE` in `src/node-check.ts`; `engines` in package.json is deliberately wide, because npm treats it as a filter and would hand users of an older Node.js an older Edgewatch instead of the one that explains how to upgrade. Development runs TypeScript directly, with no build step for the server.

Fork the repository on GitHub, then:

```bash
git clone https://github.com/<you>/edgewatch.git
cd edgewatch
git remote add upstream https://github.com/r4reetik/edgewatch.git
npm install
npm run dev -- --mock   # mocked Cloudflare, Vercel and AWS data, nothing written to disk
npm run dev             # your real accounts, data kept in ./.edgewatch
```

Both start the API on port 4317 and the web app with hot reload on http://localhost:5173. To run a second copy beside the first (the mock next to your real accounts, say), give it its own ports: `EDGEWATCH_PORT=4417 EDGEWATCH_WEB_PORT=5273 npm run dev -- --mock`. The mock (`dev/mock/cloudflare.ts`, `dev/mock/vercel.ts` and `dev/mock/aws.ts`, seeded by `dev/mock/server.ts`) serves Cloudflare accounts, Vercel teams and an AWS account in three entities, one of them with every platform, with fictional data that trips every family of checks. You don't need an account on any of them to work on Edgewatch. If you do scan your own, use a read-only Cloudflare token, and remember that a Vercel token can do whatever your role allows.

Before opening a pull request:

```bash
npm run check           # typecheck, lint and format check, tests
npm run format          # fix formatting
```

## Layout

```
src/
  bin.ts, cli.ts        the edgewatch command: Node.js version check, then the command line
  main.ts               start(), which wires everything up
  core/                 Cloudflare's client, inventory and checks, and the engine every provider shares (no HTTP server, no database)
    sources.ts          every Cloudflare data source: coverage label, token permission, setup-screen probe
    cloudflare.ts       read-only API client (GET only, plus read-only GraphQL), retries, rate limits, coverage
    inventory.ts        collects one scan's data; analytics.ts holds the GraphQL reads
    cf-types.ts         shapes of the Cloudflare payloads we read
    checks/             check modules (one file per area), registered in checks/index.ts
    engine.ts           runs the modules, de-duplicates, scores
    catalog.ts          the Cloudflare check catalog, derived from the modules
  providers/            the Provider interface (types.ts), the registry (index.ts), every provider's checks (catalog.ts)
    cloudflare.ts       Cloudflare as a provider: an adapter over core/
    vercel/             Vercel: client.ts (GET only), sources.ts, inventory.ts, checks/, views.ts, permissions.ts
    aws/                AWS: client.ts (signed GET only; sigv4.ts, xml.ts), sources.ts, inventory.ts, checks/, views.ts, permissions.ts
  store/                SQLite: migrations (db.ts) and one repository per concern behind Repo
  server/               Hono app: routes/, guards in middleware.ts, validation, presentation
  shared/               code shared with the web app: API types, severities, triage, scope, filters; providers.ts says everything the app knows about each provider
web/src/                React app: routes.tsx lists every page, shell.tsx holds shared state
dev/mock/               mocked provider APIs (Cloudflare, Vercel, AWS) and seeding, for tests and the mock dev server
test/                   node:test suites; fixtures/ and checks/cases.ts for Cloudflare checks, vercel-cases.ts and aws-cases.ts for the others
```

The decisions behind the project, and the rules that follow from them, are in [AGENTS.md](AGENTS.md). Coding agents read it (Claude Code through `CLAUDE.md`), and so should you. It tells an agent how to work on a contributor's fork, so you can hand your agent a task without repeating the rules. Keep your own preferences for the agent in your personal settings (for Claude Code, a git-ignored `CLAUDE.local.md`), not in AGENTS.md. With Claude Code, `.claude/settings.json` already lets `npm run check`, the tests, formatting and the mock dev server run without asking, and blocks the release commands and reading your local scan data. Put permissions of your own in `.claude/settings.local.json`, which git ignores.

Rules worth knowing:

- **The scanner only reads.** REST calls are GET; Cloudflare's GraphQL is POST but query-only. `test/integration.test.ts`, `test/vercel.test.ts` and `test/aws.test.ts` fail on any other method.
- **Secret values are never read.** Vercel environment variables are listed without `decrypt`, and values, drain headers and URL paths are dropped as the inventory is built. AWS policy documents and Lambda environment variables are dropped the same way.
- **`src/shared` is portable**: no `node:` imports, no DOM. The server returns its DTOs (`satisfies`), the web imports them as types.
- **Routes carry their guards** (`router.ts`): `routes(app).with(requireSession(auth))`. Moving a route never changes who can reach it.

## Adding a check

1. Pick the module in `src/core/checks/` for its area, or create one and list it in `checks/index.ts`.
2. Add its metadata next to the others: category, default severity, title, why it matters, how to fix it (write steps as `1. … 2. …`), a `docs` link to developers.cloudflare.com, and `requires`, the data sources it reads.
3. Report results in the module's function: `report("XXX-012", { zone, resource, pass, detail, evidence, link })`. Report passes too, because they count towards the score. Use `confidence: "likely"` for heuristics and traffic, and `"confirmed"` for live probes.
4. If it needs data Edgewatch doesn't collect yet, add a source to `sources.ts`, the read to `inventory.ts` (GET only), the field to `types.ts`, a mock route in `dev/mock/cloudflare.ts`, and a well-configured default in `test/fixtures/inventory.ts`.
5. Add a failing case to `test/checks/cases.ts`. It's typed by check ID, so it won't compile until you do. `test/contract.test.ts` checks that the case fails, that the baseline fixture passes, and that the metadata is complete.
6. Run `npm run docs` to regenerate `docs/checks.md` and `docs/permissions.md`. A test fails if you forget.

### A check for another provider

The same steps, in the provider's folder (`src/providers/vercel/`, `src/providers/aws/`): a module in `checks/` written with that folder's
`defineChecks`, a `docs` link to the provider's own documentation, `requires` from `sources.ts`, the read in `inventory.ts` (GET only,
values dropped), a mock route in `dev/mock/<id>.ts`, and a failing case in `test/<id>-cases.ts`, which `test/<id>-checks.test.ts` checks
the same way. An AWS finding's `zone` is its region, or "Global" for IAM, S3 settings, CloudFront and Route 53; a per-region setting is
only judged where something runs. Checks that compare providers in an entity get an
`XP-` ID and read `related` (see [docs/architecture.md](docs/architecture.md#checks-that-span-providers)).

## Adding a provider

Google Cloud, Google Workspace, Alibaba Cloud and others fit the same shape as Vercel and AWS:

1. Add it to `src/shared/providers.ts`: its ID, and a `PROVIDER_INFO` entry with its label, its words for an account, a resource and a credential, the credential's fields, its API host and the shape of its account IDs. The UI and the server word everything from that entry, so nothing else should compare a provider's name. Add its mark to `PROVIDER_GLYPH` (`web/src/components/ui.tsx`): the provider's monochrome logo as one 24×24 SVG path, such as the one Simple Icons publishes.
2. Create `src/providers/<id>/` with a read-only client (GET or the provider's read-only equivalent, recording coverage), a sources registry, an inventory, check modules written with `checksFor<YourContext, YourSourceKey>()`, a catalog and an engine that ends in `summarize` from `src/core/engine.ts`.
3. Implement `Provider` (`src/providers/types.ts`) in its `index.ts` and list it in `src/providers/index.ts`. The scanner, account routes, setup screen, provider switch, scores, exports and docs pick it up from there.
4. Add a fictional mock API in `dev/mock/<id>.ts`, seed it in `dev/mock/server.ts`, and tests like `test/aws.test.ts` (only reads, no secret stored) and `test/aws-checks.test.ts` (every check fails on its case).
5. Give its inventory page a route limited to the provider (`providers` in `web/src/routes.tsx`), write the steps for creating its credential in `web/src/components/connect.tsx` (`TOKEN_HELP`), and add its sources and a section to `scripts/docs.ts`. TypeScript points at each of these: they are records keyed by provider, so a new one doesn't compile until it has an entry.
6. If it shares hostnames or resources with another provider, add a list to `ProviderLinks` (`src/shared/api.ts`) and an `XP-` check on each side that can judge it.
7. Record the decision in `AGENTS.md`, and update the README, `SECURITY.md` and the changelog.

Severity guide: **critical** means it's exploitable now (a takeover, a leaked credential). **High** means a direct path in or a missing core protection. **Medium** is a weakness that needs another failure to matter. **Low** is hardening.

## Pull requests

Work on a branch of your fork, keep it current with `git fetch upstream` and a rebase on `upstream/main`, push it to your fork, and open the pull request against `main`. CI runs `npm run check` and the packaging jobs on it, and the maintainer reviews it.

- Keep each pull request to one change, with a test that would have caught the bug or covers the feature.
- If it makes or reverses a decision (a dependency, a supported version, a UX pattern, a rule), update [AGENTS.md](AGENTS.md) and its decision log in the same pull request, and say so in the description. Merging it is what accepts the decision.
- Use the mock (`npm run dev -- --mock`) for screenshots. Never commit real account IDs, hostnames, emails or tokens, in code, fixtures or images.
- Add a line under `## Unreleased` in `CHANGELOG.md` for anything a user would notice, marked `**Breaking:**` if users may need to act (see [docs/releasing.md](docs/releasing.md)).

## Releases

Releases are cut from the maintainer's clone with `npm run release -- <patch|minor|major|rc>`, which versions,
commits, tags and pushes `main` and the tag together; the Release workflow then publishes to npm, GHCR and GitHub
releases. Use `npm run sync` to catch up with GitHub. [docs/releasing.md](docs/releasing.md) covers the steps, release candidates,
breaking changes and the one-time setup; [docs/upgrading.md](docs/upgrading.md) is what users see.
