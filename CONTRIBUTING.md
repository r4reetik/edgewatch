# Contributing to Edgewatch

Thanks for helping. Bug reports, wrong findings, new checks, docs and UI fixes are all welcome. For anything
bigger than a fix, open an issue or a discussion first so we can agree on the approach before you write code.
Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Setup

You need Node.js 26 LTS (`.nvmrc` pins it; `nvm install` picks it up). CI also runs the package on 26.13.0, the first Node 26 LTS and the oldest version it supports. The real minimum is `MIN_NODE` in `src/node-check.ts`; `engines` in package.json is deliberately wide, because npm treats it as a filter and would hand users of an older Node.js an older Edgewatch instead of the one that explains how to upgrade. Development runs TypeScript directly, with no build step for the server.

```bash
npm install
npm run dev -- --mock   # mocked Cloudflare data, nothing written to disk
npm run dev             # your real accounts, data kept in ./.edgewatch
```

Both start the API on port 4317 and the web app with hot reload on http://localhost:5173. The mock (`dev/mock/cloudflare.ts`) serves three accounts in two entities, with data that trips every family of checks.

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
  core/                 everything that talks to Cloudflare or judges what it found (no HTTP server, no database)
    sources.ts          every data source: coverage label, token permission, setup-screen probe
    cloudflare.ts       read-only API client (GET only, plus read-only GraphQL), retries, rate limits, coverage
    inventory.ts        collects one scan's data; analytics.ts holds the GraphQL reads
    cf-types.ts         shapes of the Cloudflare payloads we read
    checks/             check modules (one file per area), registered in checks/index.ts
    engine.ts           runs the modules, de-duplicates, scores
    catalog.ts          the check catalog, derived from the modules
  store/                SQLite: migrations (db.ts) and one repository per concern behind Repo
  server/               Hono app: routes/, guards in middleware.ts, validation, presentation
  shared/               code shared with the web app: API types, severities, triage, scope, filters
web/src/                React app: routes.tsx lists every page, shell.tsx holds shared state
dev/mock/               mocked Cloudflare API and seeding, for tests and the mock dev server
test/                   node:test suites; fixtures/ and checks/cases.ts for check tests
```

Rules worth knowing:

- **The scanner only reads.** REST calls are GET; GraphQL is POST but query-only. `test/integration.test.ts` fails on any other method.
- **`src/shared` is portable**: no `node:` imports, no DOM. The server returns its DTOs (`satisfies`), the web imports them as types.
- **Routes carry their guards** (`router.ts`): `routes(app).with(requireSession(auth))`. Moving a route never changes who can reach it.

## Adding a check

1. Pick the module in `src/core/checks/` for its area, or create one and list it in `checks/index.ts`.
2. Add its metadata next to the others: category, default severity, title, why it matters, how to fix it (write steps as `1. … 2. …`), a `docs` link to developers.cloudflare.com, and `requires`, the data sources it reads.
3. Report results in the module's function: `report("XXX-012", { zone, resource, pass, detail, evidence, link })`. Report passes too, because they count towards the score. Use `confidence: "likely"` for heuristics and traffic, and `"confirmed"` for live probes.
4. If it needs data Edgewatch doesn't collect yet, add a source to `sources.ts`, the read to `inventory.ts` (GET only), the field to `types.ts`, a mock route in `dev/mock/cloudflare.ts`, and a well-configured default in `test/fixtures/inventory.ts`.
5. Add a failing case to `test/checks/cases.ts`. It's typed by check ID, so it won't compile until you do. `test/contract.test.ts` checks that the case fails, that the baseline fixture passes, and that the metadata is complete.
6. Run `npm run docs` to regenerate `docs/checks.md` and `docs/permissions.md`. A test fails if you forget.

Severity guide: **critical** means it's exploitable now (a takeover, a leaked credential). **High** means a direct path in or a missing core protection. **Medium** is a weakness that needs another failure to matter. **Low** is hardening.

## Pull requests

- Keep each pull request to one change, with a test that would have caught the bug or covers the feature.
- Use the mock (`npm run dev -- --mock`) for screenshots. Never commit real account IDs, hostnames, emails or tokens, in code, fixtures or images.
- Add a line under `## Unreleased` in `CHANGELOG.md` for anything a user would notice, marked `**Breaking:**` if users may need to act (see [docs/releasing.md](docs/releasing.md)).

## Releases

Releases are cut from GitHub: **Actions → Release → Run workflow**. The workflow versions, tags and publishes
to npm, GHCR and GitHub releases. [docs/releasing.md](docs/releasing.md) covers the steps, release candidates,
breaking changes and the one-time setup; [docs/upgrading.md](docs/upgrading.md) is what users see.
