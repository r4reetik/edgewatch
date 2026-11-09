# Releasing

For maintainers. Users' side of this is in [upgrading.md](upgrading.md).

## While working

Every user-visible change adds a line under `## Unreleased` at the top of `CHANGELOG.md`, in the pull request
that makes it. Write it for someone running Edgewatch, not for a reviewer.

Mark anything that may need users to act with `**Breaking:**` and say what to do:

```markdown
- **Breaking:** the `--password-file` flag is gone; set `EDGEWATCH_PASSWORD` instead.
```

That marker matters: the release script refuses to ship it as a compatible update, and running installations
read it from the GitHub release to warn before upgrading.

## Cutting a release

From your clone, on `main`, with everything committed:

```bash
npm run release -- minor
```

Pick the bump:

| Bump | When | Example |
|---|---|---|
| `patch` | fixes only | 0.4.1 → 0.4.2 |
| `minor` | new checks or features; before 1.0, also breaking changes or a database migration | 0.4.2 → 0.5.0 |
| `major` | breaking changes, from 1.0 | 1.6.0 → 2.0.0 |
| `rc` | a release candidate of the next line, to try a breaking release first | 0.4.2 → 0.5.0-rc.1, then rc.2… |

To finalise a candidate, release `minor` before 1.0 (0.5.0-rc.2 → 0.5.0) or `major` from 1.0 (2.0.0-rc.1 → 2.0.0). `patch` finalises too; `major` on a 0.x candidate jumps to 1.0.0.

`npm run release -- minor --dry-run` shows the version, what it would merge and push, and the notes, without changing anything.

The command (`scripts/release.ts`):

1. stops unless you're on `main` with nothing uncommitted, so work in progress can't slip into a release;
2. syncs with `origin/main` (see below), so the release has both what's on GitHub and everything you haven't pushed;
3. runs `npm run check`;
4. bumps `package.json` and `package-lock.json`, renames `## Unreleased` to the new version and opens a new
   `## Unreleased`, and on a new release line points the README and deployment guide at it. It stops if there
   are no notes, or if the bump stays on the current release line while the notes mark a breaking change or a
   database migration was added;
5. commits `Release vX.Y.Z`, tags it, and pushes `main` and the tag in one atomic push: both land or neither does.

The tag starts the Release workflow, which runs `npm run check` on it, refuses a tag that isn't on `main`,
publishes to npm (`latest`, or `next` for a candidate) with provenance, pushes the multi-arch image to
`ghcr.io/r4reetik/edgewatch` with the tags in [upgrading.md](upgrading.md#docker), and creates the GitHub release
with that version's notes (a prerelease for candidates). Running installations see it within a day.

**Why from your machine.** The workflow used to commit `Release vX.Y.Z` to `main` on GitHub. That forked `main`
on every release: commits you hadn't pushed were silently left out, and the next `git pull` merged
`CHANGELOG.md` across the rename of `## Unreleased`, moving new notes under the version just released. Now the
release commit is made where your work is, and GitHub only ever receives a `main` that already contains it.
The workflow never commits, and a test fails if it starts to.

## Keeping up with GitHub

`npm run sync` is a `git pull` that knows about releases: it fetches, merges what's new on `origin/main`
(merged pull requests, Dependabot), and if a merge left notes under a version that's already released, it moves
them back under `## Unreleased` (comparing with what that version's tag shipped) and commits the repair. It
stops on a merge conflict and leaves `main` as it was. `npm run release` runs it first, so you rarely need it on
its own.

A plain `git pull` is safe now too, since no release commit is ever made on GitHub. If notes ever do end up under
a released version, the tests fail and say to run `npm run sync`.

## Setup, once

- **npm:** add an `NPM_TOKEN` repository secret: a granular access token with read and write access to
  `edgewatch` (or to all packages, for the very first publish, before the package exists). Once it's
  published, you can switch to npm trusted publishing for this repository and `release.yml` instead.
- **Labels:** create `checks` and `false-positive` (the issue forms apply them; GitHub has `bug` and
  `enhancement` already).
- **Protected `main`:** `npm run release` pushes the release commit and tag to `main` as you, so you need to be
  allowed to push to `main` (or to bypass the rule). The workflow itself needs no extra token.
- **GHCR:** after the first release, make the `edgewatch` package public under the repository's Packages.

If a release fails halfway (npm down, a flaky Docker build), re-run the failed jobs: each publishing step skips
what's already done. If the push itself is refused (someone pushed to `main` a moment earlier), nothing was
published: delete the local tag (`git tag -d vX.Y.Z`), undo the release commit (`git reset --hard HEAD~1`), and run
`npm run release` again; it merges their commits first.

## Breaking changes

Before shipping one:

- Can it be avoided? Accept the old name and the new one for a release line, logging a warning for the
  old one, and remove it in the next line.
- Database changes are new migrations appended to `MIGRATIONS` in `src/store/db.ts`, and they ship only in a
  new release line: an older version refuses a database with migrations it doesn't know, so a patch with one
  would break rolling back within the line (the release script refuses it). Never edit a shipped migration
  (`test/migrations.test.ts` fails if you do), and add its fingerprint to the list in that test.
- Publish an `rc` first, and say in the notes what to test.
- In the notes, say what breaks, who's affected, and the exact steps to take.
