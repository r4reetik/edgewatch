# Upgrading

Keelson is released from GitHub. Every release is published to npm and to the GitHub container registry
at the same time, with notes on the [releases page](https://github.com/r4reetik/keelson/releases).

## How versions work

Keelson follows [semantic versioning](https://semver.org), counted in **release lines**:

| | Before 1.0 | From 1.0 |
|---|---|---|
| A release line | `0.4`, `0.5`… | `1`, `2`… |
| Compatible updates (fixes, new checks, features) | `0.4.0` → `0.4.1` → `0.4.2` | `1.2.0` → `1.3.0` → `1.3.1` |
| Breaking changes, only in a new line | `0.4.x` → `0.5.0` | `1.x` → `2.0.0` |

So **staying on your release line is always safe to automate**, and moving to a new line is a choice you make
after reading its notes. A breaking change is anything that could need you to act:

- a command-line flag or environment variable removed or renamed
- a changed export or alert format (CSV columns, JSON, webhook payloads)
- a newer minimum Node.js version, or a token permission that's now required
- a database migration (they only come with a new release line, so going back within a line always works)

Release notes mark each of these with **Breaking:** and say what to do. Before a breaking release, a
**release candidate** (`0.5.0-rc.1`) is published for anyone who wants to try it first. Candidates never
reach `:latest`, npm's default tag, or the release-line tags.

Deprecations come first where possible: a setting that's going away keeps working for at least one release
line, with a warning in the log saying what replaces it.

## Knowing when there's an update

Keelson checks GitHub shortly after it starts and then once a day, and shows **"0.4.2 available"** in the sidebar, with details, release
notes and the exact upgrade command under **Settings → Updates**. A release with breaking changes is
flagged before you upgrade. The check reads the public list of releases and sends nothing about your
installation; turn it off in Settings, or for a whole deployment with `KEELSON_UPDATE_CHECK=off`.

To be told without opening Keelson, **watch** the repository on GitHub with *Custom → Releases*.

## Docker

Pick the tag that matches how much change you want to take automatically:

| Tag | You get | Breaking changes |
|---|---|---|
| `:0.4` (the release line) | every compatible update in 0.4 | never; **recommended** |
| `:latest` | every stable release | yes, when a new line ships |
| `:0.4.1` | exactly that version | never; you upgrade by changing the tag |
| `:0.5.0-rc.1` | a release candidate, to test | possibly |

From 1.0, the line tag is the major version (`:1`).

**Updating by hand:**

```bash
docker compose pull && docker compose up -d
```

**Updating automatically**, on a line tag. Any scheduler works; with cron:

```cron
# Every day at 04:30, take compatible updates and restart if the image changed.
30 4 * * * cd /srv/keelson && docker compose pull -q && docker compose up -d
```

Image-update tools that watch a registry (Watchtower and similar, or Renovate if you deploy from a Git
repository) work the same way; point them at the line tag, not `:latest`.

## npm

```bash
npm install -g keelson@0.4     # newest 0.4.x: compatible updates only
npm install -g keelson@latest  # newest stable release
```

Restart Keelson after installing. With npx, `npx keelson@latest` always starts the newest release. Plain
`npx keelson` also looks for a newer one, except when Keelson is installed globally (`npm install -g`):
then it runs that copy, whatever its version.

On a Node.js older than Keelson needs, the `keelson` command stops and says how to upgrade Node.js
rather than falling back to an older Keelson.

## What happens on upgrade

On start, Keelson applies any database migrations the new version brings, in order, so you can skip
versions: 0.4.0 can go straight to 0.9.0. **Before it changes anything, it copies the database** to
`<data-dir>/backups/keelson-<date>-schema<N>.db` (owner-only, the newest three are kept) and logs where.
Tokens in `credentials.json` are never changed by an upgrade.

## Rolling back

Going back to an older version on the **same release line** needs nothing special: run the older image or
package.

Going back across a release line, after the new version changed the database:

1. Stop Keelson.
2. Replace `<data-dir>/keelson.db` with the backup from before the upgrade (the newest file in
   `<data-dir>/backups/`), and delete `keelson.db-wal` and `keelson.db-shm` if they exist.
3. Start the older version.

If you start an older version on a database a newer one already migrated, Keelson refuses to start and
names the backup to restore, rather than misreading your data. Scans and triage made after the upgrade
aren't in the backup.

## Upgrading from Edgewatch

Keelson was called Edgewatch until 0.10. Nothing has to change for an existing installation to keep working:

- **npx and npm:** the `edgewatch` package is still published with every release and starts Keelson, so
  `npx edgewatch@latest` keeps working. Switch to `npx keelson@latest` (or `npm install -g keelson@latest`,
  then `npm uninstall -g edgewatch`) when convenient.
- **Docker:** every release is also published as `ghcr.io/r4reetik/edgewatch`. Switch the image to
  `ghcr.io/r4reetik/keelson` with the same tag; the `/data` volume stays as it is.
- **Settings:** every `EDGEWATCH_*` variable is still read when its `KEELSON_*` name isn't set. Rename them
  when convenient; a `KEELSON_*` variable wins over its old name.
- **Data:** an existing `~/.edgewatch` folder is used when there is no `~/.keelson`, and an existing
  `edgewatch.db` when there is no `keelson.db`. Nothing is moved. To switch to the new names, stop Keelson,
  rename the folder to `~/.keelson` and the database (with its `-wal` and `-shm` files) to `keelson.db`, and
  start it again.
- **Sign-in:** an upgrade restarts the server, which signs everyone out, as with any upgrade.
