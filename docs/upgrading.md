# Upgrading

Keelson is released from GitHub. Every release is published as a container image to the GitHub container
registry (`ghcr.io/r4reetik/keelson`), with notes on the [releases page](https://github.com/r4reetik/keelson/releases).
It isn't published to npm.

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
- a token permission that's now required
- a database migration (they only come with a new release line, so going back within a line always works)

Release notes mark each of these with **Breaking:** and say what to do. Before a breaking release, a
**release candidate** (`0.5.0-rc.1`) is published for anyone who wants to try it first. Candidates never
reach `:latest` or the release-line tags.

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

## What happens on upgrade

On start, Keelson applies any database migrations the new version brings, in order, so you can skip
versions: 0.4.0 can go straight to 0.9.0. **Before it changes anything, it copies the database** to
`<data-dir>/backups/keelson-<date>-schema<N>.db` (owner-only, the newest three are kept) and logs where.
Tokens in `credentials.json` are never changed by an upgrade.

## Rolling back

Going back to an older version on the **same release line** needs nothing special: run the older image.

Going back across a release line, after the new version changed the database:

1. Stop Keelson.
2. Replace `<data-dir>/keelson.db` with the backup from before the upgrade (the newest file in
   `<data-dir>/backups/`), and delete `keelson.db-wal` and `keelson.db-shm` if they exist.
3. Start the older version.

If you start an older version on a database a newer one already migrated, Keelson refuses to start and
names the backup to restore, rather than misreading your data. Scans and triage made after the upgrade
aren't in the backup.

## Upgrading from Edgewatch

Keelson was called Edgewatch until 0.10.

- **Docker:** nothing has to change. Every release is also published as `ghcr.io/r4reetik/edgewatch`, so your
  current image keeps upgrading. Switch the image to `ghcr.io/r4reetik/keelson` with the same tag when convenient;
  the `/data` volume stays as it is.
- **npx or npm (`npx edgewatch`, `npm install -g edgewatch`):** Keelson is no longer published to npm, so npm
  installations stay on 0.9 and stop receiving updates. Move to the image and keep your data by mounting your data
  folder, which is `~/.edgewatch` unless you set `EDGEWATCH_DATA_DIR`. Stop Edgewatch, then:

  ```bash
  docker run -d --name keelson -p 127.0.0.1:4317:4317 \
    --user "$(id -u):$(id -g)" -v ~/.edgewatch:/data \
    -e KEELSON_PASSWORD='a-long-admin-password' \
    ghcr.io/r4reetik/keelson:latest
  ```

  Your accounts, scans, triage and tokens carry over. `--user` runs Keelson as you, so it can read the files
  Edgewatch created. Unlike the npm version, the container asks for a password even on your own machine, because
  it can't tell how its port was published. Remove the old package with `npm uninstall -g edgewatch`.
- **Settings:** every `EDGEWATCH_*` variable is still read when its `KEELSON_*` name isn't set. Rename them
  when convenient; a `KEELSON_*` variable wins over its old name.
- **Data:** an existing `edgewatch.db` is used when there is no `keelson.db`, and nothing is moved. To switch to
  the new name, stop Keelson, rename the database (with its `-wal` and `-shm` files) to `keelson.db`, and start it
  again.
- **Sign-in:** an upgrade restarts the server, which signs everyone out, as with any upgrade.
