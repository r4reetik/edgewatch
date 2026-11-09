// The release script: version bumps, release candidates, CHANGELOG roll-over,
// refusing breaking changes in a compatible update, and cutting a release from
// the maintainer's machine so main never forks.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  bump,
  release,
  repairReleasedNotes,
  resolveAdjacent,
  sync,
  changelogAtTag,
  migrationsAddedSince,
  newLine,
  nextVersion,
  pinLine,
  releasedNotesChanged,
  releaseNotes,
  rollChangelog,
  section,
} from "../scripts/release.ts";

const LOG = `# Changelog

## Unreleased

- **Breaking:** CSV columns renamed.
- Faster scans.

## 0.4.1

- Fixed a crash.
`;

describe("versions", () => {
  test("bumps like npm, and release candidates open the next line", () => {
    assert.equal(nextVersion("0.4.1", "patch"), "0.4.2");
    assert.equal(nextVersion("0.4.1", "minor"), "0.5.0");
    assert.equal(nextVersion("0.4.1", "major"), "1.0.0");
    assert.equal(nextVersion("0.4.1", "rc"), "0.5.0-rc.1");
    assert.equal(nextVersion("0.5.0-rc.1", "rc"), "0.5.0-rc.2");
    assert.equal(nextVersion("0.5.0-rc.2", "minor"), "0.5.0", "finalises the candidate");
    assert.equal(nextVersion("0.5.0-rc.2", "patch"), "0.5.0");
    assert.equal(nextVersion("1.2.3", "rc"), "2.0.0-rc.1");
    assert.equal(nextVersion("2.0.0-rc.3", "major"), "2.0.0");
    assert.throws(() => nextVersion("1.0.0-beta.1", "patch"), /Unexpected version/);
  });

  test("a new release line is a minor before 1.0 and a major after", () => {
    assert.equal(newLine("0.4.1", "0.4.2"), false);
    assert.equal(newLine("0.4.1", "0.5.0"), true);
    assert.equal(newLine("1.2.0", "1.3.0"), false);
    assert.equal(newLine("1.2.0", "2.0.0"), true);
    assert.equal(newLine("0.5.0-rc.2", "0.5.0"), true, "finalising the candidate of a new line");
    assert.equal(newLine("2.0.0-rc.1", "2.0.0"), true);
  });
});

describe("changelog", () => {
  test("a release takes the unreleased notes and opens a new section", () => {
    const out = rollChangelog(LOG, "0.4.1", "0.5.0");
    assert.equal(section(out, "## Unreleased"), "");
    assert.match(section(out, "## 0.5.0") ?? "", /Faster scans/);
    assert.equal(releaseNotes(out, "0.5.0"), section(LOG, "## Unreleased"));
    assert.match(releaseNotes(out, "0.4.1"), /Fixed a crash/);
  });

  test("a release candidate keeps them unreleased, and its notes are those", () => {
    assert.equal(rollChangelog(LOG, "0.4.1", "0.5.0-rc.1"), LOG);
    assert.match(releaseNotes(LOG, "0.5.0-rc.1"), /Faster scans/);
  });

  test("refuses an empty release, and a breaking change in a compatible update", () => {
    assert.throws(() => rollChangelog("# Changelog\n\n## Unreleased\n\n## 0.4.1\n- x\n", "0.4.1", "0.4.2"), /Nothing to release/);
    assert.throws(() => rollChangelog(LOG, "0.4.1", "0.4.2"), /breaking change.*minor/);
    assert.throws(() => rollChangelog(LOG, "1.4.1", "1.5.0"), /breaking change.*major/);
  });

  test("the real CHANGELOG has an Unreleased section and notes for the current version", () => {
    const log = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8");
    const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.notEqual(section(log, "## Unreleased"), null, 'CHANGELOG.md needs a "## Unreleased" section');
    assert.ok(releaseNotes(log, version).length > 0);
  });

  test("counts migrations added to the shipped list since the last release", () => {
    const diff = `--- a/test/migrations.test.ts
+++ b/test/migrations.test.ts
@@ -19 +19 @@
-const SHIPPED = ["1d4e7bd803fb7be7", "03a85dfc75f3fd2a"];
+const SHIPPED = ["1d4e7bd803fb7be7", "03a85dfc75f3fd2a", "aaaaaaaaaaaaaaaa"];`;
    assert.equal(migrationsAddedSince(diff), 1);
    assert.equal(migrationsAddedSince(""), 0);
  });
});

describe("released notes", () => {
  test("notes that moved under a released version are caught", () => {
    const released = "# Changelog\n\n## Unreleased\n\n## 0.5.0\n\n- Node 26.\n\n## 0.4.0\n\n- Old.\n";
    const merged = "# Changelog\n\n## Unreleased\n\n## 0.5.0\n\n- Node 26.\n- Split Run scan.\n\n## 0.4.0\n\n- Old.\n";
    const atTag = (v: string) => (v === "0.5.0" || v === "0.4.0" ? released : null);
    assert.deepEqual(releasedNotesChanged(merged, atTag), ["0.5.0"]);
    assert.deepEqual(releasedNotesChanged(released, atTag), []);
    assert.deepEqual(
      releasedNotesChanged(merged, () => null),
      [],
      "versions without a tag aren't compared",
    );
  });

  test("CHANGELOG.md still has the notes each tagged release shipped with", () => {
    const changed = releasedNotesChanged(readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8"), changelogAtTag);
    assert.deepEqual(changed, [], `move notes added after ${changed.join(", ")} under "## Unreleased"`);
  });
});

describe("install instructions", () => {
  test("follow the newest release line, leaving exact versions and @latest alone", () => {
    const docs =
      "image: ghcr.io/r4reetik/edgewatch:0.4\nThe Docker tag `:0.4` above; `npm install -g\nedgewatch@0.4`, edgewatch@0.4.1, edgewatch@latest, http://edgewatch:4317";
    assert.equal(
      pinLine(docs, "0.6"),
      "image: ghcr.io/r4reetik/edgewatch:0.6\nThe Docker tag `:0.6` above; `npm install -g\nedgewatch@0.6`, edgewatch@0.4.1, edgewatch@latest, http://edgewatch:4317",
    );
    assert.equal(pinLine("ghcr.io/r4reetik/edgewatch:0.9", "1"), "ghcr.io/r4reetik/edgewatch:1");
  });
});

describe("cutting a release from the maintainer's machine", () => {
  // Throwaway repositories, isolated from the user's git configuration (signing, hooks, default branch).
  const root = mkdtempSync(join(tmpdir(), "edgewatch-release-"));
  const cfg = join(root, "gitconfig");
  writeFileSync(
    cfg,
    "[user]\n\tname = Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false\n",
  );
  const env = { ...process.env, GIT_CONFIG_GLOBAL: cfg, GIT_CONFIG_NOSYSTEM: "1" };
  const saved = { ...process.env };
  before(() => Object.assign(process.env, env));
  after(() => {
    for (const k of ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"]) if (saved[k] === undefined) delete process.env[k];
    rmSync(root, { recursive: true, force: true });
  });
  // stderr is captured, so git's chatter ("cloned an empty repository") stays out of the test output.
  const git = (cwd: string, ...args: string[]) =>
    execFileSync("git", args, { cwd, encoding: "utf8", env: { ...env }, stdio: ["ignore", "pipe", "pipe"] }).trim();
  const write = (dir: string, f: string, text: string) => {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    writeFileSync(join(dir, f), text);
  };
  const read = (dir: string, f: string) => readFileSync(join(dir, f), "utf8");

  /** origin with a v0.6.0 release, and the maintainer's clone of it. */
  function repos() {
    const id = Math.random().toString(36).slice(2);
    const origin = join(root, `origin-${id}.git`),
      local = join(root, `local-${id}`);
    git(root, "init", "--quiet", "--bare", origin);
    git(root, "clone", "--quiet", origin, local);
    write(local, "package.json", `${JSON.stringify({ name: "edgewatch", version: "0.6.0", description: "For Cloudflare." }, null, 2)}\n`);
    write(local, "package-lock.json", `${JSON.stringify({ name: "edgewatch", version: "0.6.0", packages: { "": { version: "0.6.0" } } }, null, 2)}\n`);
    write(local, "CHANGELOG.md", "# Changelog\n\n## Unreleased\n\n## 0.6.0\n\n- Old.\n");
    write(local, "README.md", "docker pull ghcr.io/r4reetik/edgewatch:0.6\n");
    write(local, "docs/deployment.md", "npm install -g edgewatch@0.6\n");
    git(local, "add", "-A");
    git(local, "commit", "--quiet", "-m", "Start");
    git(local, "tag", "-a", "v0.6.0", "-m", "v0.6.0");
    git(local, "push", "--quiet", "origin", "main", "v0.6.0");
    return { origin, local };
  }

  /** What the old workflow did: commit "Release vX" to origin/main from a fresh checkout of it. */
  function releaseFromCi(origin: string, kind: string) {
    const ci = join(root, `ci-${Math.random().toString(36).slice(2)}`);
    git(root, "clone", "--quiet", origin, ci);
    const { next } = bump(kind, ci);
    git(ci, "commit", "--quiet", "-am", `Release v${next}`);
    git(ci, "tag", "-a", `v${next}`, "-m", `v${next}`);
    git(ci, "push", "--quiet", "origin", "HEAD:main", `v${next}`);
  }

  test("sync merges a release made elsewhere and puts notes that landed under it back in Unreleased", () => {
    const { origin, local } = repos();
    write(local, "CHANGELOG.md", "# Changelog\n\n## Unreleased\n\n- Node 26.\n\n## 0.6.0\n\n- Old.\n");
    git(local, "commit", "--quiet", "-am", "Node 26");
    git(local, "push", "--quiet", "origin", "main");
    releaseFromCi(origin, "minor");
    // Work done meanwhile, never pushed: the release didn't include it. It also edits the line next to "version",
    // which git reports as a conflict with the release's version bump.
    write(local, "CHANGELOG.md", "# Changelog\n\n## Unreleased\n\n- Node 26.\n- Owner suggestions.\n\n## 0.6.0\n\n- Old.\n");
    write(local, "package.json", `${JSON.stringify({ name: "edgewatch", version: "0.6.0", description: "Now with Vercel." }, null, 2)}\n`);
    git(local, "commit", "--quiet", "-am", "Owner suggestions");

    const r = sync(local, () => {});
    assert.equal(r.merged, 1);
    assert.deepEqual(r.moved, ["- Owner suggestions."]);
    const log = read(local, "CHANGELOG.md");
    assert.equal(section(log, "## Unreleased"), "- Owner suggestions.");
    assert.equal(section(log, "## 0.7.0"), "- Node 26.");
    assert.deepEqual(JSON.parse(read(local, "package.json")), { name: "edgewatch", version: "0.7.0", description: "Now with Vercel." });
    assert.equal(git(local, "status", "--porcelain"), "", "the repair is committed");
  });

  test("release commits, tags and pushes main and the tag together, including unpushed work", () => {
    const { origin, local } = repos();
    write(local, "CHANGELOG.md", "# Changelog\n\n## Unreleased\n\n- Vercel support.\n\n## 0.6.0\n\n- Old.\n");
    git(local, "commit", "--quiet", "-am", "Vercel");
    const r = release("minor", { dir: local, check: false, log: () => {} });
    assert.equal(r.next, "0.7.0");
    assert.equal(git(local, "rev-parse", "HEAD"), git(origin, "rev-parse", "main"), "origin/main is exactly the local main");
    assert.equal(git(origin, "rev-parse", "v0.7.0^{commit}"), git(origin, "rev-parse", "main"));
    const log = read(local, "CHANGELOG.md");
    assert.equal(section(log, "## 0.7.0"), "- Vercel support.");
    assert.equal(section(log, "## Unreleased"), "");
    assert.match(read(local, "README.md"), /edgewatch:0\.7/, "a new line moves the install instructions");
  });

  test("release refuses uncommitted work and other branches, and a dry run changes nothing", () => {
    const { local } = repos();
    write(local, "CHANGELOG.md", "# Changelog\n\n## Unreleased\n\n- Fix.\n\n## 0.6.0\n\n- Old.\n");
    assert.throws(() => release("patch", { dir: local, check: false, log: () => {} }), /Commit or stash/);
    git(local, "commit", "--quiet", "-am", "Fix");
    const lines: string[] = [];
    assert.equal(release("patch", { dir: local, dryRun: true, log: (m) => lines.push(m) }).pushed, false);
    assert.match(lines.join("\n"), /0\.6\.0 → 0\.6\.1/);
    assert.equal(git(local, "tag", "--list", "v0.6.1"), "");
    git(local, "switch", "--quiet", "-c", "feature");
    assert.throws(() => release("patch", { dir: local, check: false, log: () => {} }), /Releases come from main/);
  });
});

test("resolveAdjacent combines edits on neighbouring lines and leaves real conflicts alone", () => {
  const hunk = (ours: string) =>
    [
      "{",
      "<<<<<<< HEAD",
      ours,
      '  "description": "For Cloudflare and Vercel.",',
      "||||||| base",
      '  "version": "0.6.0",',
      '  "description": "For Cloudflare.",',
      "=======",
      '  "version": "0.7.0",',
      '  "description": "For Cloudflare.",',
      ">>>>>>> origin/main",
      "}",
    ].join("\n");
  assert.equal(resolveAdjacent(hunk('  "version": "0.6.0",')), '{\n  "version": "0.7.0",\n  "description": "For Cloudflare and Vercel.",\n}');
  assert.equal(resolveAdjacent(hunk('  "version": "0.6.1",')), null, "both sides changed the version: a person decides");
});

test("repairReleasedNotes restores what a release shipped and keeps everything else", () => {
  const shipped = "# Changelog\n\n## Unreleased\n\n## 0.7.0\n\n- A.\n\n## 0.6.0\n\n- Old.\n";
  const merged = "# Changelog\n\n## Unreleased\n\n- C.\n\n## 0.7.0\n\n- A.\n- B.\n\n## 0.6.0\n\n- Old.\n";
  const { changelog, moved } = repairReleasedNotes(merged, (v) => (v === "0.7.0" ? shipped : null));
  assert.deepEqual(moved, ["- B."]);
  assert.equal(section(changelog, "## Unreleased"), "- B.\n- C.");
  assert.equal(section(changelog, "## 0.7.0"), "- A.");
  assert.deepEqual(repairReleasedNotes(shipped, () => shipped).moved, []);
});

test("the Release workflow only publishes tags and never commits to main", () => {
  const wf = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  assert.ok(!/workflow_dispatch/.test(wf), "releases are cut with npm run release, not from the Actions tab");
  assert.ok(!/git (commit|push)/.test(wf), "the workflow must not commit or push: that forks main");
  assert.match(wf, /merge-base --is-ancestor/, "a tag that isn't on main is refused");
});
