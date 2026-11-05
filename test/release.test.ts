// The release script behind the Release workflow: version bumps, release
// candidates, CHANGELOG roll-over, and refusing breaking changes in a
// compatible update.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { changelogAtTag, migrationsAddedSince, newLine, nextVersion, releasedNotesChanged, releaseNotes, rollChangelog, section } from "../scripts/release.ts";

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
