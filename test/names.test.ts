// Keelson was called Edgewatch until 0.10. These tests hold the promise that an
// installation from before the rename upgrades without changes: old variables,
// folders and database names are still read, and every release still ships the
// old npm package and image names (see "Old names keep working" in AGENTS.md).

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { databasePath, defaultDataDir, defaultHost, env } from "../src/names.ts";
import { Store } from "../src/store/db.ts";
import { Repo } from "../src/store/repo.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

function tempHome(): { home: string; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), "keelson-names-"));
  return { home, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

describe("settings from the environment", () => {
  test("KEELSON_* wins, EDGEWATCH_* is the fallback, and empty counts as unset", () => {
    assert.equal(env("PORT", { KEELSON_PORT: "5000", EDGEWATCH_PORT: "6000" }), "5000");
    assert.equal(env("PORT", { EDGEWATCH_PORT: "6000" }), "6000");
    assert.equal(env("PORT", { KEELSON_PORT: "", EDGEWATCH_PORT: "6000" }), "6000");
    assert.equal(env("PORT", {}), undefined);
  });

  test("the Docker image listens on every interface unless told otherwise, by either name", () => {
    assert.equal(defaultHost({}), "127.0.0.1");
    assert.equal(defaultHost({ KEELSON_INSTALL: "docker" }), "0.0.0.0");
    assert.equal(defaultHost({ KEELSON_INSTALL: "docker", EDGEWATCH_HOST: "127.0.0.1" }), "127.0.0.1");
  });

  test("the Docker image sets only the install marker, so variables on the container win", () => {
    const dockerfile = read("Dockerfile");
    assert.match(dockerfile, /KEELSON_INSTALL=docker/);
    assert.doesNotMatch(dockerfile, /(KEELSON|EDGEWATCH)_(HOST|PORT|DATA_DIR)=/, "an image default would hide an EDGEWATCH_* set on the container");
  });
});

describe("the data folder", () => {
  test("is ~/.keelson for a new installation", () => {
    const { home, cleanup } = tempHome();
    assert.equal(defaultDataDir(home, {}), join(home, ".keelson"));
    cleanup();
  });

  test("is the existing ~/.edgewatch when there is no ~/.keelson", () => {
    const { home, cleanup } = tempHome();
    mkdirSync(join(home, ".edgewatch"));
    assert.equal(defaultDataDir(home, {}), join(home, ".edgewatch"));
    mkdirSync(join(home, ".keelson"));
    assert.equal(defaultDataDir(home, {}), join(home, ".keelson"), "once ~/.keelson exists it is used");
    cleanup();
  });

  test("follows KEELSON_DATA_DIR or EDGEWATCH_DATA_DIR, and is /data in the Docker image", () => {
    const { home, cleanup } = tempHome();
    assert.equal(defaultDataDir(home, { EDGEWATCH_DATA_DIR: "/srv/old" }), "/srv/old");
    assert.equal(defaultDataDir(home, { KEELSON_DATA_DIR: "/srv/new", EDGEWATCH_DATA_DIR: "/srv/old" }), "/srv/new");
    assert.equal(defaultDataDir(home, { KEELSON_INSTALL: "docker" }), "/data");
    assert.equal(defaultDataDir(home, { KEELSON_INSTALL: "docker", EDGEWATCH_DATA_DIR: "/srv/old" }), "/srv/old");
    cleanup();
  });

  test("an existing edgewatch.db is opened with its data, and nothing new is created beside it", () => {
    const { home: dir, cleanup } = tempHome();
    assert.equal(databasePath(dir), join(dir, "keelson.db"));
    const old = new Repo(new Store(join(dir, "edgewatch.db")));
    old.entities.create("Mock Co");
    old.store.close();

    assert.equal(databasePath(dir), join(dir, "edgewatch.db"));
    const repo = new Repo(new Store(databasePath(dir)));
    assert.deepEqual(
      repo.entities.list().map((e) => e.name),
      ["Mock Co"],
    );
    repo.store.close();
    cleanup();
  });

  test("keelson.db is used once it exists", () => {
    const { home: dir, cleanup } = tempHome();
    writeFileSync(join(dir, "edgewatch.db"), "");
    writeFileSync(join(dir, "keelson.db"), "");
    assert.equal(databasePath(dir), join(dir, "keelson.db"));
    cleanup();
  });
});

describe("the old package and image names", () => {
  test("the edgewatch package only starts keelson, through a path keelson still has", () => {
    const shim = JSON.parse(read("packages/edgewatch/package.json"));
    assert.equal(shim.name, "edgewatch");
    assert.equal(shim.bin.edgewatch, "bin.js");
    assert.ok("keelson" in shim.dependencies);
    assert.match(read("packages/edgewatch/bin.js"), /import\("keelson\/dist\/bin\.js"\)/);

    const pkg = JSON.parse(read("package.json"));
    assert.equal(pkg.name, "keelson");
    assert.equal(pkg.bin.keelson, "dist/bin.js");
    assert.ok(pkg.files.includes("dist"));
    assert.equal(pkg.exports, undefined, "an exports field would block the edgewatch package's import of keelson/dist/bin.js");
  });

  test("every release publishes the edgewatch package and image too", () => {
    const wf = read(".github/workflows/release.yml");
    assert.match(wf, /working-directory: packages\/edgewatch/);
    assert.match(wf, /npm pkg set version="\$VERSION" "dependencies\.keelson=\$VERSION"/);
    assert.match(wf, /ghcr\.io\/\$\{\{ github\.repository_owner \}\}\/edgewatch/);
  });

  test("the browser still reads the theme and view saved under the old name", () => {
    assert.match(read("web/public/theme.js"), /localStorage\.getItem\("edgewatch-mode"\)/);
    assert.match(read("web/src/lib/scope.ts"), /"edgewatch-scope"/);
  });
});
