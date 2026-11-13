// Settings from the environment, the defaults that depend on where Keelson runs,
// and the image, which is the only way Keelson ships.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { defaultDataDir, defaultHost, env } from "../src/env.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

describe("settings from the environment", () => {
  test("are KEELSON_* variables, and empty counts as unset", () => {
    assert.equal(env("PORT", { KEELSON_PORT: "5000" }), "5000");
    assert.equal(env("PORT", { KEELSON_PORT: "" }), undefined);
    assert.equal(env("PORT", {}), undefined);
  });

  test("the Docker image listens on every interface unless told otherwise", () => {
    assert.equal(defaultHost({}), "127.0.0.1");
    assert.equal(defaultHost({ KEELSON_INSTALL: "docker" }), "0.0.0.0");
    assert.equal(defaultHost({ KEELSON_INSTALL: "docker", KEELSON_HOST: "127.0.0.1" }), "127.0.0.1");
    assert.match(read("Dockerfile"), /KEELSON_INSTALL=docker/);
  });

  test("the data folder is ~/.keelson, KEELSON_DATA_DIR, or /data in the Docker image", () => {
    assert.equal(defaultDataDir("/home/me", {}), join("/home/me", ".keelson"));
    assert.equal(defaultDataDir("/home/me", { KEELSON_DATA_DIR: "/srv/keelson" }), "/srv/keelson");
    assert.equal(defaultDataDir("/home/me", { KEELSON_INSTALL: "docker" }), "/data");
    assert.equal(defaultDataDir("/home/me", { KEELSON_INSTALL: "docker", KEELSON_DATA_DIR: "/srv/keelson" }), "/srv/keelson");
  });
});

describe("the image, the only way Keelson ships", () => {
  test("nothing is published to npm", () => {
    const pkg = JSON.parse(read("package.json"));
    assert.equal(pkg.name, "keelson");
    assert.equal(pkg.private, true, "private stops an accidental npm publish");
    const wf = read(".github/workflows/release.yml");
    assert.doesNotMatch(wf, /npm publish|NPM_TOKEN|registry\.npmjs\.org/);
    assert.match(wf, /images: ghcr\.io\/\$\{\{ github\.repository \}\}\n/);
  });

  test("the image keeps the node user's uid, so volumes from earlier images stay readable", () => {
    assert.match(read("Dockerfile"), /adduser -u 1000 /);
  });

  test("runtime dependencies are plain JavaScript, since the image's build stage runs on the build machine's platform", () => {
    const deps = Object.keys(JSON.parse(read("package.json")).dependencies);
    for (const dep of deps) {
      const meta = JSON.parse(read(`node_modules/${dep}/package.json`));
      assert.ok(!meta.gypfile && !meta.scripts?.install && !meta.scripts?.postinstall, `${dep} builds native code`);
      assert.ok(!meta.optionalDependencies, `${dep} may pull in a platform-specific package`);
    }
  });
});

test("the old name is gone, except where history keeps it", () => {
  // Released changelog sections, the decision log and a shipped migration can't change.
  const history = new Set(["CHANGELOG.md", "AGENTS.md", "src/store/db.ts"]);
  let files: string[] = [];
  try {
    files = execFileSync("git", ["grep", "-I", "-l", "-i", ["edge", "watch"].join("")], { cwd: new URL("..", import.meta.url), encoding: "utf8" })
      .split("\n")
      .filter(Boolean);
  } catch (e) {
    if ((e as { status?: number }).status !== 1) throw e; // 1: nothing found
  }
  assert.deepEqual(
    files.filter((f) => !history.has(f)),
    [],
  );
});
