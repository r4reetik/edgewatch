// The Node.js version check that runs before anything else: too old stops with
// upgrade steps, Node 24 warns, Node 26 and later run quietly.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkNode, MIN_NODE, older, upgradeCommand } from "../src/node-check.ts";

const linux = (env: Record<string, string> = {}, execPath = "/usr/bin/node") => [env, execPath, "linux"] as const;

describe("Node.js version check", () => {
  test("compares versions part by part", () => {
    assert.equal(older("22.13.0", MIN_NODE), true);
    assert.equal(older("24.22.0", "24.22.1"), true);
    assert.equal(older("24.22.1", "24.22.1"), false);
    assert.equal(older("24.100.0", "24.22.1"), false, "numerically, not as text");
    assert.equal(older("v26.0.0", "24.22.1"), false);
  });

  test("too old stops with upgrade steps and the latest Edgewatch", () => {
    const c = checkNode("22.13.0", ...linux({ NVM_DIR: "/home/me/.nvm" }));
    assert.equal(c.level, "error");
    assert.match(c.message, /this is Node\.js 22\.13\.0/);
    assert.match(c.message, /nvm install 26 && nvm alias default 26/);
    assert.match(c.message, /npx edgewatch@latest/);
    assert.equal(checkNode("18.0.0", ...linux()).level, "error");
  });

  test("Node 24 runs with a recommendation, Node 26 and later quietly", () => {
    const warn = checkNode("24.22.1", ...linux());
    assert.equal(warn.level, "warn");
    assert.match(warn.message, /Node\.js 26 LTS is recommended/);
    assert.equal(checkNode("25.9.0", ...linux()).level, "warn");
    assert.deepEqual(checkNode("26.13.0", ...linux()), { level: "ok", message: "" });
    assert.equal(checkNode("28.1.0", ...linux()).level, "ok");
  });

  test("suggests the Node.js manager in use", () => {
    assert.match(upgradeCommand({}, "/Users/me/.nvm/versions/node/v22.13.0/bin/node", "darwin"), /^nvm install 26/);
    assert.match(upgradeCommand({ FNM_MULTISHELL_PATH: "/tmp/fnm" }, "/x/node", "darwin"), /^fnm install 26/);
    assert.match(upgradeCommand({ VOLTA_HOME: "/v" }, "/x/node", "linux"), /^volta install node@26/);
    assert.match(upgradeCommand({}, "/opt/homebrew/Cellar/node@22/22.13.0/bin/node", "darwin"), /^brew install node@26/);
    assert.match(upgradeCommand({}, "C:\\Program Files\\nodejs\\node.exe", "win32"), /^winget install/);
    assert.match(upgradeCommand({}, "/usr/bin/node", "linux"), /nodejs\.org/);
  });

  test("npm can't filter out the newest Edgewatch on an older Node.js", () => {
    // A strict engines range makes npm pick an older release instead; the launcher enforces MIN_NODE.
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.equal(pkg.engines.node, ">=18");
    assert.equal(pkg.bin.edgewatch, "dist/bin.js");
  });
});
