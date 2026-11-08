// AGENTS.md records the project's decisions for coding agents and people, and CLAUDE.md imports it.
// These tests catch it drifting from the code: a renamed file, a removed script, a new Node.js line.
// When one fails, update AGENTS.md (and its decision log) rather than loosening the test.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { MIN_NODE, NODE_MAJOR } from "../src/node-check.ts";

const root = new URL("../", import.meta.url);
const read = (p: string) => readFileSync(new URL(p, root), "utf8");
const agents = read("AGENTS.md");

/** Repository paths named in `code` or in Markdown links. */
function namedPaths(md: string): string[] {
  const code = [...md.matchAll(/`([^`\s]+)`/g)].map((m) => m[1]);
  const links = [...md.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)].map((m) => m[1]).filter((p) => !/^https?:/.test(p));
  const repoPath = /^(?:src|web|test|dev|scripts|docs|\.github)\/[\w./-]+$|^[\w.-]+\.(?:md|json)$|^Dockerfile$|^\.nvmrc$/;
  return [...new Set([...code, ...links])].filter((p) => repoPath.test(p) && !p.includes("*"));
}

test("every path AGENTS.md names exists", () => {
  const paths = namedPaths(agents);
  assert.ok(paths.length > 20, "found the paths");
  const missing = paths.filter((p) => !existsSync(new URL(p, root)) && !existsSync(new URL(p.replace(/\/$/, ""), root)));
  assert.deepEqual(missing, [], "AGENTS.md names files that don't exist: update it");
});

test("every npm script AGENTS.md mentions exists", () => {
  const scripts = Object.keys(JSON.parse(read("package.json")).scripts);
  const named = [...agents.matchAll(/npm run ([\w:-]+)/g)].map((m) => m[1]);
  assert.ok(named.length > 0);
  assert.deepEqual(
    named.filter((s) => !scripts.includes(s)),
    [],
  );
});

test("AGENTS.md states the Node.js version the code enforces", () => {
  assert.match(agents, new RegExp(`Node\\.js ${NODE_MAJOR} LTS only`));
  assert.ok(agents.includes(MIN_NODE), `AGENTS.md should name the minimum, ${MIN_NODE}`);
  assert.equal(read(".nvmrc").trim(), String(NODE_MAJOR));
  assert.match(read("Dockerfile"), new RegExp(`node:${NODE_MAJOR}-slim`));
});

test("CLAUDE.md imports AGENTS.md, and AGENTS.md keeps its rules and log", () => {
  assert.match(read("CLAUDE.md"), /^@AGENTS\.md$/m);
  for (const heading of ["## Keep this file current", "## Hard rules", "## Decision log"]) assert.ok(agents.includes(heading), heading);
  const dates = [...agents.slice(agents.indexOf("## Decision log")).matchAll(/^- (\d{4}-\d{2}-\d{2}):/gm)].map((m) => m[1]);
  assert.ok(dates.length > 0, "the decision log has entries");
  assert.deepEqual(dates, [...dates].sort().reverse(), "the decision log is newest first");
});
