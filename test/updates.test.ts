// Update checks: semver ordering, release lines, breaking-change detection from
// release notes, and that a disabled or failing check never gets in the way.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { compareVersions, evaluate, releaseLine, UpdateChecker } from "../src/updates.ts";
import { makeApp } from "./helpers/app.ts";

const release = (tag: string, body = "", o: { prerelease?: boolean; draft?: boolean } = {}) => ({
  tag_name: tag,
  html_url: `https://github.com/r4reetik/keelson/releases/tag/${tag}`,
  published_at: "2026-12-01T00:00:00Z",
  body,
  draft: !!o.draft,
  prerelease: !!o.prerelease,
});

describe("versions", () => {
  test("compare like semver, with prereleases before their release", () => {
    const sorted = ["0.10.0", "0.4.0", "0.4.1", "1.0.0", "1.0.0-rc.2", "1.0.0-rc.10", "v0.9.3"].sort(compareVersions);
    assert.deepEqual(sorted, ["0.4.0", "0.4.1", "v0.9.3", "0.10.0", "1.0.0-rc.2", "1.0.0-rc.10", "1.0.0"]);
  });

  test("release lines: minor before 1.0, major after", () => {
    assert.equal(releaseLine("0.4.7"), "0.4");
    assert.equal(releaseLine("1.2.3"), "1");
    assert.equal(releaseLine("2.0.0-rc.1"), "2");
  });
});

describe("evaluate", () => {
  test("finds the newest stable release, ignoring drafts and prereleases", () => {
    const r = evaluate("0.4.0", [
      release("v0.4.0"),
      release("v0.4.1"),
      release("v0.5.0-rc.1", "", { prerelease: true }),
      release("v0.6.0", "", { draft: true }),
    ]);
    assert.equal(r.latest?.version, "0.4.1");
    assert.equal(r.latest?.sameLine, true);
    assert.equal(r.breaking, false);
    assert.equal(r.newerCount, 1);
  });

  test("flags breaking changes in any release between this one and the latest", () => {
    const r = evaluate("0.4.1", [release("v0.5.0", "- **Breaking:** CSV columns renamed"), release("v0.5.1", "- Fixed a crash")]);
    assert.equal(r.latest?.version, "0.5.1");
    assert.equal(r.latest?.sameLine, false);
    assert.equal(r.breaking, true);
    assert.equal(r.newerCount, 2);
    assert.equal(r.inLine, null, "nothing newer on 0.4");
    assert.equal(evaluate("0.4.1", [release("v0.5.0", "### Breaking changes\n- …")]).breaking, true);
    assert.equal(evaluate("0.5.0", [release("v0.5.0", "- **Breaking:** old"), release("v0.5.1")]).breaking, false, "already installed");
  });

  test("offers the newest compatible update when the latest starts a new line", () => {
    const r = evaluate("0.4.0", [release("v0.4.2"), release("v0.5.0", "- **Breaking:** x")]);
    assert.equal(r.latest?.version, "0.5.0");
    assert.equal(r.inLine?.version, "0.4.2");
    assert.equal(evaluate("0.4.0", [release("v0.4.2")]).inLine, null, "already the latest");
  });

  test("up to date", () => {
    assert.deepEqual(evaluate("0.4.1", [release("v0.4.1"), release("v0.4.0")]), { latest: null, inLine: null, breaking: false, newerCount: 0 });
  });
});

describe("checker", () => {
  const fakeFetch = (respond: () => Response) => {
    const calls: string[] = [];
    const f = (async (url: string | URL) => {
      calls.push(String(url));
      return respond();
    }) as typeof fetch;
    return { f, calls };
  };

  test("reads the public releases list and keeps the last result when a check fails", async () => {
    let ok = true;
    const { f, calls } = fakeFetch(() => (ok ? new Response(JSON.stringify([release("v0.4.2")])) : new Response("", { status: 503 })));
    const c = new UpdateChecker({ version: "0.4.0", repository: "r4reetik/keelson", install: "docker", enabled: () => true, fetch: f });
    assert.equal((await c.check()).latest?.version, "0.4.2");
    assert.equal(calls[0], "https://api.github.com/repos/r4reetik/keelson/releases?per_page=30");
    ok = false;
    const after = await c.check();
    assert.equal(after.latest?.version, "0.4.2", "kept");
    assert.match(after.error ?? "", /503/);
  });

  test("never contacts GitHub when switched off, in Settings, by environment, or without a repository", async () => {
    const { f, calls } = fakeFetch(() => new Response("[]"));
    const base = { version: "0.4.0", install: "npm" as const, fetch: f };
    await new UpdateChecker({ ...base, repository: "r4reetik/keelson", enabled: () => false }).check();
    const locked = new UpdateChecker({ ...base, repository: "r4reetik/keelson", enabled: () => true, lockedOff: true });
    await locked.check();
    await new UpdateChecker({ ...base, repository: null, enabled: () => true }).check();
    assert.equal(calls.length, 0);
    assert.equal(locked.status().enabled, false);
    assert.equal(locked.status().lockedOff, true);
  });
});

describe("routes", () => {
  test("settings switch update checks, and status reads as off without a checker", async () => {
    const { json, call, cleanup } = makeApp({ configured: true });
    assert.equal((await json("/api/settings")).updates.check, true, "on by default");
    assert.equal((await json("/api/settings", "PUT", { updates: { check: false } })).updates.check, false);
    assert.equal((await call("/api/settings", { method: "PUT", body: JSON.stringify({ updates: { check: "yes" } }) })).status, 400);
    const status = await json("/api/updates");
    assert.equal(status.enabled, false);
    assert.equal(status.latest, null);
    cleanup();
  });
});
