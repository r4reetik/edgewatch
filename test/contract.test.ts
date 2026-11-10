// Rules every check must follow, enforced over the whole catalog.

import { providerOfUrl } from "../src/shared/providers.ts";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { evaluate } from "../src/core/engine.ts";
import { CATEGORIES, CHECKS } from "../src/core/catalog.ts";
import { MODULES } from "../src/core/checks/index.ts";
import { SOURCES } from "../src/core/sources.ts";
import { CASE_OPTS, CASES } from "./checks/cases.ts";
import { inventory, opts } from "./fixtures/inventory.ts";

test("every check fails on its case from test/checks/cases.ts", () => {
  const missing = CHECKS.filter((c) => !CASES[c.id]).map((c) => c.id);
  assert.deepEqual(missing, [], "add a failing case for each new check");
  const silent: string[] = [];
  for (const c of CHECKS) {
    const failing = evaluate(CASES[c.id](), opts(CASE_OPTS[c.id])).findings.filter((f) => f.checkId === c.id);
    if (!failing.length) silent.push(c.id);
  }
  assert.deepEqual(silent, [], "these cases don't make their check fail");
});

test("the well-configured fixture passes every check it evaluates", () => {
  const failing = evaluate(inventory(), opts())
    .findings.filter((f) => f.source === "custom")
    .map((f) => `${f.checkId} ${f.resource}`);
  assert.deepEqual(failing, []);
});

test("check metadata is complete and consistent", () => {
  const ids = CHECKS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length, "check IDs are unique");
  for (const c of CHECKS) {
    assert.match(c.id, /^[A-Z]+-\d{3}$/, c.id);
    assert.ok((CATEGORIES as readonly string[]).includes(c.category), `${c.id} has a known category`);
    assert.ok(c.title && c.why && c.fix, `${c.id} has a title, why and fix`);
    // Checks that span providers (XP-) may link the other provider's docs.
    assert.ok(
      !c.docs || c.docs.startsWith("https://developers.cloudflare.com/") || (c.id.startsWith("XP-") && providerOfUrl(c.docs) != null),
      `${c.id} links Cloudflare's docs`,
    );
    for (const s of c.requires || []) assert.ok(s in SOURCES, `${c.id} requires a known source: ${s}`);
  }
});

test("every module file in src/core/checks is registered", () => {
  const dir = new URL("../src/core/checks/", import.meta.url);
  const files = readdirSync(dir).filter((f) => /^export default defineChecks\(/m.test(readFileSync(new URL(f, dir), "utf8")));
  assert.equal(files.length, MODULES.length, `modules on disk: ${files.join(", ")}`);
});
