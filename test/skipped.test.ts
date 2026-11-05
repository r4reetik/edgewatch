// "Skipped, never passed": when the token can't read a source, every check that
// requires it reports nothing, neither a pass that inflates the score nor a
// failure invented from the missing data.

import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/core/engine.ts";
import { CHECKS } from "../src/core/catalog.ts";
import { CASES } from "./checks/cases.ts";
import { analytics, inventory, opts, zone } from "./fixtures/inventory.ts";

test("a check whose source was unreadable reports nothing, even on its failing case", () => {
  const leaked: string[] = [];
  for (const c of CHECKS.filter((x) => x.requires?.length)) {
    for (const source of c.requires!) {
      const inv = { ...CASES[c.id](), unreadable: [source] };
      if (evaluate(inv, opts()).results.some((r) => r.checkId === c.id)) leaked.push(`${c.id} (${source})`);
    }
  }
  assert.deepEqual(leaked, []);
});

test("traffic checks skip analytics that couldn't be read instead of passing on an empty list", () => {
  const unread = analytics({ sensitive: null, logOnly: null, hosts: null, oldTls: null, leakedLogins: null });
  const results = evaluate(inventory({ zones: [zone("example.com", { analytics: unread })] }), opts()).results;
  for (const id of ["TRF-003", "TRF-004", "TRF-006", "TRF-009"]) {
    assert.equal(results.filter((r) => r.checkId === id).length, 0, `${id} should be skipped`);
  }
});
