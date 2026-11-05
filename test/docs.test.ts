// The reference pages in docs/ are generated from the check modules and source
// registry. This fails when a check changes and `npm run docs` wasn't run.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DOCS } from "../scripts/docs.ts";

for (const [path, render] of Object.entries(DOCS)) {
  test(`${path} is up to date (run npm run docs)`, () => {
    assert.equal(readFileSync(new URL(`../${path}`, import.meta.url), "utf8"), render());
  });
}
