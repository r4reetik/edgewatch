// The rules every Vercel check follows, as test/contract.test.ts and
// test/skipped.test.ts enforce them for Cloudflare: each fails on its case, the
// well-configured fixture passes everything, and an unreadable source skips its
// checks instead of passing them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { evaluateVercel } from "../src/providers/vercel/engine.ts";
import { VERCEL_CHECKS } from "../src/providers/vercel/catalog.ts";
import { VERCEL_MODULES } from "../src/providers/vercel/checks/index.ts";
import { looksSecret, secretKindIn } from "../src/providers/vercel/checks/define.ts";
import { CATEGORIES } from "../src/core/categories.ts";
import { NOW, project, VERCEL_CASE_OPTS, VERCEL_CASES, vercelInventory } from "./vercel-cases.ts";
import { opts } from "./fixtures/inventory.ts";

test("every Vercel check fails on its case", () => {
  const missing = VERCEL_CHECKS.filter((c) => !VERCEL_CASES[c.id]).map((c) => c.id);
  assert.deepEqual(missing, []);
  const silent = VERCEL_CHECKS.filter((c) => !evaluateVercel(VERCEL_CASES[c.id](), opts(VERCEL_CASE_OPTS[c.id])).findings.some((f) => f.checkId === c.id)).map(
    (c) => c.id,
  );
  assert.deepEqual(silent, [], "these cases don't make their check fail");
});

test("the well-configured Vercel team passes every check it evaluates", () => {
  const failing = evaluateVercel(vercelInventory(), opts()).findings.map((f) => `${f.checkId} ${f.resource}`);
  assert.deepEqual(failing, []);
});

test("a Vercel check whose source was unreadable reports nothing, even on its failing case", () => {
  const leaked: string[] = [];
  for (const c of VERCEL_CHECKS)
    for (const source of c.requires ?? []) {
      const inv = { ...VERCEL_CASES[c.id](), unreadable: [source] };
      if (evaluateVercel(inv, opts(VERCEL_CASE_OPTS[c.id])).results.some((r) => r.checkId === c.id)) leaked.push(`${c.id} (${source})`);
    }
  assert.deepEqual(leaked, []);
});

test("Vercel checks use the shared categories, and every module file is registered", () => {
  for (const c of VERCEL_CHECKS) assert.ok((CATEGORIES as readonly string[]).includes(c.category), c.id);
  const dir = new URL("../src/providers/vercel/checks/", import.meta.url);
  const files = readdirSync(dir).filter((f) => /^export default defineChecks\(/m.test(readFileSync(new URL(f, dir), "utf8")));
  assert.equal(files.length, VERCEL_MODULES.length, `modules on disk: ${files.join(", ")}`);
});

test("secret-looking names: keys, tokens and passwords, but not public identifiers", () => {
  for (const k of ["STRIPE_SECRET_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "DATABASE_URL", "OPENAI_API_KEY", "JWT_SIGNING_KEY", "SENTRY_DSN"])
    assert.ok(looksSecret(k), k);
  for (const k of ["STRIPE_PUBLISHABLE_KEY", "SUPABASE_ANON_KEY", "RECAPTCHA_SITE_KEY", "GOOGLE_CLIENT_ID", "API_URL", "NODE_ENV"])
    assert.ok(!looksSecret(k), k);
});

test("a project never configured runs Vercel's firewall defaults: on, with managed rulesets off", () => {
  const defaults = { enabled: true, configured: false, managedRules: {}, crs: null, rules: [], ips: [] };
  const r = evaluateVercel(vercelInventory({ projects: [project({ firewall: defaults })] }), opts()).results;
  const by = (id: string) => r.filter((x) => x.checkId === id);
  assert.equal(by("VFW-001")[0]?.pass, true, "the firewall is on by default");
  assert.equal(by("VFW-002")[0]?.pass, false, "bot protection is off by default on a public site");
  // Opt-in checks wait until someone starts configuring the firewall.
  for (const id of ["VFW-003", "VFW-004", "VFW-007"]) assert.equal(by(id).length, 0, id);
});

test("members waiting for approval are open requests, not members with access", () => {
  const pending = {
    uid: "p",
    email: "new@gmail.com",
    username: "new",
    role: "OWNER",
    confirmed: false,
    createdAt: NOW - 30 * 86_400_000,
    viaSso: false,
    joinedFrom: "nsnb-request-access",
  };
  const r = evaluateVercel(vercelInventory({ members: [...vercelInventory().members!, pending] }), opts()).results;
  assert.ok(r.some((x) => x.checkId === "VID-004" && x.resource === "new@gmail.com" && !x.pass));
  assert.ok(!r.some((x) => (x.checkId === "VID-003" || x.checkId === "VID-002") && !x.pass));
  // Someone invited shows up as an invitation and an unconfirmed member: one evaluation, from the invitation.
  const invited = { ...pending, email: "late@example.com" };
  const both = vercelInventory({
    members: [...vercelInventory().members!, invited],
    invites: [{ email: "late@example.com", role: "DEVELOPER", createdAt: NOW - 40 * 86_400_000, expired: false }],
  });
  const v4 = evaluateVercel(both, opts()).results.filter((x) => x.checkId === "VID-004" && x.resource === "late@example.com");
  assert.equal(v4.length, 1);
  assert.match(v4[0].detail, /^Invited/);
});

test("credentials in commands are found by kind, variable references aren't, and the value is never reported", () => {
  for (const ok of [
    "npm config set //registry.npmjs.org/:_authToken=$NPM_TOKEN",
    "curl -H 'Authorization: Bearer ${API_TOKEN}' x",
    "git clone https://$GH_USER:$GH_TOKEN@github.com/a/b",
  ])
    assert.equal(secretKindIn(ok), null, ok);
  assert.equal(secretKindIn("pip install -i https://user:hunter22@pypi.example.com/simple x"), "a password in a URL");
  assert.equal(secretKindIn("echo AKIAABCDEFGHIJKLMNOP"), "an AWS access key");
  const token = "npm_abcdefghijklmnopqrstuvwxyz0123456789";
  const f = evaluateVercel(VERCEL_CASES["VEN-008"](), opts()).findings.find((x) => x.checkId === "VEN-008")!;
  assert.ok(!JSON.stringify(f).includes(token), "the finding must not carry the secret");
});
