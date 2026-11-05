// The Cloudflare client: retries, pagination, and how unreadable data is recorded.

import { test, describe, afterEach } from "node:test";
import assert from "node:assert/strict";
import { CloudflareClient } from "../src/core/cloudflare.ts";

const real = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = real;
});

/** Answers each request with the next response in the list; records the URLs. */
function serve(...responses: (() => Response)[]): string[] {
  const seen: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    seen.push(String(input));
    const next = responses.shift();
    if (!next) throw new Error("unexpected request");
    return next();
  }) as typeof fetch;
  return seen;
}
const json =
  (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  () =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const ok = (result: unknown, extra = {}) => json({ success: true, errors: [], result, ...extra });

describe("CloudflareClient", () => {
  test("429 is retried after Retry-After, and counts every attempt", async () => {
    serve(json({ success: false, errors: [{ message: "rate limited" }] }, 429, { "retry-after": "0.01" }), ok({ id: "z" }));
    const cf = new CloudflareClient("t", "a");
    assert.deepEqual(await cf.get("zoneSettings", "/zones/z/settings"), { id: "z" });
    assert.equal(cf.calls, 2);
    assert.equal(cf.coverage.get("zoneSettings")?.ok, true);
  });

  test("a 5xx is retried; a 4xx is not", async () => {
    serve(json({}, 502), ok([1]));
    assert.deepEqual(await new CloudflareClient("t", "a").get("zones", "/zones"), [1]);
    serve(json({ success: false, errors: [{ message: "Authentication error" }] }, 403));
    const cf = new CloudflareClient("t", "a");
    assert.equal(await cf.get("members", "/accounts/a/members"), null);
    assert.equal(cf.calls, 1);
  });

  test("an unreadable source records its label, permission and error", async () => {
    serve(json({ success: false, errors: [{ message: "Authentication error" }] }, 403));
    const cf = new CloudflareClient("t", "a");
    await cf.get("accountTokens", "/accounts/a/tokens");
    assert.deepEqual(cf.coverage.get("accountTokens"), {
      key: "accountTokens",
      label: "Account API tokens",
      permission: "Account · Account API Tokens · Read",
      ok: false,
      status: 403,
      message: "Authentication error",
    });
  });

  test("the first failure for a source sticks even if a later zone succeeds", async () => {
    serve(json({ success: false, errors: [{ message: "denied" }] }, 403), ok({}));
    const cf = new CloudflareClient("t", "a");
    await cf.get("dnssec", "/zones/1/dnssec");
    await cf.get("dnssec", "/zones/2/dnssec");
    assert.equal(cf.coverage.get("dnssec")?.ok, false);
  });

  test("getOptional: 404 or a listed status means not configured (null), other errors unreadable (undefined)", async () => {
    serve(json({ success: false, errors: [] }, 404), json({ success: false, errors: [] }, 400), json({ success: false, errors: [] }, 403));
    const cf = new CloudflareClient("t", "a");
    assert.equal(await cf.getOptional("wafRulesets", "/zones/z/rulesets/phases/x/entrypoint"), null);
    assert.equal(await cf.getOptional("tlsSettings", "/zones/z/custom_certificates", [400]), null);
    assert.equal(cf.coverage.get("tlsSettings")?.ok, true);
    assert.equal(await cf.getOptional("ddosRules", "/zones/z/rulesets/phases/ddos_l7/entrypoint"), undefined);
    assert.equal(cf.coverage.get("ddosRules")?.ok, false);
  });

  test("list() follows pages until total_pages", async () => {
    const seen = serve(ok([1, 2], { result_info: { total_pages: 2 } }), ok([3], { result_info: { total_pages: 2 } }));
    assert.deepEqual(await new CloudflareClient("t", "a").list("dnsRecords", "/zones/z/dns_records", { perPage: 2 }), [1, 2, 3]);
    assert.match(seen[0], /per_page=2&page=1$/);
    assert.match(seen[1], /page=2$/);
  });

  test("GraphQL errors in a 200 response throw", async () => {
    serve(json({ data: null, errors: [{ message: "zone does not have access to the field" }] }));
    await assert.rejects(new CloudflareClient("t", "a").graphql("{viewer{zones{zoneTag}}}", {}), /does not have access/);
  });
});
