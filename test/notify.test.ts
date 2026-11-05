import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { notifyScan, sendTest, validWebhookUrl, type ScanSummary } from "../src/notify.ts";
import { DEFAULT_NOTIFICATIONS, type EntityNotifications } from "../src/store/repo.ts";

let sent: { url: string; body: any }[] = [];
let status = 200;
const real = globalThis.fetch;
beforeEach(() => {
  sent = [];
  status = 200;
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    sent.push({ url: String(url), body: JSON.parse(String(init?.body)) });
    return new Response("ok", { status });
  }) as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = real;
});

const dest = (n: Partial<EntityNotifications>): EntityNotifications => ({ ...DEFAULT_NOTIFICATIONS, ...n });
const summary: ScanSummary = {
  accountId: "0123456789abcdef0123456789abcdef",
  accountName: "Acme",
  entityName: "Acme Ltd",
  scanId: 7,
  finishedAt: "2026-06-01T00:00:00Z",
  score: 71,
  counts: { critical: 1, high: 2, medium: 3, low: 4 },
  newFindings: [
    { severity: "critical", title: "Managed WAF off", resource: "acme.com", zone: "acme.com" },
    { severity: "low", title: "No CAA", resource: "acme.com", zone: "acme.com" },
  ],
};

describe("notifications", () => {
  test("posts only findings at or above the minimum severity, to both targets", async () => {
    await notifyScan(
      dest({ slackWebhookUrl: "https://hooks.slack.com/services/X", webhookUrl: "https://example.com/hook", minSeverity: "high" }),
      "https://ew.example.com",
      summary,
      () => {},
    );
    assert.equal(sent.length, 2);
    const slack = sent.find((s) => s.url.includes("slack"))!.body;
    assert.match(slack.text, /1 new finding in Acme/);
    assert.ok(
      JSON.stringify(slack.blocks).includes("https://ew.example.com/findings?scope=a:0123456789abcdef0123456789abcdef"),
      "links to the scanned account",
    );
    assert.ok(JSON.stringify(slack.blocks).includes("Acme Ltd"));
    const hook = sent.find((s) => s.url.includes("example.com/hook"))!.body;
    assert.equal(hook.event, "scan.new_findings");
    assert.equal(hook.entity, "Acme Ltd");
    assert.deepEqual(
      hook.newFindings.map((f: { severity: string }) => f.severity),
      ["critical"],
    );
  });

  test("sends nothing when no new finding meets the threshold, or nothing is configured", async () => {
    await notifyScan(
      dest({ webhookUrl: "https://example.com/hook", minSeverity: "critical" }),
      "",
      { ...summary, newFindings: [summary.newFindings[1]] },
      () => {},
    );
    await notifyScan(dest({}), "", summary, () => {});
    assert.equal(sent.length, 0);
  });

  test("escapes Slack markup in finding text", async () => {
    await notifyScan(
      dest({ slackWebhookUrl: "https://hooks.slack.com/services/X", minSeverity: "low" }),
      "",
      { ...summary, newFindings: [{ severity: "high", title: "<script> & stuff", resource: "<@here>", zone: null }] },
      () => {},
    );
    const text = JSON.stringify(sent[0].body.blocks);
    assert.ok(!text.includes("<@here>") && text.includes("&lt;@here&gt;"));
  });

  test("test notifications report delivery failures without throwing", async () => {
    status = 500;
    const r = await sendTest(dest({ slackWebhookUrl: "https://hooks.slack.com/services/X" }), "", "Acme Ltd");
    assert.deepEqual(r, { slack: "HTTP 500" });
  });

  test("only https webhook URLs are valid", () => {
    assert.ok(validWebhookUrl("https://hooks.slack.com/x"));
    assert.ok(validWebhookUrl(""));
    assert.ok(!validWebhookUrl("http://example.com"));
    assert.ok(!validWebhookUrl("javascript:alert(1)"));
  });
});
