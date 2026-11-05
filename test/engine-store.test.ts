import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { computeScore, fingerprint, evaluate } from "../src/core/engine.ts";
import { Store } from "../src/store/db.ts";
import { Repo, DEFAULT_SETTINGS } from "../src/store/repo.ts";
import { inventory, opts, ACCOUNT } from "./fixtures/inventory.ts";
import type { CategoryTotals, Result } from "../src/core/types.ts";

describe("scoring", () => {
  test("overall score is the average of category scores", () => {
    const cats: CategoryTotals = { DNS: { total: 100, evaluated: 50 }, Monitoring: { total: 10, evaluated: 3 } };
    const s = computeScore(cats, [{ source: "custom", category: "Monitoring", severity: "medium", settled: false }]);
    assert.equal(s.byCategory.DNS, 100);
    assert.equal(s.byCategory.Monitoring, 70);
    assert.equal(s.overall, 85);
  });

  test("settled findings and Security Center findings don't reduce the score", () => {
    const cats: CategoryTotals = { DNS: { total: 10, evaluated: 2 } };
    const s = computeScore(cats, [
      { source: "custom", category: "DNS", severity: "high", settled: true },
      { source: "security_center", category: "DNS", severity: "critical", settled: false },
    ]);
    assert.equal(s.overall, 100);
  });

  test("fingerprints are stable and scoped to the account", () => {
    const f = { checkId: "DNS-005", zone: "example.com", resource: "a.example.com A" };
    assert.equal(fingerprint("acc1", f), fingerprint("acc1", { ...f, resource: "A.EXAMPLE.COM A" }));
    assert.notEqual(fingerprint("acc1", f), fingerprint("acc2", f));
    assert.match(fingerprint("acc1", f), /^[0-9a-f]{20}$/);
  });
});

function scanWith(repo: Repo, findings: Result[]) {
  const { id } = repo.scans.create(ACCOUNT, "test");
  repo.scans.complete(id, { findings, score: 50, counts: {}, categories: {}, snapshot: {}, calls: 1 });
  return id;
}

const finding = (resource: string, severity: Result["severity"] = "high"): Result => {
  const f: Result = {
    checkId: "IAM-001",
    source: "custom",
    category: "Identity & access",
    title: "t",
    zone: null,
    resource,
    pass: false,
    severity,
    detail: "",
    evidence: null,
    link: null,
  };
  return { ...f, fingerprint: fingerprint(ACCOUNT, f) };
};

describe("store", () => {
  test("history tracks first seen and resolution across scans", () => {
    const repo = new Repo(new Store(":memory:"));
    scanWith(repo, [finding("a@x"), finding("b@x")]);
    const second = scanWith(repo, [finding("a@x")]);
    const rows = repo.store.all<{ fingerprint: string; resolved_at: string | null }>(
      "SELECT fingerprint, resolved_at FROM finding_history ORDER BY fingerprint",
    );
    assert.equal(rows.filter((r) => r.resolved_at).length, 1);
    assert.equal(repo.findings.forScan(second, DEFAULT_SETTINGS.slaDays).length, 1);
  });

  test("accepted risk lapses back to open after its expiry date", () => {
    const repo = new Repo(new Store(":memory:"));
    const f = finding("a@x");
    const id = scanWith(repo, [f]);
    repo.findings.setTriage([f.fingerprint!], { status: "accepted", owner: "sec", note: null, dueDate: null, acceptUntil: "2000-01-01" }, "local");
    const [v] = repo.findings.forScan(id, DEFAULT_SETTINGS.slaDays);
    assert.equal(v.status, "open");
    assert.equal(v.settled, false);
    repo.findings.setTriage([f.fingerprint!], { status: "accepted", owner: "sec", note: null, dueDate: null, acceptUntil: "2999-01-01" }, "local");
    assert.equal(repo.findings.forScan(id, DEFAULT_SETTINGS.slaDays)[0].settled, true);
    assert.ok(repo.findings.settled().has(f.fingerprint!));
  });

  test("overdue uses the due date, or first seen plus the SLA", () => {
    const repo = new Repo(new Store(":memory:"));
    const f = finding("a@x", "critical");
    const id = scanWith(repo, [f]);
    repo.store.run("UPDATE finding_history SET first_seen = '2000-01-01T00:00:00Z'");
    assert.equal(repo.findings.forScan(id, DEFAULT_SETTINGS.slaDays)[0].overdue, true);
    repo.findings.setTriage([f.fingerprint!], { status: "in_progress", owner: null, note: null, dueDate: "2999-01-01", acceptUntil: null }, "local");
    assert.equal(repo.findings.forScan(id, DEFAULT_SETTINGS.slaDays)[0].overdue, false);
  });

  test("settings merge over defaults; overrides round-trip", () => {
    const repo = new Repo(new Store(":memory:"));
    repo.settings.save({ ...DEFAULT_SETTINGS, retentionDays: 30 });
    assert.equal(repo.settings.get().retentionDays, 30);
    assert.equal(repo.settings.get().slaDays.critical, 7);
    repo.settings.setOverride("WAF-005", true, null);
    repo.settings.setOverride("DNS-007", false, "info");
    const o = repo.settings.overrides();
    assert.ok(o.disabled.has("WAF-005"));
    assert.equal(o.severity["DNS-007"], "info");
    repo.settings.setOverride("WAF-005", false, null);
    assert.ok(!repo.settings.overrides().disabled.has("WAF-005"));
  });

  test("interrupted scans are recovered as failed", () => {
    const repo = new Repo(new Store(":memory:"));
    repo.scans.create(ACCOUNT, "test");
    repo.scans.recoverInterrupted();
    assert.equal(repo.scans.list([ACCOUNT])[0].status, "failed");
  });

  test("an evaluated inventory persists and reads back", () => {
    const repo = new Repo(new Store(":memory:"));
    const r = evaluate(inventory({ account: { settings: { enforce_twofactor: false } } }), opts());
    const { id } = repo.scans.create(ACCOUNT, "test");
    repo.scans.complete(id, { findings: r.findings, score: 90, counts: {}, categories: r.categories, snapshot: {}, calls: 1 });
    assert.deepEqual(
      repo.findings.forScan(id, DEFAULT_SETTINGS.slaDays).map((f) => f.checkId),
      ["IAM-005"],
    );
  });
});
