// Scans accounts one at a time from a queue and tracks live progress for the UI.
// One account at a time keeps the request rate predictable when several
// accounts share a token (Cloudflare's rate limit is per user).

import { CloudflareClient } from "./core/cloudflare.ts";
import { collectInventory } from "./core/inventory.ts";
import { evaluate, computeScore, severityCounts } from "./core/engine.ts";
import { CHECKS } from "./core/catalog.ts";
import { zoneGrid, valueView, activityView } from "./core/views.ts";
import { notifyScan } from "./notify.ts";
import { displayName, type Account, type Repo } from "./store/repo.ts";
import type { TokenVault } from "./config.ts";

export interface ScanState {
  running: boolean;
  /** The account being scanned now. */
  accountId: string | null;
  scanId: number | null;
  trigger: string | null;
  startedAt: string | null;
  phase: string | null;
  done: number | null;
  total: number | null;
  /** Accounts waiting their turn, in order. */
  queued: string[];
}

export interface ScanResult {
  accountId: string;
  scanId: number;
  score: number | null;
  findings: number;
  newFindings: number;
}

interface Job {
  accountId: string;
  trigger: string;
  promise: Promise<ScanResult>;
  resolve: (r: ScanResult) => void;
  reject: (e: unknown) => void;
}

const IDLE: ScanState = { running: false, accountId: null, scanId: null, trigger: null, startedAt: null, phase: null, done: null, total: null, queued: [] };

export class Scanner {
  state: ScanState = { ...IDLE };
  readonly #repo: Repo;
  readonly #vault: TokenVault;
  readonly #log: (msg: string) => void;
  #jobs: Job[] = [];
  #current: Job | null = null;

  constructor(repo: Repo, vault: TokenVault, log: (msg: string) => void) {
    this.#repo = repo;
    this.#vault = vault;
    this.#log = log;
  }

  isBusy(accountId: string): boolean {
    return this.#current?.accountId === accountId || this.#jobs.some((j) => j.accountId === accountId);
  }

  /**
   * Queues scans for the given accounts (every account when omitted). Accounts
   * already queued or running aren't queued twice; `done` settles when all the
   * requested accounts have finished.
   */
  start(trigger: string, accountIds?: string[]): { queued: string[]; alreadyRunning: boolean; done: Promise<ScanResult[]> } {
    const ids = accountIds ?? this.#repo.accounts.list().map((a) => a.id);
    if (!ids.length) throw new Error("Add a Cloudflare account before scanning.");
    const queued: string[] = [];
    const promises = ids.map((id) => {
      const existing = this.#current?.accountId === id ? this.#current : this.#jobs.find((j) => j.accountId === id);
      if (existing) return existing.promise;
      let resolve!: Job["resolve"], reject!: Job["reject"];
      const promise = new Promise<ScanResult>((res, rej) => {
        resolve = res;
        reject = rej;
      });
      // Callers that don't await the scan still get errors logged instead of an unhandled rejection.
      promise.catch(() => {});
      this.#jobs.push({ accountId: id, trigger, promise, resolve, reject });
      queued.push(id);
      return promise;
    });
    this.state = { ...this.state, queued: this.#jobs.map((j) => j.accountId) };
    if (!this.#current) void this.#drain();
    // Settles once every requested account has finished, and rejects if any of them failed.
    const done = Promise.allSettled(promises).then((rs) => {
      const failed = rs.find((r) => r.status === "rejected");
      if (failed) throw failed.reason;
      return rs.map((r) => (r as PromiseFulfilledResult<ScanResult>).value);
    });
    done.catch(() => {});
    return { queued, alreadyRunning: queued.length === 0, done };
  }

  async #drain(): Promise<void> {
    while (this.#jobs.length) {
      const job = this.#jobs.shift()!;
      this.#current = job;
      try {
        job.resolve(await this.#scan(job));
      } catch (e) {
        job.reject(e);
      }
    }
    this.#current = null;
    this.state = { ...IDLE };
  }

  async #scan(job: Job): Promise<ScanResult> {
    const account = this.#repo.accounts.get(job.accountId);
    if (!account) throw new Error(`Account ${job.accountId} was removed.`);
    const { id, started } = this.#repo.scans.create(account.id, job.trigger);
    this.state = {
      running: true,
      accountId: account.id,
      scanId: id,
      trigger: job.trigger,
      startedAt: started,
      phase: "Starting",
      done: null,
      total: null,
      queued: this.#jobs.map((j) => j.accountId),
    };
    const token = this.#vault.get(account.tokenId);
    if (!token) {
      const msg = "The API token for this account is missing. Replace it on the Accounts page.";
      this.#repo.scans.fail(id, msg, 0);
      this.#log(`Scan ${id} (${displayName(account)}) failed: ${msg}`);
      throw new Error(msg);
    }
    const cf = new CloudflareClient(token.token, account.id);
    try {
      const settings = this.#repo.settings.get();
      const entity = this.#repo.entities.get(account.entityId);
      const inv = await collectInventory(
        cf,
        (p) => {
          this.state = { ...this.state, phase: p.phase, done: p.done ?? null, total: p.total ?? null };
        },
        { probeTakeovers: settings.probes.takeover },
      );
      this.state = { ...this.state, phase: "Evaluating checks", done: null, total: null };

      const overrides = this.#repo.settings.overrides();
      const result = evaluate(inv, {
        orgDomains: [...(entity?.orgDomains || []), ...this.#siblingZones(account)],
        disabledChecks: overrides.disabled,
        severityOverrides: overrides.severity,
      });
      const settled = this.#repo.findings.settled();
      const scored = result.findings.map((f) => ({ ...f, settled: settled.has(f.fingerprint!) }));
      const score = computeScore(result.categories, scored);
      const counts = severityCounts(scored.filter((f) => !f.settled));
      const failures = result.findings.filter((f) => f.source === "custom");

      const snapshot = {
        accountName: inv.accountName,
        zones: zoneGrid(inv, failures),
        value: valueView(inv),
        activity: activityView(inv),
        coverage: [...cf.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        checks: result.checkStats,
        securityCenter: result.securityCenter,
        probes: { takeover: inv.takeover ? { probed: inv.takeover.length, unclaimed: inv.takeover.filter((p) => p.unclaimed).length } : null },
      };

      const prev = this.#repo.scans.latest(account.id);
      this.#repo.scans.complete(id, { findings: result.findings, score: score.overall, counts, categories: result.categories, snapshot, calls: cf.calls });
      this.#repo.scans.prune(account.id, settings.retentionDays);
      // Keep the Cloudflare name current, for accounts renamed in the dashboard.
      if (inv.accountName && inv.accountName !== account.name) this.#repo.accounts.update(account.id, { name: inv.accountName });

      // Alert only on findings that are new since the previous scan (never on the first scan).
      let fresh: typeof result.findings = [];
      if (prev && entity) {
        const before = new Set(this.#repo.scans.fingerprints(prev.id as number).map((r) => r.fingerprint));
        fresh = result.findings.filter((f) => !before.has(f.fingerprint!) && !settled.has(f.fingerprint!));
        // A fresh finding that was seen before has come back after being resolved.
        const reopened = new Set(
          this.#repo.findings
            .forScan(id, settings.slaDays)
            .filter((f) => f.reopened)
            .map((f) => f.fingerprint),
        );
        await notifyScan(
          entity.notifications,
          settings.baseUrl,
          {
            accountId: account.id,
            accountName: account.alias || inv.accountName || account.name || account.id,
            entityName: entity.name,
            scanId: id,
            finishedAt: new Date().toISOString(),
            score: score.overall,
            counts,
            newFindings: fresh.map((f) => ({
              fingerprint: f.fingerprint!,
              severity: f.severity,
              title: f.title,
              resource: f.resource,
              zone: f.zone,
              reopened: reopened.has(f.fingerprint!),
            })),
          },
          this.#log,
        );
      }
      this.#log(`Scan ${id} (${displayName(account)}) finished: score ${score.overall ?? "n/a"}, ${result.findings.length} findings, ${cf.calls} API calls`);
      return { accountId: account.id, scanId: id, score: score.overall, findings: result.findings.length, newFindings: fresh.length };
    } catch (e) {
      this.#repo.scans.fail(id, String((e as Error)?.message || e), cf.calls);
      this.#log(`Scan ${id} (${displayName(account)}) failed: ${(e as Error)?.message || e}`);
      throw e;
    }
  }

  /** Zone names of the other accounts in the same entity: their email domains are internal too. */
  #siblingZones(account: Account): string[] {
    const out: string[] = [];
    for (const a of this.#repo.accounts.list()) {
      if (a.entityId !== account.entityId || a.id === account.id) continue;
      const s = this.#repo.scans.latest(a.id);
      const zones = s?.snapshot ? ((JSON.parse(s.snapshot as string).zones || []) as { name: string }[]) : [];
      out.push(...zones.map((z) => z.name));
    }
    return out;
  }
}
