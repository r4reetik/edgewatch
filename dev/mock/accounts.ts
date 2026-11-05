// Seeds a repo with accounts the way the Accounts page would, and the mock
// dev server with some triage history.

import { Store } from "../../src/store/db.ts";
import { Repo } from "../../src/store/repo.ts";
import { TokenVault } from "../../src/config.ts";
import { MOCK_ACCOUNT, MOCK_TOKEN } from "./cloudflare.ts";
import { DAY_MS, isoDate } from "../../src/shared/time.ts";

export function seedAccount(repo: Repo, vault: TokenVault, o: { id?: string; token?: string; name?: string; entity?: string | number } = {}) {
  const entityId =
    typeof o.entity === "number"
      ? o.entity
      : (repo.entities.list().find((e) => e.name === (o.entity ?? "Mock Group")) ?? repo.entities.create(o.entity ?? "Mock Group")).id;
  const id = o.id ?? MOCK_ACCOUNT;
  repo.accounts.add({ id, name: o.name ?? "Mock Co", entityId, tokenId: vault.put(o.token ?? MOCK_TOKEN, "user"), tokenKind: "user" });
  return { id, entityId };
}

/** An in-memory repo and vault with live probes off, so scans touch only the mocked Cloudflare API. */
export function testRepo(): { repo: Repo; vault: TokenVault } {
  const repo = new Repo(new Store(":memory:"));
  repo.settings.save({ ...repo.settings.get(), probes: { takeover: false } });
  return { repo, vault: new TokenVault(null) };
}

/**
 * Gives the mock a past: the account's first scan moves three weeks back, and a
 * few findings get dated triage changes, one of which a later scan stops finding.
 * Writes straight to the tables, since the app only ever records "now".
 */
export function seedTriageHistory(repo: Repo, accountId: string) {
  const db = repo.store.db;
  const ago = (days: number) => new Date(Date.now() - days * DAY_MS).toISOString();
  const scans = db.prepare("SELECT id FROM scans WHERE account_id = ? AND status = 'done' ORDER BY id").all(accountId) as { id: number }[];
  if (scans.length < 2) return;
  const [first, latest] = [scans[0].id, scans[scans.length - 1].id];
  db.prepare("UPDATE scans SET started_at = ?, finished_at = ? WHERE id = ?").run(ago(21), ago(21), first);
  const fps = repo.findings.forScan(latest, repo.settings.get().slaDays).map((f) => f.fingerprint);
  for (const fp of fps) db.prepare("UPDATE finding_history SET first_seen = ? WHERE fingerprint = ?").run(ago(21), fp);

  const change = (fp: string, days: number, patch: Parameters<typeof repo.findings.setTriage>[1]) => {
    repo.findings.setTriage([fp], patch, "admin");
    db.prepare("UPDATE triage_events SET at = ? WHERE id = (SELECT MAX(id) FROM triage_events)").run(ago(days));
    db.prepare("UPDATE triage SET updated_at = ? WHERE fingerprint = ?").run(ago(days), fp);
  };
  const inDays = (n: number) => isoDate(Date.now() + n * DAY_MS);
  change(fps[0], 18, { status: "in_progress", owner: "sam@mock.example" });
  change(fps[0], 9, { status: "accepted", acceptUntil: inDays(60), note: "Compensating control at the origin firewall" });
  change(fps[1], 15, { owner: "alex@mock.example" });
  change(fps[1], 12, { status: "in_progress" });
  change(fps[2], 6, { status: "false_positive", note: "Public status page, meant to be open" });
  change(fps[3], 3, { status: "in_progress", owner: "sam@mock.example", dueDate: inDays(7) });
  change(fps[4], 16, { status: "accepted", acceptUntil: inDays(-4) });
  // Fixed after triage: the latest scan no longer reports it.
  change(fps[5], 10, { status: "in_progress", owner: "alex@mock.example" });
  db.prepare("DELETE FROM findings WHERE scan_id = ? AND fingerprint = ?").run(latest, fps[5]);
}
