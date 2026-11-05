// The store's domain operations, one repository per concern:
//   repo.settings   instance settings and check overrides
//   repo.entities   companies or teams that own accounts
//   repo.accounts   Cloudflare accounts
//   repo.scans      scan lifecycle, trends and retention
//   repo.findings   findings with triage, and each finding's timeline

import type { Store } from "./db.ts";
import { SettingsRepo } from "./settings.ts";
import { AccountRepo, EntityRepo, type Account, type Entity } from "./accounts.ts";
import { ScanRepo } from "./scans.ts";
import { FindingRepo } from "./findings.ts";
import { resolveScope, type ResolvedScope } from "../shared/scope.ts";

export type { Account, Entity, EntityNotifications, EntityUpdate } from "./accounts.ts";
export { DEFAULT_NOTIFICATIONS } from "./accounts.ts";
export { DEFAULT_SETTINGS, type Overrides } from "./settings.ts";
export type { StoredFinding, TriagePatch } from "./findings.ts";
export type { DoneScan } from "./scans.ts";
export type { Settings } from "../shared/api.ts";
export { displayName } from "../shared/scope.ts";

/** What the dashboard is looking at: every included account, one entity, or one account. */
export type Scope = ResolvedScope<Account, Entity>;

export class Repo {
  readonly store: Store;
  readonly settings: SettingsRepo;
  readonly entities: EntityRepo;
  readonly accounts: AccountRepo;
  readonly scans: ScanRepo;
  readonly findings: FindingRepo;

  constructor(store: Store) {
    this.store = store;
    this.settings = new SettingsRepo(store);
    this.entities = new EntityRepo(store);
    this.accounts = new AccountRepo(store);
    this.scans = new ScanRepo(store);
    this.findings = new FindingRepo(store);
  }

  /** "all" (accounts whose entity is included in combined views), "e:<entity id>" or "a:<account id>"; null if unknown. */
  resolveScope(key: string): Scope | null {
    return resolveScope(this.accounts.list(), this.entities.list(), key);
  }
}
