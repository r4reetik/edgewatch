// Entities (the companies or teams that own accounts) and the Cloudflare
// accounts in them, in the order the user arranged them.

import type { Store } from "./db.ts";
import { deleteOrphans } from "./findings.ts";
import type { AccountRecord, EntityRecord } from "./rows.ts";
import type { Severity } from "../shared/severity.ts";
import type { TokenKind } from "../shared/api.ts";

export interface EntityNotifications {
  slackWebhookUrl: string;
  webhookUrl: string;
  minSeverity: Severity;
}
export const DEFAULT_NOTIFICATIONS: EntityNotifications = { slackWebhookUrl: "", webhookUrl: "", minSeverity: "high" };

export interface Entity {
  id: number;
  name: string;
  /** Whether this entity's accounts appear in the "All accounts" view and its reports. */
  includeInAll: boolean;
  /** Extra email domains treated as internal; the entity's zone names always count. */
  orgDomains: string[];
  notifications: EntityNotifications;
  position: number;
}

export type EntityUpdate = Pick<Entity, "name" | "includeInAll" | "orgDomains" | "notifications">;

export interface Account {
  id: string;
  name: string | null;
  alias: string | null;
  entityId: number;
  tokenId: string;
  tokenKind: TokenKind | null;
  /** Included in the daily scan. Manual scans always run. */
  scheduled: boolean;
  position: number;
  addedAt: string;
}

type Direction = "up" | "down";

/** Swaps an item with its neighbour and renumbers the list, so positions stay unique after deletes. */
function reorder<T extends { id: string | number }>(s: Store, list: T[], id: T["id"], dir: Direction, sql: string): void {
  const i = list.findIndex((x) => x.id === id);
  const j = dir === "up" ? i - 1 : i + 1;
  if (i < 0 || j < 0 || j >= list.length) return;
  [list[i], list[j]] = [list[j], list[i]];
  s.tx(() => list.forEach((x, n) => s.run(sql, n, x.id)));
}

const nextPosition = (s: Store, sql: string, ...params: (string | number)[]) => (s.get<{ p: number | null }>(sql, ...params)?.p ?? -1) + 1;

export class EntityRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  list(): Entity[] {
    return this.#s.all<EntityRecord>("SELECT * FROM entities ORDER BY position, id").map(toEntity);
  }

  get(id: number): Entity | null {
    const r = this.#s.get<EntityRecord>("SELECT * FROM entities WHERE id = ?", id);
    return r ? toEntity(r) : null;
  }

  create(name: string, init: Partial<Omit<EntityUpdate, "name">> = {}): Entity {
    const r = this.#s.run(
      "INSERT INTO entities (name, include_in_all, org_domains, notifications, position, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      name,
      init.includeInAll === false ? 0 : 1,
      JSON.stringify(init.orgDomains || []),
      JSON.stringify({ ...DEFAULT_NOTIFICATIONS, ...(init.notifications || {}) }),
      nextPosition(this.#s, "SELECT MAX(position) AS p FROM entities"),
      new Date().toISOString(),
    );
    return this.get(Number(r.lastInsertRowid))!;
  }

  update(id: number, next: EntityUpdate): void {
    this.#s.run(
      "UPDATE entities SET name = ?, include_in_all = ?, org_domains = ?, notifications = ? WHERE id = ?",
      next.name,
      next.includeInAll ? 1 : 0,
      JSON.stringify(next.orgDomains),
      JSON.stringify(next.notifications),
      id,
    );
  }

  move(id: number, dir: Direction): void {
    reorder(this.#s, this.list(), id, dir, "UPDATE entities SET position = ? WHERE id = ?");
  }

  delete(id: number): void {
    this.#s.run("DELETE FROM entities WHERE id = ?", id);
  }
}

export class AccountRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  /** Every account, in entity order then the user's order within each entity. */
  list(): Account[] {
    return this.#s
      .all<AccountRecord>("SELECT a.* FROM accounts a JOIN entities e ON e.id = a.entity_id ORDER BY e.position, e.id, a.position, a.added_at")
      .map(toAccount);
  }

  get(id: string): Account | null {
    const r = this.#s.get<AccountRecord>("SELECT * FROM accounts WHERE id = ?", id);
    return r ? toAccount(r) : null;
  }

  add(a: Pick<Account, "id" | "name" | "entityId" | "tokenId" | "tokenKind">): void {
    this.#s.run(
      "INSERT INTO accounts (id, name, entity_id, token_id, token_kind, position, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      a.id,
      a.name,
      a.entityId,
      a.tokenId,
      a.tokenKind,
      nextPosition(this.#s, "SELECT MAX(position) AS p FROM accounts WHERE entity_id = ?", a.entityId),
      new Date().toISOString(),
    );
  }

  update(id: string, next: Partial<Pick<Account, "name" | "alias" | "tokenId" | "tokenKind" | "scheduled">>): void {
    const cur = this.get(id);
    if (!cur) return;
    const m = { ...cur, ...next };
    this.#s.run(
      "UPDATE accounts SET name = ?, alias = ?, token_id = ?, token_kind = ?, scheduled = ? WHERE id = ?",
      m.name,
      m.alias,
      m.tokenId,
      m.tokenKind,
      m.scheduled ? 1 : 0,
      id,
    );
  }

  /** Moves an account to another entity, at the end of its list. */
  setEntity(id: string, entityId: number): void {
    this.#s.run(
      "UPDATE accounts SET entity_id = ?, position = ? WHERE id = ?",
      entityId,
      nextPosition(this.#s, "SELECT MAX(position) AS p FROM accounts WHERE entity_id = ?", entityId),
      id,
    );
  }

  move(id: string, dir: Direction): void {
    const a = this.get(id);
    if (a)
      reorder(
        this.#s,
        this.list().filter((x) => x.entityId === a.entityId),
        id,
        dir,
        "UPDATE accounts SET position = ? WHERE id = ?",
      );
  }

  /** Removes an account with its scans, findings, triage and history. */
  remove(id: string): void {
    this.#s.tx(() => {
      this.#s.run("DELETE FROM scans WHERE account_id = ?", id);
      this.#s.run("DELETE FROM accounts WHERE id = ?", id);
      deleteOrphans(this.#s);
    });
  }
}

function toEntity(r: EntityRecord): Entity {
  return {
    id: r.id,
    name: r.name,
    includeInAll: !!r.include_in_all,
    position: r.position,
    orgDomains: JSON.parse(r.org_domains || "[]"),
    notifications: { ...DEFAULT_NOTIFICATIONS, ...JSON.parse(r.notifications || "{}") },
  };
}

function toAccount(r: AccountRecord): Account {
  return {
    id: r.id,
    name: r.name ?? null,
    alias: r.alias ?? null,
    entityId: r.entity_id,
    tokenId: r.token_id,
    tokenKind: (r.token_kind as TokenKind) ?? null,
    scheduled: !!r.scheduled,
    position: r.position,
    addedAt: r.added_at,
  };
}
