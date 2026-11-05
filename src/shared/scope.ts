// What the dashboard is looking at: every account included in "All accounts",
// one entity, or one account. Resolved the same way on the server and in the browser.

export type ScopeKind = "all" | "entity" | "account";

export interface ScopeAccount {
  id: string;
  entityId: number;
  name: string | null;
  alias: string | null;
}
export interface ScopeEntity {
  id: number;
  name: string;
  includeInAll: boolean;
}

export interface ResolvedScope<A extends ScopeAccount, E extends ScopeEntity> {
  /** "all", "e:<entity id>" or "a:<account id>". */
  key: string;
  kind: ScopeKind;
  label: string;
  accounts: A[];
  entity: E | null;
}

export const displayName = (a: Pick<ScopeAccount, "id" | "name" | "alias">): string => a.alias || a.name || a.id;

export const scopeKey = { all: "all", entity: (id: number) => `e:${id}`, account: (id: string) => `a:${id}` } as const;

/** Resolves a scope key; unknown keys return null. */
export function resolveScope<A extends ScopeAccount, E extends ScopeEntity>(accounts: A[], entities: E[], key: string): ResolvedScope<A, E> | null {
  if (key === "all") {
    const included = new Set(entities.filter((e) => e.includeInAll).map((e) => e.id));
    const list = accounts.filter((a) => included.has(a.entityId));
    // With a single account there's nothing to combine, so the view is named after it.
    return { key, kind: "all", label: list.length === 1 && accounts.length === 1 ? displayName(list[0]) : "All accounts", entity: null, accounts: list };
  }
  const m = /^(e|a):(.+)$/.exec(key);
  if (m?.[1] === "e") {
    const e = entities.find((x) => String(x.id) === m[2]);
    return e ? { key, kind: "entity", label: e.name, entity: e, accounts: accounts.filter((a) => a.entityId === e.id) } : null;
  }
  if (m?.[1] === "a") {
    const a = accounts.find((x) => x.id === m[2]);
    return a ? { key, kind: "account", label: displayName(a), entity: entities.find((e) => e.id === a.entityId) ?? null, accounts: [a] } : null;
  }
  return null;
}

/** "All accounts" when it has anything in it, otherwise the first entity with accounts. */
export function defaultScopeKey(accounts: ScopeAccount[], entities: ScopeEntity[]): string {
  if (resolveScope(accounts, entities, "all")?.accounts.length) return "all";
  const first = entities.find((e) => accounts.some((a) => a.entityId === e.id));
  return first ? scopeKey.entity(first.id) : "all";
}
