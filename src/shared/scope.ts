// What the dashboard is looking at: every account included in "All accounts",
// one entity, one account, or any set of accounts the user ticked ("s:<id>,<id>"),
// optionally narrowed to one provider ("e:3@vercel"). Resolved the same way on the
// server and in the browser.
//
// A set of accounts may span entities only when every one of them is shown in
// "All accounts": an entity that is kept separate is never combined with another.

import { isProvider, type ProviderId } from "./providers.ts";

export type ScopeKind = "all" | "entity" | "account" | "selection";

export interface ScopeAccount {
  id: string;
  provider: ProviderId;
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
  /** "all", "e:<entity id>", "a:<account id>" or "s:<account id>,<account id>…", with "@<provider>" when narrowed to one provider. */
  key: string;
  kind: ScopeKind;
  label: string;
  /** The accounts in view, after the provider filter. */
  accounts: A[];
  entity: E | null;
  /** The provider filter, or null for every provider. */
  provider: ProviderId | null;
  /** Providers among the scope's accounts before the filter, in the order they first appear. */
  providers: ProviderId[];
}

export const displayName = (a: Pick<ScopeAccount, "id" | "name" | "alias">): string => a.alias || a.name || a.id;

export const scopeKey = {
  all: "all",
  entity: (id: number) => `e:${id}`,
  account: (id: string) => `a:${id}`,
  /** A set of accounts, in a stable order so the same set always has the same key. */
  selection: (ids: Iterable<string>) => `s:${[...new Set(ids)].sort().join(",")}`,
} as const;

/** Splits "e:3@vercel" into its base and provider. An unknown provider leaves the key unfiltered. */
export function splitScopeKey(key: string): { base: string; provider: ProviderId | null } {
  const at = key.lastIndexOf("@");
  if (at < 0) return { base: key, provider: null };
  const p = key.slice(at + 1);
  return { base: key.slice(0, at), provider: isProvider(p) ? p : null };
}

/** The same view narrowed to `provider`, or widened to every provider when null. */
export const withProvider = (key: string, provider: ProviderId | null): string => {
  const { base } = splitScopeKey(key);
  return provider ? `${base}@${provider}` : base;
};

/** Resolves a scope key; unknown keys return null. */
export function resolveScope<A extends ScopeAccount, E extends ScopeEntity>(accounts: A[], entities: E[], key: string): ResolvedScope<A, E> | null {
  const { base, provider } = splitScopeKey(key);
  const resolved = resolveBase(accounts, entities, base);
  if (!resolved) return null;
  const providers = [...new Set(resolved.accounts.map((a) => a.provider))];
  // A filter for a provider the view doesn't have would show nothing: it's dropped instead.
  const filter = provider && providers.includes(provider) && providers.length > 1 ? provider : null;
  return {
    ...resolved,
    key: filter ? `${base}@${filter}` : base,
    provider: filter,
    providers,
    accounts: filter ? resolved.accounts.filter((a) => a.provider === filter) : resolved.accounts,
  };
}

function resolveBase<A extends ScopeAccount, E extends ScopeEntity>(
  accounts: A[],
  entities: E[],
  key: string,
): Omit<ResolvedScope<A, E>, "provider" | "providers"> | null {
  if (key === "all") {
    const included = new Set(entities.filter((e) => e.includeInAll).map((e) => e.id));
    const list = accounts.filter((a) => included.has(a.entityId));
    // With a single account there's nothing to combine, so the view is named after it.
    return { key, kind: "all", label: list.length === 1 && accounts.length === 1 ? displayName(list[0]) : "All accounts", entity: null, accounts: list };
  }
  if (key.startsWith("s:")) {
    const ids = new Set(key.slice(2).split(",").filter(Boolean));
    const list = accounts.filter((a) => ids.has(a.id));
    const owners = entities.filter((e) => list.some((a) => a.entityId === e.id));
    // Nothing left of the selection, or it would combine an entity that is kept separate with another.
    if (!list.length || (owners.length > 1 && owners.some((e) => !e.includeInAll))) return null;
    const entity = owners.length === 1 ? owners[0] : null;
    const label = list.length === 1 ? displayName(list[0]) : entity ? entity.name : `${list.length} accounts`;
    return { key: scopeKey.selection(list.map((a) => a.id)), kind: "selection", label, entity, accounts: list };
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

/**
 * The shortest key for a set of accounts: "all" when it is everything in All accounts, an entity's key when it is
 * all of one entity, either of those narrowed to a provider, an account's key for one, otherwise the set itself.
 * Null when the set is empty or can't be shown together (it would combine an entity that is kept separate).
 */
export function keyForAccounts(accounts: ScopeAccount[], entities: ScopeEntity[], ids: Iterable<string>): string | null {
  const want = new Set(ids);
  const picked = accounts.filter((a) => want.has(a.id));
  if (!picked.length) return null;
  if (picked.length === 1) return scopeKey.account(picked[0].id);
  const same = (key: string) => {
    const r = resolveScope(accounts, entities, key);
    return !!r && r.key === key && r.accounts.length === picked.length && r.accounts.every((a) => want.has(a.id));
  };
  // The narrowest whole comes first: accounts that all belong to one entity are named after it, not after "All accounts".
  const home = entities.filter((e) => picked.every((a) => a.entityId === e.id)).map((e) => scopeKey.entity(e.id));
  const bases = [...home, scopeKey.all, ...entities.map((e) => scopeKey.entity(e.id)).filter((k) => !home.includes(k))];
  const whole = bases.find(same);
  if (whole) return whole;
  const provider = picked.every((a) => a.provider === picked[0].provider) ? picked[0].provider : null;
  const narrowed = provider ? bases.map((b) => `${b}@${provider}`).find(same) : undefined;
  if (narrowed) return narrowed;
  const key = scopeKey.selection(picked.map((a) => a.id));
  return resolveScope(accounts, entities, key) ? key : null;
}

/** "All accounts" when it has anything in it, otherwise the first entity with accounts. */
export function defaultScopeKey(accounts: ScopeAccount[], entities: ScopeEntity[]): string {
  if (resolveScope(accounts, entities, "all")?.accounts.length) return "all";
  const first = entities.find((e) => accounts.some((a) => a.entityId === e.id));
  return first ? scopeKey.entity(first.id) : "all";
}
