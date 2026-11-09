// What the dashboard is looking at: every account included in "All accounts",
// one entity, or one account, optionally narrowed to one provider ("e:3@vercel").
// Resolved the same way on the server and in the browser.

import { isProvider, type ProviderId } from "./providers.ts";

export type ScopeKind = "all" | "entity" | "account";

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
  /** "all", "e:<entity id>" or "a:<account id>", with "@<provider>" when narrowed to one provider. */
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

export const scopeKey = { all: "all", entity: (id: number) => `e:${id}`, account: (id: string) => `a:${id}` } as const;

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
