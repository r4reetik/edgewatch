// Token verification and a fast permission probe for the setup screen: one cheap
// request per token permission, built from the source registry (sources.ts), with
// the checks that permission powers.

import { CloudflareClient, type ApiError } from "./cloudflare.ts";
import { SOURCES, SOURCE_KEYS, type SourceKey } from "./sources.ts";
import { CHECKS } from "./catalog.ts";
import type { Api } from "./types.ts";

export interface TokenInfo {
  valid: boolean;
  kind: "user" | "account" | null;
  status?: string;
  expiresOn?: string | null;
  message?: string;
}

export interface ProbeResult {
  source: string;
  permission: string;
  powers: string;
  ok: boolean;
  status?: number;
  message?: string;
}

/** Verifies a token as user-owned or account-owned. */
export async function verifyToken(token: string, accountId: string | null): Promise<TokenInfo> {
  const cf = new CloudflareClient(token, accountId || "");
  const tries: [TokenInfo["kind"], string][] = [["user", "/user/tokens/verify"]];
  if (accountId) tries.push(["account", `/accounts/${accountId}/tokens/verify`]);
  let last: string | undefined;
  for (const [kind, path] of tries) {
    try {
      const body = await cf.raw(path);
      return { valid: body.result?.status === "active", kind, status: body.result?.status, expiresOn: body.result?.expires_on ?? null };
    } catch (e) {
      last = (e as ApiError).message;
    }
  }
  return { valid: false, kind: null, message: last || "Token is not valid" };
}

/** Accounts the token can see, for the setup account picker. */
export async function listAccounts(token: string): Promise<{ id: string; name: string }[]> {
  const cf = new CloudflareClient(token, "");
  const accounts = await cf.list("account", "/accounts", { perPage: 50, max: 500 });
  return (accounts || []).map((a: Api) => ({ id: String(a.id), name: String(a.name) }));
}

interface Probe {
  source: string;
  permission: string;
  powers: string;
  path: (acc: string, zone: string | null) => string | null;
  graphql?: boolean;
}

/**
 * One probe per permission, from the source registry: the first source with a
 * probe path stands in for every source that permission grants. `powers` lists
 * the checks those sources feed.
 */
const PROBES: Probe[] = (() => {
  const byPermission = new Map<string, SourceKey[]>();
  for (const k of SOURCE_KEYS) {
    const s = SOURCES[k];
    if (s.external || !s.permission) continue;
    byPermission.set(s.permission, [...(byPermission.get(s.permission) || []), k]);
  }
  const out: Probe[] = [];
  for (const [permission, keys] of byPermission) {
    const lead = keys.find((k) => SOURCES[k].probe);
    if (!lead) continue;
    const checks = CHECKS.filter((c) => c.requires?.some((r) => keys.includes(r)));
    const titles = [...new Set(checks.map((c) => c.title))];
    out.push({
      source:
        keys
          .map((k) => SOURCES[k].label)
          .slice(0, 3)
          .join(", ") + (keys.length > 3 ? ` and ${keys.length - 3} more` : ""),
      permission,
      graphql: SOURCES[lead].graphql,
      path: SOURCES[lead].probe!,
      powers: titles.length ? `${titles.length} check${titles.length === 1 ? "" : "s"}, e.g. ${titles.slice(0, 2).join("; ")}` : "Inventory and the Value page",
    });
  }
  return out;
})();

export async function probePermissions(token: string, accountId: string): Promise<ProbeResult[]> {
  const cf = new CloudflareClient(token, accountId);
  let zone: string | null = null;
  try {
    const z = await cf.raw(`/zones?account.id=${accountId}&per_page=1`);
    zone = z.result?.[0]?.id ?? null;
  } catch {
    /* reported by the Zones probe */
  }

  return Promise.all(
    PROBES.map(async (p): Promise<ProbeResult> => {
      const base = { source: p.source, permission: p.permission, powers: p.powers };
      const path = p.path(accountId, zone);
      if (!path) return { ...base, ok: false, message: "No zones to test against" };
      try {
        if (p.graphql) {
          if (!zone) return { ...base, ok: false, message: "No zones to test against" };
          await cf.graphql(`query($z:String!){viewer{zones(filter:{zoneTag:$z}){zoneTag}}}`, { z: zone });
        } else {
          await cf.raw(path);
        }
        return { ...base, ok: true };
      } catch (e) {
        const err = e as ApiError;
        // 404 on optional features (e.g. no Workers subdomain) still means the token could ask.
        if (err.status === 404) return { ...base, ok: true };
        return { ...base, ok: false, status: err.status, message: err.message };
      }
    }),
  );
}

/**
 * Link that opens Cloudflare's "create user API token" form pre-filled with the
 * read permissions that have documented template keys. The rest are listed on
 * the setup screen for the user to add, or they can pick the "Read all
 * resources" template, which covers everything.
 */
export function tokenTemplateUrl(accountId?: string | null): string {
  const keys = [
    "account_settings",
    "account_analytics",
    "billing",
    "workers_scripts",
    "workers_r2",
    "access",
    "teams",
    "zone",
    "zone_settings",
    "dns",
    "analytics",
    "firewall_services",
    "ssl_and_certificates",
  ];
  const perms = encodeURIComponent(JSON.stringify(keys.map((key) => ({ key, type: "read" }))));
  return `https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=${perms}&accountId=${encodeURIComponent(accountId || "*")}&zoneId=all&name=${encodeURIComponent("Keelson (read-only)")}`;
}
