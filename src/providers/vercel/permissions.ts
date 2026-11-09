// Token verification, the team picker and the permission probe for the setup
// screen. A Vercel token has no permissions of its own: it can do whatever its
// user's role on each team allows, so the probe shows what that role can read.

import { VercelClient, type VercelError } from "./client.ts";
import { VERCEL_SOURCES, VERCEL_SOURCE_KEYS } from "./sources.ts";
import { VERCEL_CHECKS } from "./catalog.ts";
import type { PermissionProbe, TokenInfo } from "../../shared/api.ts";

/** Vercel team IDs start with "team_"; any other ID is the token owner's personal account. */
export const teamOf = (accountId: string): string | null => (accountId.startsWith("team_") ? accountId : null);

export async function verifyVercelToken(token: string): Promise<TokenInfo> {
  try {
    await new VercelClient(token, null).raw("/v2/user");
    return { valid: true, kind: "user", status: "active", expiresOn: null };
  } catch (e) {
    const err = e as VercelError;
    return { valid: false, kind: null, message: err.status === 401 || err.status === 403 ? "Vercel didn't accept this token." : err.message };
  }
}

/** Teams the token reaches, plus the personal account when the token can read it. */
export async function listVercelAccounts(token: string): Promise<{ id: string; name: string }[]> {
  const client = new VercelClient(token, null);
  const out: { id: string; name: string }[] = [];
  let until: number | null = null;
  do {
    const body = await client.raw(`/v2/teams?limit=100${until != null ? `&until=${until}` : ""}`);
    const teams: { id: string; name?: string; slug?: string }[] = body?.teams ?? [];
    out.push(...teams.map((t) => ({ id: String(t.id), name: String(t.name || t.slug || t.id) })));
    until = teams.length ? (body?.pagination?.next ?? null) : null;
  } while (until != null && out.length < 500);
  // A token scoped to one team can't read the personal account's projects; only offer it when it can.
  try {
    const [user] = await Promise.all([client.raw("/v2/user"), client.raw("/v10/projects?limit=1")]);
    const u = user?.user;
    if (u?.id) out.push({ id: String(u.id), name: `${u.name || u.username || "Personal account"} (personal)` });
  } catch {
    /* team-scoped token */
  }
  return out;
}

/** One request per source with a probe, and the checks each source powers. */
export async function probeVercel(token: string, accountId: string): Promise<PermissionProbe[]> {
  const team = teamOf(accountId);
  const client = new VercelClient(token, team);
  const keys = VERCEL_SOURCE_KEYS.filter((k) => VERCEL_SOURCES[k].probe && !(VERCEL_SOURCES[k].teamOnly && !team));
  return Promise.all(
    keys.map(async (k): Promise<PermissionProbe> => {
      const s = VERCEL_SOURCES[k];
      const titles = [...new Set(VERCEL_CHECKS.filter((c) => c.requires?.includes(k)).map((c) => c.title))];
      const base = {
        source: s.label,
        permission: s.permission,
        powers: titles.length ? `${titles.length} check${titles.length === 1 ? "" : "s"}, e.g. ${titles.slice(0, 2).join("; ")}` : "Inventory",
      };
      try {
        await client.raw(client.path(s.probe!(team)));
        return { ...base, ok: true };
      } catch (e) {
        const err = e as VercelError;
        return { ...base, ok: false, status: err.status, message: err.message };
      }
    }),
  );
}
