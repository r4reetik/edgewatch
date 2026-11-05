// Connecting Cloudflare accounts: verify a token, add accounts, rename, move,
// replace a token, remove. Available before any account is connected.

import type { AppContext } from "../env.ts";
import type { Routes } from "../router.ts";
import { listAccounts, probePermissions, tokenTemplateUrl, verifyToken } from "../../core/permissions.ts";
import { publicAccount, publicEntity } from "../present.ts";
import { ACCOUNT_ID, accountIds, bool, cleanName, direction, param, readJson, requireJson, token } from "../validate.ts";
import { badRequest, conflict, notFound } from "../errors.ts";
import type { AccountRow, AccountsResponse, AddAccountsResponse, TemplateResponse, VerifyResponse } from "../../shared/api.ts";

/** Permissions are probed for the first few accounts a token can read; the rest are assumed alike. */
const PROBE_LIMIT = 10;

export function accountRoutes(r: Routes, { repo, scanner, vault }: AppContext) {
  const account = (id: string) =>
    repo.accounts.get(id) ??
    (() => {
      throw notFound("Unknown account");
    })();
  /** Drops tokens that no account references any more. */
  const pruneTokens = () => vault.retain(new Set(repo.accounts.list().map((a) => a.tokenId)));
  const visibleAccounts = (t: string) => listAccounts(t).catch(() => [] as { id: string; name: string }[]);

  r.get("/api/accounts/template", (c) => {
    const acc = c.req.query("accountId");
    return c.json({
      url: tokenTemplateUrl(acc && ACCOUNT_ID.test(acc) ? acc : null),
      readAllUrl: "https://dash.cloudflare.com/profile/api-tokens",
    } satisfies TemplateResponse);
  });

  r.post("/api/accounts/verify", async (c) => {
    const body = await requireJson(c);
    const t = token(body.token);
    const ids = accountIds(body.accountIds ?? (body.accountId ? [body.accountId] : []));
    const [info, visible] = await Promise.all([verifyToken(t, ids[0] || null), visibleAccounts(t)]);
    if (!info.valid) return c.json({ token: info, accounts: [], probes: {}, probeLimit: PROBE_LIMIT } satisfies VerifyResponse);
    const known = new Map(repo.accounts.list().map((a) => [a.id, a]));
    const probes = Object.fromEntries(await Promise.all(ids.slice(0, PROBE_LIMIT).map(async (id) => [id, await probePermissions(t, id)] as const)));
    return c.json({
      token: info,
      probes,
      probeLimit: PROBE_LIMIT,
      templateUrl: tokenTemplateUrl(ids[0] || null),
      accounts: visible.map((a) => ({ ...a, added: known.has(a.id), entityId: known.get(a.id)?.entityId ?? null })),
    } satisfies VerifyResponse);
  });

  r.post("/api/accounts", async (c) => {
    const body = await requireJson(c);
    const t = token(body.token);
    const ids = accountIds(body.accountIds);
    if (!ids.length) throw badRequest("Choose at least one account.");
    const info = await verifyToken(t, ids[0]);
    if (!info.valid) throw badRequest(info.message || "The token is not valid.");
    const visible = new Map((await visibleAccounts(t)).map((a) => [a.id, a.name]));
    const unseen = ids.find((id) => !visible.has(id));
    if (unseen) throw badRequest(`This token can't read account ${unseen}.`);

    let entityId: number;
    if (body.entityId != null) {
      const e = repo.entities.get(Number(body.entityId));
      if (!e) throw badRequest("That entity no longer exists.");
      entityId = e.id;
    } else {
      const name = body.entityName != null ? cleanName(body.entityName) : visible.get(ids[0]) || "My organization";
      if (!name) throw badRequest("Give the entity a name.");
      entityId = repo.entities.create(name).id;
    }

    const tokenId = vault.put(t, info.kind);
    const added: string[] = [],
      updated: string[] = [];
    for (const id of ids) {
      if (repo.accounts.get(id)) {
        repo.accounts.update(id, { tokenId, tokenKind: info.kind, name: visible.get(id) ?? null });
        updated.push(id);
      } else {
        repo.accounts.add({ id, name: visible.get(id) ?? null, entityId, tokenId, tokenKind: info.kind });
        added.push(id);
      }
    }
    pruneTokens();
    scanner.start("setup", ids);
    return c.json({ ok: true, added, updated, entityId } satisfies AddAccountsResponse);
  });

  r.get("/api/accounts", (c) => {
    const accounts = repo.accounts.list();
    return c.json({
      entities: repo.entities.list().map((e) => ({
        ...publicEntity(e),
        accounts: accounts
          .filter((a) => a.entityId === e.id)
          .map((a): AccountRow => {
            const last = repo.scans.latestSummary(a.id);
            const failed = repo.scans.lastFailed(a.id);
            return {
              ...publicAccount(vault, a),
              busy: scanner.isBusy(a.id),
              lastScan: last ? { finishedAt: last.finished_at!, score: last.score, counts: JSON.parse(last.counts || "{}") } : null,
              lastFailed: failed && (!last || failed.id > last.id) ? { finishedAt: failed.finished_at!, error: failed.error || "" } : null,
            };
          }),
      })),
    } satisfies AccountsResponse);
  });

  r.patch("/api/accounts/:id", async (c) => {
    const a = account(param(c, "id"));
    const body = await requireJson(c);
    if (body.alias !== undefined) repo.accounts.update(a.id, { alias: body.alias == null ? null : cleanName(body.alias) || null });
    if (body.scheduled !== undefined) repo.accounts.update(a.id, { scheduled: bool(body.scheduled, "scheduled") });
    if (body.entityId !== undefined) {
      const e = repo.entities.get(Number(body.entityId));
      if (!e) throw badRequest("Unknown entity");
      if (e.id !== a.entityId) repo.accounts.setEntity(a.id, e.id);
    }
    if (body.move !== undefined) repo.accounts.move(a.id, direction(body.move));
    return c.json({ ok: true, account: publicAccount(vault, repo.accounts.get(a.id)!) });
  });

  r.put("/api/accounts/:id/token", async (c) => {
    const a = account(param(c, "id"));
    const t = token((await readJson(c))?.token);
    const info = await verifyToken(t, a.id);
    if (!info.valid) throw badRequest(info.message || "The token is not valid.");
    if (!(await visibleAccounts(t)).some((v) => v.id === a.id)) throw badRequest("This token can't read this account.");
    repo.accounts.update(a.id, { tokenId: vault.put(t, info.kind), tokenKind: info.kind });
    pruneTokens();
    scanner.start("token", [a.id]);
    return c.json({ ok: true });
  });

  r.delete("/api/accounts/:id", (c) => {
    const a = account(param(c, "id"));
    if (scanner.isBusy(a.id)) throw conflict("Wait for this account's scan to finish.");
    repo.accounts.remove(a.id);
    pruneTokens();
    return c.json({ ok: true });
  });
}
