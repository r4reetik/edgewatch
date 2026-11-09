// Connecting accounts from any provider: verify a token, add accounts, rename,
// move, replace a token, remove. Available before any account is connected. The
// request names its provider (`provider`, Cloudflare when absent).

import type { AppContext } from "../env.ts";
import type { Provider } from "../../providers/types.ts";
import type { Routes } from "../router.ts";
import { PROVIDER } from "../../providers/index.ts";
import { publicAccount, publicEntity } from "../present.ts";
import { ACCOUNT_ID_PATTERN } from "../../shared/providers.ts";
import { accountIds, bool, cleanName, direction, param, providerId, readJson, requireJson, token } from "../validate.ts";
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
  const visibleAccounts = (p: Provider, t: string) => p.listAccounts(t).catch(() => [] as { id: string; name: string }[]);

  r.get("/api/accounts/template", (c) => {
    const p = PROVIDER[providerId(c.req.query("provider"))];
    const acc = c.req.query("accountId");
    const help = p.tokenHelp(acc && ACCOUNT_ID_PATTERN[p.info.id].test(acc) ? acc : null);
    return c.json({ url: help.templateUrl ?? help.url, readAllUrl: help.url, template: !!help.templateUrl } satisfies TemplateResponse);
  });

  r.post("/api/accounts/verify", async (c) => {
    const body = await requireJson(c);
    const p = PROVIDER[providerId(body.provider)];
    const t = token(body.token);
    const ids = accountIds(body.accountIds ?? (body.accountId ? [body.accountId] : []), p.info.id);
    const [info, visible] = await Promise.all([p.verify(t, ids), visibleAccounts(p, t)]);
    if (!info.valid) return c.json({ token: info, accounts: [], probes: {}, probeLimit: PROBE_LIMIT } satisfies VerifyResponse);
    const known = new Map(repo.accounts.list().map((a) => [a.id, a]));
    const probes = Object.fromEntries(await Promise.all(ids.slice(0, PROBE_LIMIT).map(async (id) => [id, await p.probe(t, id)] as const)));
    return c.json({
      token: info,
      probes,
      probeLimit: PROBE_LIMIT,
      templateUrl: p.tokenHelp(ids[0] || null).templateUrl ?? undefined,
      accounts: visible.map((a) => ({ ...a, added: known.has(a.id), entityId: known.get(a.id)?.entityId ?? null })),
    } satisfies VerifyResponse);
  });

  r.post("/api/accounts", async (c) => {
    const body = await requireJson(c);
    const p = PROVIDER[providerId(body.provider)];
    const t = token(body.token);
    const ids = accountIds(body.accountIds, p.info.id);
    if (!ids.length) throw badRequest(`Choose at least one ${p.info.account}.`);
    const info = await p.verify(t, ids);
    if (!info.valid) throw badRequest(info.message || "The token is not valid.");
    const visible = new Map((await visibleAccounts(p, t)).map((a) => [a.id, a.name]));
    const unseen = ids.find((id) => !visible.has(id));
    if (unseen) throw badRequest(`This token can't read ${p.info.account} ${unseen}.`);
    const other = ids.map((id) => repo.accounts.get(id)).find((a) => a && a.provider !== p.info.id);
    if (other) throw badRequest(`${other.id} is already connected as a ${PROVIDER[other.provider].info.label} account.`);

    // Accounts already here only get the new token and stay in their entity, so a new entity is
    // created only when at least one account is new; otherwise it would be left empty.
    const fresh = ids.filter((id) => !repo.accounts.get(id));
    let entityId: number;
    if (body.entityId != null) {
      const e = repo.entities.get(Number(body.entityId));
      if (!e) throw badRequest("That entity no longer exists.");
      entityId = e.id;
    } else if (!fresh.length) {
      entityId = repo.accounts.get(ids[0])!.entityId;
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
        repo.accounts.add({ id, provider: p.info.id, name: visible.get(id) ?? null, entityId, tokenId, tokenKind: info.kind });
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
    // Validate everything first, so a rejected request changes nothing.
    const alias = body.alias === undefined ? undefined : body.alias == null ? null : cleanName(body.alias) || null;
    const scheduled = body.scheduled === undefined ? undefined : bool(body.scheduled, "scheduled");
    const entity = body.entityId === undefined ? undefined : repo.entities.get(Number(body.entityId));
    if (body.entityId !== undefined && !entity) throw badRequest("Unknown entity");
    const move = body.move === undefined ? undefined : direction(body.move);
    repo.store.tx(() => {
      if (alias !== undefined) repo.accounts.update(a.id, { alias });
      if (scheduled !== undefined) repo.accounts.update(a.id, { scheduled });
      if (entity && entity.id !== a.entityId) repo.accounts.setEntity(a.id, entity.id);
      if (move) repo.accounts.move(a.id, move);
    });
    return c.json({ ok: true, account: publicAccount(vault, repo.accounts.get(a.id)!) });
  });

  r.put("/api/accounts/:id/token", async (c) => {
    const a = account(param(c, "id"));
    const t = token((await readJson(c))?.token);
    const p = PROVIDER[a.provider];
    const info = await p.verify(t, [a.id]);
    if (!info.valid) throw badRequest(info.message || "The token is not valid.");
    if (!(await visibleAccounts(p, t)).some((v) => v.id === a.id)) throw badRequest(`This token can't read this ${p.info.account}.`);
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
