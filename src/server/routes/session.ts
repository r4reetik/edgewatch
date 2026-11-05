// Public: health, session state, sign in and out.

import type { AppContext } from "../env.ts";
import type { Routes } from "../router.ts";
import { publicAccount, sessionEntity } from "../present.ts";
import { readJson } from "../validate.ts";
import { HttpError } from "../errors.ts";
import type { Session } from "../../shared/api.ts";

export function sessionRoutes(r: Routes, { repo, auth, vault, version }: AppContext) {
  r.get("/api/health", (c) => c.json({ ok: true, version }));

  r.get("/api/session", (c) => {
    const authed = auth.isAuthenticated(c);
    const accounts = repo.accounts.list();
    return c.json({
      version,
      authRequired: auth.required,
      authenticated: authed,
      configured: accounts.length > 0,
      ...(authed ? { accounts: accounts.map((a) => publicAccount(vault, a)), entities: repo.entities.list().map(sessionEntity) } : {}),
    } satisfies Session);
  });

  r.post("/api/login", async (c) => {
    const err = auth.login(c, String((await readJson(c))?.password ?? ""));
    if (err) throw new HttpError(401, err, "auth");
    return c.json({ ok: true });
  });

  r.post("/api/logout", (c) => {
    auth.logout(c);
    return c.json({ ok: true });
  });
}
