import type { MiddlewareHandler } from "hono";
import type { Repo } from "../store/repo.ts";
import type { AppEnv } from "./env.ts";
import type { Auth } from "./security.ts";
import { HttpError } from "./errors.ts";
import { readJson } from "./validate.ts";

/** Signed in (or auth is off). */
export const requireSession =
  (auth: Auth): MiddlewareHandler<AppEnv> =>
  async (c, next) => {
    if (!auth.isAuthenticated(c)) throw new HttpError(401, "Sign in required", "auth");
    await next();
  };

/** At least one Cloudflare account is connected. */
export const requireConfigured =
  (repo: Repo): MiddlewareHandler<AppEnv> =>
  async (_c, next) => {
    if (!repo.accounts.list().length) throw new HttpError(409, "Not connected to a Cloudflare account", "setup");
    await next();
  };

/** Resolves ?scope= (or the JSON body's `scope` on POST): all | e:<entity id> | a:<account id> | s:<account id>,<account id>… */
export const withScope =
  (repo: Repo): MiddlewareHandler<AppEnv> =>
  async (c, next) => {
    const key = c.req.method === "POST" ? String((await readJson(c))?.scope || "all") : c.req.query("scope") || "all";
    const scope = repo.resolveScope(key);
    if (!scope) throw new HttpError(404, "That account or entity no longer exists.", "scope");
    c.set("scope", scope);
    await next();
  };
