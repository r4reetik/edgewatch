// Registers routes with their guards attached to each route, so who can reach
// a route never depends on where it is registered:
//   const open = routes(app);                       // no guard
//   const authed = open.with(requireSession(auth)); // signed in
//   const scoped = authed.with(requireConfigured(repo), withScope(repo));

import type { Context, Hono, MiddlewareHandler } from "hono";
import type { AppEnv } from "./env.ts";

type Handler = (c: Context<AppEnv>) => Response | Promise<Response>;
type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface Routes {
  get(path: string, h: Handler): void;
  post(path: string, h: Handler): void;
  put(path: string, h: Handler): void;
  patch(path: string, h: Handler): void;
  delete(path: string, h: Handler): void;
  on(methods: Method[], paths: string[], h: Handler): void;
  /** The same registrar with more guards, run in order before the handler. */
  with(...guards: MiddlewareHandler<AppEnv>[]): Routes;
}

export function routes(app: Hono<AppEnv>, guards: MiddlewareHandler<AppEnv>[] = []): Routes {
  // Hono's overloads don't accept a spread list of middleware; the runtime does.
  const on = app.on.bind(app) as unknown as (m: Method[], p: string[], ...h: (MiddlewareHandler<AppEnv> | Handler)[]) => void;
  const add = (method: Method) => (path: string, h: Handler) => on([method], [path], ...guards, h);
  return {
    get: add("GET"),
    post: add("POST"),
    put: add("PUT"),
    patch: add("PATCH"),
    delete: add("DELETE"),
    on: (methods, paths, h) => on(methods, paths, ...guards, h),
    with: (...more) => routes(app, [...guards, ...more]),
  };
}
