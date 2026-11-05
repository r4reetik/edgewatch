import type { Repo, Scope } from "../store/repo.ts";
import type { Scanner } from "../scanner.ts";
import type { TokenVault } from "../config.ts";
import type { Auth } from "./security.ts";

export interface AppContext {
  repo: Repo;
  scanner: Scanner;
  auth: Auth;
  vault: TokenVault;
  webDir: string | null;
  version: string;
}

/** Hono environment: `withScope` sets `scope` for dashboard routes. */
export interface AppEnv {
  Variables: { scope: Scope };
}
