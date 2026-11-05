import type { Repo, Scope } from "../store/repo.ts";
import type { Scanner } from "../scanner.ts";
import type { TokenVault } from "../config.ts";
import type { Auth } from "./security.ts";
import type { UpdateChecker } from "../updates.ts";

export interface AppContext {
  repo: Repo;
  scanner: Scanner;
  auth: Auth;
  vault: TokenVault;
  webDir: string | null;
  version: string;
  /** Absent in tests and the mock dev server, which never check for updates. */
  updates?: UpdateChecker;
}

/** Hono environment: `withScope` sets `scope` for dashboard routes. */
export interface AppEnv {
  Variables: { scope: Scope };
}
