// Keelson was called Edgewatch until 0.10. Installations set up under the old
// name keep working without changes: every KEELSON_* variable falls back to its
// EDGEWATCH_* twin, and an existing ~/.edgewatch folder and edgewatch.db are used
// where they are rather than moved, so an upgrade can't lose credentials or data
// halfway through a copy. Keep these fallbacks; they are what makes the rename
// safe to take (see AGENTS.md).

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** `KEELSON_<name>`, else the old `EDGEWATCH_<name>`. Empty counts as unset. */
export function env(name: string, vars: NodeJS.ProcessEnv = process.env): string | undefined {
  return vars[`KEELSON_${name}`] || vars[`EDGEWATCH_${name}`] || undefined;
}

/** The Docker image sets KEELSON_INSTALL=docker and leaves the rest to these defaults. */
const inDocker = (vars: NodeJS.ProcessEnv) => env("INSTALL", vars) === "docker";

/** KEELSON_HOST; in the Docker image every interface, else loopback only. */
export function defaultHost(vars: NodeJS.ProcessEnv = process.env): string {
  return env("HOST", vars) || (inDocker(vars) ? "0.0.0.0" : "127.0.0.1");
}

/** KEELSON_DATA_DIR; in the Docker image /data; else ~/.keelson, unless only the old ~/.edgewatch exists. */
export function defaultDataDir(home: string = homedir(), vars: NodeJS.ProcessEnv = process.env): string {
  const set = env("DATA_DIR", vars);
  if (set) return set;
  if (inDocker(vars)) return "/data";
  const dir = join(home, ".keelson");
  const old = join(home, ".edgewatch");
  return !existsSync(dir) && existsSync(old) ? old : dir;
}

/** keelson.db in the data folder, unless only the old edgewatch.db is there. */
export function databasePath(dataDir: string): string {
  const file = join(dataDir, "keelson.db");
  const old = join(dataDir, "edgewatch.db");
  return !existsSync(file) && existsSync(old) ? old : file;
}
