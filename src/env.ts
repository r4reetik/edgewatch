// Settings from the environment, and the defaults that depend on where Keelson
// runs. Every setting is a KEELSON_* variable read through env(). The Docker image
// sets only KEELSON_INSTALL=docker and leaves the address and data folder to the
// defaults here, so the image and a clone share one set of rules.

import { homedir } from "node:os";
import { join } from "node:path";

/** `KEELSON_<name>`. Empty counts as unset. */
export function env(name: string, vars: NodeJS.ProcessEnv = process.env): string | undefined {
  return vars[`KEELSON_${name}`] || undefined;
}

const inDocker = (vars: NodeJS.ProcessEnv) => env("INSTALL", vars) === "docker";

/** KEELSON_HOST; in the Docker image every interface, else loopback only. */
export function defaultHost(vars: NodeJS.ProcessEnv = process.env): string {
  return env("HOST", vars) || (inDocker(vars) ? "0.0.0.0" : "127.0.0.1");
}

/** KEELSON_DATA_DIR; in the Docker image /data; else ~/.keelson. */
export function defaultDataDir(home: string = homedir(), vars: NodeJS.ProcessEnv = process.env): string {
  return env("DATA_DIR", vars) || (inDocker(vars) ? "/data" : join(home, ".keelson"));
}
