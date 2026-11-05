// An app instance over an in-memory store and a temporary data directory, with
// helpers to call it like the browser does.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../../src/store/db.ts";
import { Repo } from "../../src/store/repo.ts";
import { Scanner } from "../../src/scanner.ts";
import { createApp } from "../../src/server/app.ts";
import { Auth } from "../../src/server/security.ts";
import { TokenVault } from "../../src/config.ts";
import { seedAccount } from "../../dev/mock/accounts.ts";

export const PASSWORD = "correct horse battery staple";

export function makeApp({ password = null as string | null, configured = false } = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), "edgewatch-test-"));
  const webDir = join(dataDir, "web");
  mkdirSync(join(webDir, "assets"), { recursive: true });
  writeFileSync(join(webDir, "index.html"), "<!doctype html><title>Edgewatch</title>");
  writeFileSync(join(webDir, "assets", "app.js"), "console.log(1)");
  writeFileSync(join(dataDir, "secret.txt"), "do not serve");
  const repo = new Repo(new Store(":memory:"));
  repo.settings.save({ ...repo.settings.get(), probes: { takeover: false } });
  const vault = new TokenVault(dataDir);
  if (configured) seedAccount(repo, vault);
  const scanner = new Scanner(repo, vault, () => {});
  const auth = new Auth({ password, insecureNoAuth: false, loopback: !password, trustProxy: false, allowedHosts: [] });
  const app = createApp({ repo, scanner, auth, vault, webDir, version: "test" });
  const call = (path: string, init: RequestInit & { host?: string } = {}) =>
    app.request(path, {
      ...init,
      headers: { host: init.host || "127.0.0.1:4317", ...(init.body ? { "content-type": "application/json" } : {}), ...(init.headers || {}) },
    });
  const json = async (path: string, method = "GET", body?: unknown) =>
    (await call(path, { method, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) })).json() as Promise<any>;
  return { app, call, json, repo, vault, scanner, dataDir, cleanup: () => rmSync(dataDir, { recursive: true, force: true }) };
}
