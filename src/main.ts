// Starts Edgewatch: store, scanner, scheduler and HTTP server. The CLI parses
// options and calls this; the mock dev server calls it with seeded accounts.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { serve } from "@hono/node-server";
import { Store } from "./store/db.ts";
import { Repo } from "./store/repo.ts";
import { Scanner } from "./scanner.ts";
import { startScheduler } from "./scheduler.ts";
import { createApp } from "./server/app.ts";
import { Auth } from "./server/security.ts";
import { TokenVault } from "./config.ts";
import { importLegacy } from "./store/legacy.ts";
import { log } from "./log.ts";
import { REPOSITORY, VERSION } from "./meta.ts";
import { UpdateChecker } from "./updates.ts";

export { VERSION } from "./meta.ts";

export interface StartOptions {
  host: string;
  port: number;
  /** Where the database and credentials live; null keeps everything in memory. */
  dataDir: string | null;
  password: string | null;
  /** An authenticating proxy sits in front, so no password is needed off loopback. */
  insecureNoAuth: boolean;
  trustProxy: boolean;
  allowedHosts: string[];
  /** Run the daily scan schedule (off for the mock dev server). */
  schedule?: boolean;
  /** Check GitHub for newer releases, if Settings allow (off for the mock dev server). */
  updateCheck?: boolean;
  /** Called with the URL once the server is listening. */
  onListening?: (url: string, ctx: Running) => void;
}

export interface Running {
  url: string;
  repo: Repo;
  vault: TokenVault;
  scanner: Scanner;
  close: () => Promise<void>;
}

export const isLoopback = (host: string) => ["127.0.0.1", "localhost", "::1"].includes(host);

/** The built web UI, next to the compiled server or in dist/ when running from source. */
function findWebDir(): string | null {
  const here = fileURLToPath(new URL(".", import.meta.url));
  return [join(here, "web"), join(here, "..", "dist", "web")].find((d) => existsSync(join(d, "index.html"))) || null;
}

export async function start(o: StartOptions): Promise<Running> {
  const vault = new TokenVault(o.dataDir);
  const store = new Store(o.dataDir ? join(o.dataDir, "edgewatch.db") : ":memory:", { log: log.info });
  const repo = new Repo(store);
  repo.scans.recoverInterrupted();
  if (o.dataDir) importLegacy(o.dataDir, repo, vault, log.info);

  const scanner = new Scanner(repo, vault, log.info);
  const auth = new Auth({
    password: o.password,
    insecureNoAuth: o.insecureNoAuth,
    loopback: isLoopback(o.host),
    trustProxy: o.trustProxy,
    allowedHosts: o.allowedHosts,
  });
  const updates =
    o.updateCheck === false
      ? undefined
      : new UpdateChecker({
          version: VERSION,
          repository: REPOSITORY,
          // The Docker image sets EDGEWATCH_INSTALL=docker; npx runs packages from its cache
          // (…/_npx/…), so upgrade instructions match how this copy started.
          install: process.env.EDGEWATCH_INSTALL === "docker" ? "docker" : /[\\/]_npx[\\/]/.test(process.argv[1] ?? "") ? "npx" : "npm",
          lockedOff: process.env.EDGEWATCH_UPDATE_CHECK === "off",
          enabled: () => repo.settings.get().updates.check,
          log: log.info,
        });
  const app = createApp({ repo, scanner, auth, vault, webDir: findWebDir(), version: VERSION, updates });
  const stopScheduler = o.schedule === false ? () => {} : startScheduler(repo, scanner, log.info);
  const stopUpdates = updates ? updates.start() : () => {};

  return new Promise((resolve, reject) => {
    const server = serve({ fetch: app.fetch, hostname: o.host, port: o.port }, () => {
      const shown = o.host === "0.0.0.0" || o.host === "::" ? "localhost" : o.host.includes(":") ? `[${o.host}]` : o.host;
      const running: Running = {
        url: `http://${shown}:${o.port}`,
        repo,
        vault,
        scanner,
        close: () =>
          new Promise<void>((done) => {
            stopScheduler();
            stopUpdates();
            server.close(() => {
              store.close();
              done();
            });
          }),
      };
      o.onListening?.(running.url, running);
      resolve(running);
    });
    server.on("error", (e: NodeJS.ErrnoException) => {
      stopScheduler();
      stopUpdates();
      reject(e.code === "EADDRINUSE" ? new Error(`Port ${o.port} is already in use. Pick another with --port.`) : e);
    });
  });
}

/** True when the web UI build is missing (shown as a startup warning). */
export const webMissing = () => !findWebDir();
