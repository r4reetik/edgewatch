#!/usr/bin/env node
// Edgewatch entry point: `npx edgewatch` starts the server and opens the browser.

// Edgewatch is built on Node.js 26 LTS and still runs on Node 24 from its 24.22.1 security release;
// say so plainly instead of failing on an import.
const MIN_NODE = [24, 22, 1];
const nodeVersion = process.versions.node.split(".").map(Number);
const differs = MIN_NODE.findIndex((n, i) => nodeVersion[i] !== n);
if (differs >= 0 && nodeVersion[differs] < MIN_NODE[differs]) {
  console.error(`edgewatch: Node.js ${MIN_NODE.join(".")} or newer is required (Node 26 LTS recommended); this is ${process.versions.node}.`);
  process.exit(1);
}

import "./warnings.ts";
import { parseArgs, type ParseArgsConfig } from "node:util";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

const { start, isLoopback, webMissing, VERSION } = await import("./main.ts");
const { defaultDataDir } = await import("./config.ts");

const HELP = `Edgewatch ${VERSION}: security posture tracker for Cloudflare accounts

Usage: edgewatch [options]

Options:
  --port <n>            Port to listen on (default 4317, env EDGEWATCH_PORT)
  --host <addr>         Address to bind (default 127.0.0.1, env EDGEWATCH_HOST)
  --data-dir <path>     Where the database and credentials live (default ~/.edgewatch, env EDGEWATCH_DATA_DIR)
  --password-file <p>   File containing the admin password (or env EDGEWATCH_PASSWORD)
  --trust-proxy         Trust X-Forwarded-* headers from a reverse proxy (env EDGEWATCH_TRUST_PROXY=1)
  --no-open             Don't open the browser
  -v, --version         Print the version
  -h, --help            Show this help

Environment only:
  EDGEWATCH_AUTH=none          No password on a network address, because an authenticating proxy
                               (for example Cloudflare Access) sits in front
  EDGEWATCH_ALLOWED_HOSTS=a,b  Extra hostnames accepted in local mode
  EDGEWATCH_LOG=json           Log one JSON object per line
  EDGEWATCH_UPDATE_CHECK=off   Never check GitHub for new releases

Cloudflare accounts are added in the browser, one token or several. Tokens are stored in
<data-dir>/credentials.json, readable by your user only. Binding to a non-loopback address
requires a password unless EDGEWATCH_AUTH=none is set.

Docs: https://github.com/r4reetik/edgewatch#readme`;

const { values: args } = parseOptions({
  options: {
    port: { type: "string" },
    host: { type: "string" },
    "data-dir": { type: "string" },
    "password-file": { type: "string" },
    "trust-proxy": { type: "boolean" },
    "no-open": { type: "boolean" },
    version: { type: "boolean", short: "v" },
    help: { type: "boolean", short: "h" },
  },
  strict: true,
});

/** parseArgs, with a one-line message instead of a stack trace for a mistyped flag. */
function parseOptions<T extends ParseArgsConfig>(config: T): ReturnType<typeof parseArgs<T>> {
  try {
    return parseArgs(config);
  } catch (e) {
    fail(`${(e as Error).message.replace(/\. To specify.*/s, "")}. Run edgewatch --help for the options.`);
  }
}

if (args.help) {
  console.log(HELP);
  process.exit(0);
}
if (args.version) {
  console.log(VERSION);
  process.exit(0);
}

const host = args.host || process.env.EDGEWATCH_HOST || "127.0.0.1";
const portText = String(args.port || process.env.EDGEWATCH_PORT || process.env.PORT || 4317);
const port = Number(portText);
const dataDir = resolve(args["data-dir"] || defaultDataDir());
const loopback = isLoopback(host);
const password = args["password-file"] ? readPassword(String(args["password-file"])) : process.env.EDGEWATCH_PASSWORD || null;
const insecureNoAuth = process.env.EDGEWATCH_AUTH === "none";

if (!Number.isInteger(port) || port < 1 || port > 65535) fail(`Invalid port: ${portText}`);
if (!loopback && !password && !insecureNoAuth) {
  fail(`Refusing to listen on ${host} without a password.
Set EDGEWATCH_PASSWORD (or --password-file), or set EDGEWATCH_AUTH=none if an authenticating proxy protects this instance.`);
}
if (password && password.length < 12) fail("EDGEWATCH_PASSWORD must be at least 12 characters.");

const running = await start({
  host,
  port,
  dataDir,
  password,
  insecureNoAuth,
  trustProxy: !!args["trust-proxy"] || process.env.EDGEWATCH_TRUST_PROXY === "1",
  allowedHosts: (process.env.EDGEWATCH_ALLOWED_HOSTS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
}).catch((e: NodeJS.ErrnoException) =>
  fail(e.code === "EACCES" || e.code === "EROFS" || e.code === "EPERM" ? `${e.message}. Choose a writable directory with --data-dir.` : e.message),
);

const accounts = running.repo.accounts.list(),
  entities = running.repo.entities.list();
console.log(
  `\n  Edgewatch ${VERSION}\n\n  Open:  ${running.url}\n  Data:  ${dataDir}\n  Auth:  ${password ? "password" : insecureNoAuth && !loopback ? "none (behind your proxy)" : "none (local only)"}\n`,
);
if (!accounts.length) console.log("  No accounts yet: open the URL to add a read-only Cloudflare API token.\n");
else
  console.log(`  Watching ${accounts.length} account${accounts.length === 1 ? "" : "s"} in ${entities.length} entit${entities.length === 1 ? "y" : "ies"}.\n`);
if (process.env.CLOUDFLARE_API_TOKEN) console.log("  Note: CLOUDFLARE_API_TOKEN is no longer read. Add accounts in the browser instead.\n");
if (webMissing()) console.log("  Warning: web UI not found. Run `npm run build:web`.\n");
if (!args["no-open"] && loopback && process.stdout.isTTY) openBrowser(running.url);

let stopping = false;
for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    if (stopping) process.exit(1);
    stopping = true;
    void running.close().then(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  });
}

function openBrowser(url: string) {
  const [cmd, argv] = process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  try {
    spawn(cmd, argv as string[], { stdio: "ignore", detached: true })
      .on("error", () => {})
      .unref();
  } catch {
    /* no browser available */
  }
}

function readPassword(file: string): string {
  try {
    return readFileSync(file, "utf8").trim();
  } catch (e) {
    fail(`Can't read the password file ${file}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  }
}

function fail(msg: string): never {
  console.error(`edgewatch: ${msg}`);
  process.exit(1);
}
