// One command for local development: the API server (real or mocked
// provider data) plus the Vite dev server with hot reload.
//   npm run dev            real accounts, data in ./.keelson
//   npm run dev -- --mock  mocked provider APIs, nothing written to disk

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";

const mock = process.argv.includes("--mock");
// A clone from before the rename to Keelson keeps its ./.edgewatch until it is moved.
const dataDir = !existsSync(".keelson") && existsSync(".edgewatch") ? ".edgewatch" : ".keelson";
const server = mock ? ["--watch", "dev/mock/server.ts"] : ["--watch", "src/bin.ts", "--no-open", "--data-dir", dataDir];
const children: ChildProcess[] = [
  spawn(process.execPath, server, { stdio: "inherit" }),
  spawn(process.execPath, ["node_modules/vite/bin/vite.js", "--config", "web/vite.config.ts"], { stdio: "inherit" }),
];
const stop = () => {
  for (const c of children) c.kill("SIGTERM");
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
for (const c of children)
  c.on("exit", (code) => {
    stop();
    process.exitCode ||= code ?? 0;
  });
