#!/usr/bin/env node
// The `edgewatch` command. Checks the Node.js version before loading anything
// that needs a recent one, then starts the CLI.
//
// The real minimum lives here, not in package.json "engines": npm treats engines
// as a filter, so a strict range makes `npx edgewatch` on an older Node.js
// quietly install an old Edgewatch instead of the newest one with this message.

import { checkNode } from "./node-check.ts";

const check = checkNode(process.versions.node, process.env, process.execPath, process.platform);
if (check.level === "error") {
  console.error(check.message);
  process.exit(1);
}
if (check.level === "warn") console.warn(check.message);

await import("./cli.ts");
