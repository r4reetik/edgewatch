#!/usr/bin/env node
// The `keelson` command, which the Docker image runs. Checks the Node.js version
// before loading anything that needs a recent one, so running from a clone on an
// older Node.js says how to upgrade instead of failing on a syntax or import error.

import { checkNode } from "./node-check.ts";

const check = checkNode(process.versions.node, process.env, process.execPath, process.platform);
if (!check.ok) {
  console.error(check.message);
  process.exit(1);
}

await import("./cli.ts");
