// Facts about this build, read once from package.json: the version, and the
// GitHub repository that publishes releases (for update checks and links).

import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  version: string;
  homepage?: string;
  repository?: { url?: string };
};

export const VERSION: string = pkg.version;

/** "owner/name" from the repository URL, or null for a fork that removed it. */
export const REPOSITORY: string | null = /github\.com[/:]([^/]+\/[^/.#]+)/.exec(pkg.repository?.url ?? "")?.[1] ?? null;

/** The project page, without a fragment. */
export const HOMEPAGE: string = String(pkg.homepage || "").replace(/#.*$/, "");
