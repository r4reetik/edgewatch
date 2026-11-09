// Every check of every provider: what the API, the store and the docs read.
// Provider code uses its own catalog (src/core/catalog.ts for Cloudflare,
// src/providers/vercel/catalog.ts for Vercel).

import { PROVIDER } from "./index.ts";
import { SC_CLASSES } from "../core/catalog.ts";
import type { CheckDef } from "./types.ts";

export { CATEGORIES, type Category } from "../core/categories.ts";
export type { CheckDef };

export const CHECKS: CheckDef[] = Object.values(PROVIDER).flatMap((p) => p.checks);

export const CHECK_BY_ID: Record<string, CheckDef> = Object.fromEntries(CHECKS.map((c) => [c.id, c]));

/** The provider a check belongs to; Security Center findings ("SC:…") are Cloudflare's. */
export const providerOfCheck = (checkId: string) => (checkId.startsWith("SC:") || !CHECK_BY_ID[checkId] ? "cloudflare" : CHECK_BY_ID[checkId].provider);

export { SC_CLASSES };
