// The Vercel check catalog, built from the modules in checks/index.ts.

import { VERCEL_MODULES, type VercelCheckId } from "./checks/index.ts";
import type { CheckMeta } from "../../core/checks/define.ts";
import type { VercelSourceKey } from "./sources.ts";

export interface VercelCheckDef extends CheckMeta<VercelSourceKey> {
  id: VercelCheckId;
}

export const VERCEL_CHECKS: VercelCheckDef[] = VERCEL_MODULES.flatMap((m) =>
  Object.entries(m.meta).map(([id, meta]) => ({ id: id as VercelCheckId, ...(meta as CheckMeta<VercelSourceKey>) })),
);

export const VERCEL_CHECK_BY_ID: Record<string, VercelCheckDef> = Object.fromEntries(VERCEL_CHECKS.map((c) => [c.id, c]));
