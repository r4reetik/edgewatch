// Turns a Vercel inventory into evaluations, findings and scores, with the same
// summary step as Cloudflare (src/core/engine.ts). Pure: no I/O.

import { Evaluator, type CheckModule } from "../../core/checks/define.ts";
import type { VercelSourceKey } from "./sources.ts";
import { summarize, type Evaluation } from "../../core/engine.ts";
import { NO_RELATED, type EngineOptions } from "../../core/types.ts";
import { VERCEL_MODULES } from "./checks/index.ts";
import { dash, type VercelContext } from "./checks/define.ts";
import { VERCEL_CHECK_BY_ID } from "./catalog.ts";
import type { VercelInventory } from "./types.ts";

export function evaluateVercel(inv: VercelInventory, opts: EngineOptions): Evaluation {
  const ev = new Evaluator(opts);
  const ctx: VercelContext = { inv, opts, d: dash(inv), org: orgDomains(inv, opts), related: { ...NO_RELATED, ...opts.related } };
  for (const m of VERCEL_MODULES as readonly CheckModule<string, VercelContext, VercelSourceKey>[]) ev.runWith(m, ctx, inv.unreadable);
  return summarize(inv.accountId, ev.results, opts, VERCEL_CHECK_BY_ID);
}

/** Internal email domains: the entity's, the team's own, and the apex of every project domain. */
export function orgDomains(inv: VercelInventory, opts: EngineOptions): Set<string> {
  const out = new Set(opts.orgDomains.map((d) => d.trim().toLowerCase()).filter(Boolean));
  if (inv.team?.emailDomain) out.add(inv.team.emailDomain.toLowerCase());
  for (const d of inv.domains ?? []) out.add(d.name.toLowerCase());
  return out;
}
