// Turns an AWS inventory into evaluations, findings and scores, with the same
// summary step as the other providers (src/core/engine.ts). Pure: no I/O.

import { Evaluator, type CheckModule } from "../../core/checks/define.ts";
import { summarize, type Evaluation } from "../../core/engine.ts";
import { NO_RELATED, type EngineOptions } from "../../core/types.ts";
import { AWS_MODULES } from "./checks/index.ts";
import { dash, type AwsContext } from "./checks/define.ts";
import { AWS_CHECK_BY_ID } from "./catalog.ts";
import type { AwsSourceKey } from "./sources.ts";
import type { AwsInventory } from "./types.ts";

export function evaluateAws(inv: AwsInventory, opts: EngineOptions): Evaluation {
  const ev = new Evaluator(opts);
  const ctx: AwsContext = { inv, opts, d: dash, related: { ...NO_RELATED, ...opts.related } };
  for (const m of AWS_MODULES as readonly CheckModule<string, AwsContext, AwsSourceKey>[]) ev.runWith(m, ctx, inv.unreadable);
  return summarize(inv.accountId, ev.results, opts, AWS_CHECK_BY_ID);
}
