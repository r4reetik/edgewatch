// How a check module is written. A module declares its checks' metadata and the
// function that evaluates them, side by side:
//
//   export default defineChecks({
//     "TLS-003": { category: "TLS & HTTPS", severity: "medium", title: "…", why: "…", fix: "…",
//                  docs: "https://developers.cloudflare.com/…", requires: ["zoneSettings"] },
//   }, ({ inv, d }, report) => {
//     for (const z of inv.zones) report("TLS-003", { zone: z.name, resource: z.name, pass: … });
//   });
//
// `report` only accepts the module's own check IDs, so a typo is a type error.
// Register the module in checks/index.ts; the catalog is built from the registry.
// Other providers write their modules the same way with `checksFor<TheirContext>()`
// (see src/providers/vercel/checks/define.ts and src/providers/aws/checks/define.ts);
// the Evaluator is shared.

import type { Category } from "../categories.ts";
import type { ProviderId } from "../../shared/providers.ts";
import type { SourceKey } from "../sources.ts";
import type { Confidence, EngineOptions, Evidence, Inventory, Result, Severity } from "../types.ts";
import { dash, orgDomains, type Dash } from "./helpers.ts";

export interface CheckMeta<S extends string = SourceKey> {
  category: Category;
  severity: Severity;
  title: string;
  /** Why the problem matters, in a sentence or two. */
  why: string;
  /** How to fix it: where in the dashboard, and what to change. "1. … 2. …" renders as steps. */
  fix: string;
  /** The provider's documentation for the setting. */
  docs?: string;
  /** Data sources the check reads; when one is unreadable the UI says this check was skipped. */
  requires?: S[];
  /** A concrete way in: surfaced first on the Overview. */
  attackPath?: boolean;
  /** The other platforms this check compares the account with (checks that span providers): shown on its findings. */
  spans?: ProviderId[];
}

/** One evaluation: a resource passes or fails a check. */
export interface EvalInput {
  zone?: string | null;
  resource?: string;
  pass: boolean;
  /** Overrides the check's default severity for this finding. */
  severity?: Severity;
  detail?: string;
  evidence?: Evidence | null;
  link?: string | null;
  confidence?: Confidence;
}

export interface CheckContext {
  inv: Inventory;
  opts: EngineOptions;
  /** Cloudflare dashboard links for this account. */
  d: Dash;
  /** Email domains that count as internal: the entity's domains plus every zone name. */
  org: Set<string>;
}

export interface Report<Id extends string> {
  (id: Id, r: EvalInput): void;
  /**
   * Records one passing evaluation when the check reported nothing at all in this
   * scan, so its category is still scored. For account-wide checks; per-zone
   * checks report their own pass for each clean zone.
   */
  passIfNone(id: Id, resource?: string, zone?: string | null): void;
}

export interface CheckModule<Id extends string = string, Ctx = CheckContext, S extends string = SourceKey> {
  meta: Record<Id, CheckMeta<S>>;
  // A method, so modules with narrower ID unions still fit CheckModule<string>.
  run(ctx: Ctx, report: Report<Id>): void;
}

/** `defineChecks` for a provider's own context and source keys: `const defineChecks = checksFor<VercelContext, VercelSourceKey>();` */
export function checksFor<Ctx, S extends string>() {
  return <const M extends Record<string, CheckMeta<S>>>(meta: M, run: (ctx: Ctx, report: Report<Extract<keyof M, string>>) => void) =>
    ({ meta: meta as Record<Extract<keyof M, string>, CheckMeta<S>>, run }) as CheckModule<Extract<keyof M, string>, Ctx, S>;
}

export const defineChecks = checksFor<CheckContext, SourceKey>();

/**
 * Collects one pass/fail result per (check, resource). Failures become findings;
 * passes only count toward the score, so a check that finds nothing still earns
 * credit. Disabled checks are dropped here, and severity overrides apply.
 */
export class Evaluator {
  readonly results: Result[] = [];
  readonly #opts: EngineOptions;
  readonly #counts = new Map<string, number>();

  constructor(opts: EngineOptions) {
    this.#opts = opts;
  }

  /** Runs a Cloudflare module, giving it a `report` bound to its own metadata. */
  run<Id extends string>(m: CheckModule<Id>, inv: Inventory): void {
    this.runWith(m, { inv, opts: this.#opts, d: dash(inv), org: orgDomains(inv, this.#opts) }, inv.unreadable ?? []);
  }

  /** Runs any provider's module against its context. A check that needs a source in `unreadable` is skipped. */
  runWith<Id extends string, Ctx, S extends string>(m: CheckModule<Id, Ctx, S>, ctx: Ctx, unreadableSources: readonly string[]): void {
    // A check that needs a source the token couldn't read is skipped: no pass, no failure.
    const unreadable = new Set(unreadableSources);
    const skipped = (meta: CheckMeta<S> | undefined) => !!meta?.requires?.some((k) => unreadable.has(k));
    const report = ((id: Id, r: EvalInput) => {
      if (!skipped(m.meta[id])) this.#add(id, m.meta[id], r);
    }) as Report<Id>;
    report.passIfNone = (id, resource = "account", zone = null) => {
      if (!this.#counts.get(id) && !skipped(m.meta[id])) this.#add(id, m.meta[id], { zone, resource, pass: true });
    };
    m.run(ctx, report);
  }

  #add(
    checkId: string,
    meta: CheckMeta<string> | undefined,
    { zone = null, resource, pass, severity, detail = "", evidence = null, link = null, confidence }: EvalInput,
  ): void {
    if (!meta) throw new Error(`Check ${checkId} isn't declared in its module`);
    this.#counts.set(checkId, (this.#counts.get(checkId) || 0) + 1);
    if (this.#opts.disabledChecks.has(checkId)) return;
    this.results.push({
      checkId,
      source: "custom",
      category: meta.category,
      title: meta.title,
      zone,
      resource: String(resource ?? zone ?? "account"),
      pass: !!pass,
      severity: this.#opts.severityOverrides[checkId] || severity || meta.severity,
      detail,
      evidence,
      link,
      ...(confidence ? { confidence } : {}),
    });
  }
}
