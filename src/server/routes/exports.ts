// Findings exports. They take the Findings page's filters, so an export
// contains what the user was looking at; `fp` (repeatable) exports a selection.

import type { Context } from "hono";
import type { AppContext, AppEnv } from "../env.ts";
import type { Routes } from "../router.ts";
import { latestScans, scanMeta, scopeFindings } from "../scope.ts";
import { csvCell, slug } from "../present.ts";
import { filterFindings, filtersFromParams } from "../../shared/filters.ts";
import type { Finding } from "../../shared/api.ts";

const CSV_COLUMNS = [
  "severity",
  "status",
  "account",
  "entity",
  "category",
  "source",
  "checkId",
  "title",
  "zone",
  "resource",
  "detail",
  "fix",
  "owner",
  "due",
  "overdue",
  "firstSeen",
  "note",
  "docs",
  "link",
  // Added when Edgewatch got a second provider; last, so scripts that read columns by position keep working.
  "provider",
] as const;

export function exportRoutes(r: Routes, { repo }: AppContext) {
  const rows = (c: Context<AppEnv>) => {
    const scope = c.get("scope");
    const scans = latestScans(repo, scope);
    const meta = scanMeta(scans);
    const all = scopeFindings(repo, scans, repo.settings.get());
    const picked = new Set(c.req.queries("fp") || []);
    const findings = picked.size
      ? all.filter((f) => picked.has(f.fingerprint))
      : filterFindings(all, { status: "all", ...filtersFromParams((k) => c.req.query(k)) });
    return { scope, meta, findings, name: `edgewatch-findings-${slug(scope.label)}-${String(meta?.finishedAt || "").slice(0, 10)}` };
  };

  r.get("/api/export/findings.json", (c) => {
    const { scope, meta, findings, name } = rows(c);
    c.header("content-disposition", `attachment; filename="${name}.json"`);
    return c.json({ scope: { kind: scope.kind, label: scope.label, provider: scope.provider }, scan: meta, findings });
  });

  r.get("/api/export/findings.csv", (c) => {
    const { findings, name } = rows(c);
    const cell = (f: Finding, k: (typeof CSV_COLUMNS)[number]) => (k === "owner" || k === "note" ? f.triage?.[k] : f[k]);
    const csv = [CSV_COLUMNS.join(","), ...findings.map((f) => CSV_COLUMNS.map((k) => csvCell(cell(f, k))).join(","))].join("\r\n");
    return new Response("﻿" + csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="${name}.csv"` } });
  });
}
